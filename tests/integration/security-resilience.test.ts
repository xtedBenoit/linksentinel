import { Writable } from 'node:stream';
import dns from 'node:dns';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../../src/http/app.js';
import { loadConfig } from '../../src/infrastructure/config/env.js';
import { SafeBrowsingProvider } from '../../src/infrastructure/providers/safe-browsing.provider.js';
import { UrlHausProvider } from '../../src/infrastructure/providers/urlhaus.provider.js';
import type { AnalysisReport } from '../../src/domain/models/analysis-report.js';

describe('Sécurité applicative (OWASP SSRF, Logs, XSS) et Résilience (Phase 6)', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    vi.restoreAllMocks();
    if (app) {
      await app.close();
      app = undefined;
    }
  });

  it('ne journalise jamais l’URL complète, les tokens de requête, les mots de passe ou les clés API', async () => {
    const logChunks: string[] = [];
    const memoryStream = new Writable({
      write(chunk, _encoding, callback) {
        logChunks.push(chunk.toString('utf8'));
        callback();
      },
    });

    const fakeGsbKey = 'GSB_SECRET_KEY_999111';
    const fakeUrlhausKey = 'URLHAUS_SECRET_KEY_888222';

    const mockFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ query_status: 'no_results' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const config = loadConfig({
      NODE_ENV: 'test',
      LOG_LEVEL: 'info',
      GOOGLE_SAFE_BROWSING_API_KEY: fakeGsbKey,
      URLHAUS_AUTH_KEY: fakeUrlhausKey,
    });

    app = await buildApp({
      config,
      loggerStream: memoryStream,
      providers: [
        new SafeBrowsingProvider({ apiKey: fakeGsbKey, fetchFn: mockFetch as unknown as typeof fetch }),
        new UrlHausProvider({ authKey: fakeUrlhausKey, fetchFn: mockFetch as unknown as typeof fetch }),
      ],
    });

    const sensitiveUrl =
      'https://userAdmin:MySuperSecretPassword@example.com/reset-password/private-token-xyz987?session_id=tok_555666#secretHash';

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: sensitiveUrl },
    });

    expect(response.statusCode).toBe(200);

    const fullLogOutput = logChunks.join('\n');
    expect(fullLogOutput).toContain('https://example.com/[REDACTED]');
    expect(fullLogOutput).not.toContain('MySuperSecretPassword');
    expect(fullLogOutput).not.toContain('private-token-xyz987');
    expect(fullLogOutput).not.toContain('tok_555666');
    expect(fullLogOutput).not.toContain('secretHash');
    expect(fullLogOutput).not.toContain(fakeGsbKey);
    expect(fullLogOutput).not.toContain(fakeUrlhausKey);
  });

  it('n’effectue aucune résolution DNS ni aucune requête HTTP vers le domaine cible soumis (Zero-Touch Target)', async () => {
    const dnsLookupSpy = vi.spyOn(dns, 'lookup');
    const dnsResolveSpy = vi.spyOn(dns, 'resolve');
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test' }),
      providers: [
        new SafeBrowsingProvider({
          apiKey: 'test-key',
          fetchFn: fetchMock as unknown as typeof fetch,
        }),
      ],
    });

    const targetUrl = 'https://untrusted-target.example.test/suspicious-landing?id=42';
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: targetUrl },
    });

    expect(response.statusCode).toBe(200);
    // Aucune résolution DNS ne doit être déclenchée par l'analyse
    expect(dnsLookupSpy).not.toHaveBeenCalled();
    expect(dnsResolveSpy).not.toHaveBeenCalled();

    // Le seul appel fetch effectué doit viser exclusivement safebrowsing.googleapis.com
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(calledUrl).toMatch(/^https:\/\/safebrowsing\.googleapis\.com\//);
    expect(calledUrl).not.toContain('untrusted-target.example.test');
    expect(calledInit.redirect).toBe('error');
  });

  it('détecte toutes les variantes SSRF (IPv4 privées, loopback, IPv6 mapped, décimale, hexadécimale) sans appel externe', async () => {
    const fetchSpy = vi.fn();
    app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test' }),
      providers: [
        new SafeBrowsingProvider({
          apiKey: 'test-key',
          fetchFn: fetchSpy as unknown as typeof fetch,
        }),
      ],
    });

    const ssrfVectors = [
      'http://127.0.0.1/admin',
      'http://0.0.0.0:8080/',
      'http://10.255.255.1/internal',
      'http://172.31.255.255/',
      'http://192.168.0.1/router',
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      'http://[::1]:3000/health',
      'http://[::ffff:127.0.0.1]/secret',
      'http://[fe80::1]/link-local',
      'http://[fd00::1234]/ula',
      'http://2130706433/decimal-loopback',
      'http://0x7f.0.0.1/hex-loopback',
      'http://0177.0.0.1/octal-loopback',
    ];

    for (const vector of ssrfVectors) {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/analyze',
        payload: { url: vector },
      });

      expect(res.statusCode, `Vecteur ${vector}`).toBe(200);
      const report = res.json<AnalysisReport>();
      expect(report.status, `Statut pour ${vector}`).toBe('CONFIRMED_THREAT');
      expect(report.findings.some((f) => f.code === 'PRIVATE_OR_RESERVED_IP')).toBe(true);
    }

    // Aucun de ces vecteurs internes n'a dû être envoyé à un fournisseur externe
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('priorise CONFIRMED_THREAT même si un second fournisseur est en timeout ou en erreur', async () => {
    const timeoutErr = new Error('Timeout');
    timeoutErr.name = 'TimeoutError';

    const failingGsb = new SafeBrowsingProvider({
      apiKey: 'test-key',
      fetchFn: vi.fn().mockRejectedValue(timeoutErr) as unknown as typeof fetch,
    });

    const matchingUrlhaus = new UrlHausProvider({
      authKey: 'test-key',
      fetchFn: vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            query_status: 'ok',
            threat: 'malware_download',
            url_status: 'online',
          }),
          { status: 200 }
        )
      ) as unknown as typeof fetch,
    });

    app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test' }),
      providers: [failingGsb, matchingUrlhaus],
    });

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: 'https://malware-distribution.example.test/payload.bin' },
    });

    expect(res.statusCode).toBe(200);
    const report = res.json<AnalysisReport>();
    expect(report.status).toBe('CONFIRMED_THREAT');
    expect(report.providers).toHaveLength(2);
    expect(
      report.providers.find((p) => p.providerName === 'google_safe_browsing')?.status
    ).toBe('UNAVAILABLE');
    expect(report.providers.find((p) => p.providerName === 'urlhaus')?.status).toBe(
      'THREAT_FOUND'
    );
  });

  it('neutralise les caractères HTML/XSS dans l’URL normalisée et rejette la coercition de type', async () => {
    app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test' }),
      providers: [],
    });

    const xssAttempt = 'https://example.com/search?q=<script>alert("xss")</script>';
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: xssAttempt },
    });

    expect(res.statusCode).toBe(200);
    const report = res.json<AnalysisReport>();
    expect(report.submittedUrl).not.toContain('<script>');
    expect(report.submittedUrl).toContain('%3Cscript%3E');

    // Tentative d'envoyer un tableau ou un nombre à la place d'une chaîne
    const arrayPayload = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: ['https://example.com'] },
    });
    expect(arrayPayload.statusCode).toBe(400);
  });
});
