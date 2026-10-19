import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../../src/http/app.js';
import { loadConfig } from '../../src/infrastructure/config/env.js';
import type { ThreatIntelligenceProvider } from '../../src/domain/ports/threat-provider.js';
import type { AnalysisReport } from '../../src/domain/models/analysis-report.js';

describe('Endpoint POST /api/v1/analyze — Tests d’intégration (Phase 4)', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    if (app) {
      await app.close();
      app = undefined;
    }
  });

  const cleanMockProvider: ThreatIntelligenceProvider = {
    name: 'mock_clean_provider',
    displayName: 'Mock Threat Feed',
    async checkUrl() {
      return {
        providerName: 'mock_clean_provider',
        displayName: 'Mock Threat Feed',
        status: 'NO_KNOWN_THREAT',
        summary: 'Aucune menace détectée dans le flux de test.',
        checkedAt: new Date().toISOString(),
      };
    },
  };

  it('retourne 200 et NO_KNOWN_THREAT pour une URL HTTPS normale sans signalement', async () => {
    app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test' }),
      providers: [cleanMockProvider],
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: 'https://example.com/welcome' },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json<AnalysisReport>();
    expect(body.status).toBe('NO_KNOWN_THREAT');
    expect(body.hostname).toBe('example.com');
    expect(body.submittedUrl).toBe('https://example.com/welcome');
    expect(body.defangedUrl).toBe('hxxps://example[.]com/welcome');
    expect(body.providers).toHaveLength(1);
    expect(body.recommendations.length).toBeGreaterThan(0);
  });

  it('retourne 200 et CONFIRMED_THREAT lorsqu’un fournisseur identifie du phishing', async () => {
    const phishingProvider: ThreatIntelligenceProvider = {
      name: 'google_safe_browsing',
      displayName: 'Google Safe Browsing',
      async checkUrl() {
        return {
          providerName: 'google_safe_browsing',
          displayName: 'Google Safe Browsing',
          status: 'THREAT_FOUND',
          threatTypes: ['PHISHING_OR_SOCIAL_ENGINEERING'],
          summary: 'URL répertoriée pour hameçonnage.',
          checkedAt: new Date().toISOString(),
        };
      },
    };

    app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test' }),
      providers: [phishingProvider, cleanMockProvider],
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: 'https://synthetic-phish.example.test/login' },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json<AnalysisReport>();
    expect(body.status).toBe('CONFIRMED_THREAT');
    expect(body.findings.some((f) => f.category === 'CONFIRMED_REPUTATION')).toBe(true);
  });

  it('n’envoie jamais une adresse IP interne aux fournisseurs externes et retourne CONFIRMED_THREAT', async () => {
    const checkSpy = vi.fn();
    const spyProvider: ThreatIntelligenceProvider = {
      name: 'spy_provider',
      displayName: 'Spy Provider',
      checkUrl: checkSpy,
    };

    app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test' }),
      providers: [spyProvider],
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: 'http://169.254.169.254/latest/meta-data/' },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json<AnalysisReport>();
    expect(body.status).toBe('CONFIRMED_THREAT');
    expect(body.findings.some((f) => f.code === 'PRIVATE_OR_RESERVED_IP')).toBe(true);
    expect(checkSpy).not.toHaveBeenCalled();
  });

  it('résiste à la panne brutale (exception non gérée) d’un fournisseur et retourne INCOMPLETE', async () => {
    const crashingProvider: ThreatIntelligenceProvider = {
      name: 'crashing_provider',
      displayName: 'Crashing Provider',
      async checkUrl() {
        throw new Error('Socket hang up');
      },
    };

    app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test' }),
      providers: [cleanMockProvider, crashingProvider],
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: 'https://example.com/status' },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json<AnalysisReport>();
    expect(body.status).toBe('INCOMPLETE');
    expect(body.providers.find((p) => p.providerName === 'crashing_provider')?.status).toBe(
      'UNAVAILABLE'
    );
  });

  it('rejette en HTTP 400 les URL malformées, les schémas interdits ou les payloads invalides', async () => {
    app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test' }),
      providers: [cleanMockProvider],
    });

    const badScheme = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: 'javascript:alert(1)' },
    });
    expect(badScheme.statusCode).toBe(400);
    expect(badScheme.json()).toMatchObject({ code: 'UNSUPPORTED_SCHEME' });

    const malformed = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: 'not_a_url' },
    });
    expect(malformed.statusCode).toBe(400);
    expect(malformed.json()).toMatchObject({ code: 'MALFORMED_URL' });

    const extraProp = await app.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload: { url: 'https://example.com', unexpectedField: true },
    });
    expect(extraProp.statusCode).toBe(400);
  });
});
