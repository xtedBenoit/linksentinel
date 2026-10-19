import { describe, expect, it, vi } from 'vitest';
import { SafeBrowsingProvider } from '../../src/infrastructure/providers/safe-browsing.provider.js';
import { UrlHausProvider } from '../../src/infrastructure/providers/urlhaus.provider.js';
import { normalizeAndValidateUrl } from '../../src/domain/services/url-normalizer.js';

const sampleTarget = normalizeAndValidateUrl('https://example.com/login');

describe('SafeBrowsingProvider (Google Safe Browsing Lookup API v4)', () => {
  it('retourne UNAVAILABLE (NOT_CONFIGURED) sans appel réseau si la clé API est absente', async () => {
    const fetchSpy = vi.fn();
    const provider = new SafeBrowsingProvider({
      apiKey: undefined,
      fetchFn: fetchSpy as unknown as typeof fetch,
    });

    const result = await provider.checkUrl(sampleTarget);

    expect(result.status).toBe('UNAVAILABLE');
    expect(result.unavailableReason).toBe('NOT_CONFIGURED');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('retourne NO_KNOWN_THREAT lorsque l’API renvoie un objet vide {} et vérifie redirect: error', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const provider = new SafeBrowsingProvider({
      apiKey: 'fake-test-key',
      fetchFn: fetchMock as unknown as typeof fetch,
    });

    const result = await provider.checkUrl(sampleTarget);

    expect(result.status).toBe('NO_KNOWN_THREAT');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, requestInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(requestInit.redirect).toBe('error');
  });

  it('retourne THREAT_FOUND lorsque l’API signale SOCIAL_ENGINEERING', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          matches: [{ threatType: 'SOCIAL_ENGINEERING' }],
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const provider = new SafeBrowsingProvider({
      apiKey: 'fake-test-key',
      fetchFn: fetchMock as unknown as typeof fetch,
    });

    const result = await provider.checkUrl(sampleTarget);

    expect(result.status).toBe('THREAT_FOUND');
    expect(result.threatTypes).toEqual(['PHISHING_OR_SOCIAL_ENGINEERING']);
  });

  it('gère les limites de débit (HTTP 429), les erreurs 500, le JSON malformé et les timeouts', async () => {
    // 1. HTTP 429
    const rateLimitProvider = new SafeBrowsingProvider({
      apiKey: 'fake-test-key',
      fetchFn: vi
        .fn()
        .mockResolvedValue(new Response('Too Many Requests', { status: 429 })) as unknown as typeof fetch,
    });
    const rateLimitRes = await rateLimitProvider.checkUrl(sampleTarget);
    expect(rateLimitRes.status).toBe('UNAVAILABLE');
    expect(rateLimitRes.unavailableReason).toBe('RATE_LIMITED');

    // 2. JSON malformé
    const malformedProvider = new SafeBrowsingProvider({
      apiKey: 'fake-test-key',
      fetchFn: vi
        .fn()
        .mockResolvedValue(
          new Response('<html>Bad Gateway</html>', { status: 200 })
        ) as unknown as typeof fetch,
    });
    const malformedRes = await malformedProvider.checkUrl(sampleTarget);
    expect(malformedRes.status).toBe('UNAVAILABLE');
    expect(malformedRes.unavailableReason).toBe('MALFORMED_RESPONSE');

    // 3. Timeout
    const timeoutErr = new Error('The operation was aborted due to timeout');
    timeoutErr.name = 'TimeoutError';
    const timeoutProvider = new SafeBrowsingProvider({
      apiKey: 'fake-test-key',
      fetchFn: vi.fn().mockRejectedValue(timeoutErr) as unknown as typeof fetch,
    });
    const timeoutRes = await timeoutProvider.checkUrl(sampleTarget);
    expect(timeoutRes.status).toBe('UNAVAILABLE');
    expect(timeoutRes.unavailableReason).toBe('TIMEOUT');
  });
});

describe('UrlHausProvider (abuse.ch URLhaus API v1)', () => {
  it('retourne UNAVAILABLE (NOT_CONFIGURED) si Auth-Key est absente', async () => {
    const fetchSpy = vi.fn();
    const provider = new UrlHausProvider({
      authKey: '',
      fetchFn: fetchSpy as unknown as typeof fetch,
    });

    const result = await provider.checkUrl(sampleTarget);

    expect(result.status).toBe('UNAVAILABLE');
    expect(result.unavailableReason).toBe('NOT_CONFIGURED');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('retourne NO_KNOWN_THREAT sur query_status === "no_results"', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ query_status: 'no_results' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const provider = new UrlHausProvider({
      authKey: 'fake-urlhaus-key',
      fetchFn: fetchMock as unknown as typeof fetch,
    });

    const result = await provider.checkUrl(sampleTarget);
    expect(result.status).toBe('NO_KNOWN_THREAT');
  });

  it('retourne THREAT_FOUND sur query_status === "ok"', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          query_status: 'ok',
          threat: 'malware_download',
          url_status: 'online',
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }
      )
    );

    const provider = new UrlHausProvider({
      authKey: 'fake-urlhaus-key',
      fetchFn: fetchMock as unknown as typeof fetch,
    });

    const result = await provider.checkUrl(sampleTarget);
    expect(result.status).toBe('THREAT_FOUND');
    expect(result.threatTypes).toEqual(['MALWARE']);
    expect(result.summary).toContain('malware_download');
  });

  it('gère les réponses malformées et les dépassements de débit (HTTP 429 / 509)', async () => {
    const overLimitProvider = new UrlHausProvider({
      authKey: 'fake-urlhaus-key',
      fetchFn: vi
        .fn()
        .mockResolvedValue(new Response('', { status: 509 })) as unknown as typeof fetch,
    });
    const overLimitRes = await overLimitProvider.checkUrl(sampleTarget);
    expect(overLimitRes.status).toBe('UNAVAILABLE');
    expect(overLimitRes.unavailableReason).toBe('RATE_LIMITED');

    const unexpectedStatusProvider = new UrlHausProvider({
      authKey: 'fake-urlhaus-key',
      fetchFn: vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ query_status: 'invalid_url' }), { status: 200 })
        ) as unknown as typeof fetch,
    });
    const unexpectedRes = await unexpectedStatusProvider.checkUrl(sampleTarget);
    expect(unexpectedRes.status).toBe('UNAVAILABLE');
    expect(unexpectedRes.unavailableReason).toBe('MALFORMED_RESPONSE');
  });
});
