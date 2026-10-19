import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/infrastructure/config/env.js';
import { redactUrlForLog } from '../../src/infrastructure/logging/url-redactor.js';

describe('Configuration (loadConfig)', () => {
  it('applique les valeurs par défaut sécurisées lorsqu’aucune variable n’est fournie', () => {
    const config = loadConfig({});
    expect(config.port).toBe(3000);
    expect(config.host).toBe('127.0.0.1');
    expect(config.nodeEnv).toBe('development');
    expect(config.rateLimitMax).toBe(30);
    expect(config.rateLimitWindowMs).toBe(60000);
    expect(config.maxUrlLength).toBe(2048);
    expect(config.providerTimeoutMs).toBe(3000);
    expect(config.googleSafeBrowsingApiKey).toBeUndefined();
    expect(config.urlhausAuthKey).toBeUndefined();
  });

  it('normalise les clés API vides en undefined', () => {
    const config = loadConfig({
      GOOGLE_SAFE_BROWSING_API_KEY: '   ',
      URLHAUS_AUTH_KEY: '',
    });
    expect(config.googleSafeBrowsingApiKey).toBeUndefined();
    expect(config.urlhausAuthKey).toBeUndefined();
  });

  it('rejette un port ou un timeout hors limites', () => {
    expect(() => loadConfig({ PORT: '70000' })).toThrow(/PORT/);
    expect(() => loadConfig({ PROVIDER_TIMEOUT_MS: '100' })).toThrow(/PROVIDER_TIMEOUT_MS/);
    expect(() => loadConfig({ NODE_ENV: 'staging' })).toThrow(/NODE_ENV/);
  });
});

describe('Masquage des URL pour les logs (redactUrlForLog)', () => {
  it('masque le chemin, les paramètres de requête, le fragment et les identifiants HTTP', () => {
    const raw =
      'https://admin:secretPass123@Example.COM:8443/reset-password/token-xyz?session=987654#step2';
    const redacted = redactUrlForLog(raw);

    expect(redacted).toBe('https://example.com:8443/[REDACTED]');
    expect(redacted).not.toContain('secretPass123');
    expect(redacted).not.toContain('token-xyz');
    expect(redacted).not.toContain('987654');
    expect(redacted).not.toContain('step2');
  });

  it('conserve uniquement le schéma et le domaine pour une URL racine sans chemin ni query', () => {
    expect(redactUrlForLog('https://example.com')).toBe('https://example.com/');
    expect(redactUrlForLog('http://example.com/')).toBe('http://example.com/');
  });

  it('signale les schémas non HTTP/HTTPS sans exposer le contenu', () => {
    const redacted = redactUrlForLog('javascript:alert(document.cookie)');
    expect(redacted).toBe('[UNSUPPORTED_SCHEME:javascript]');
    expect(redacted).not.toContain('cookie');
  });

  it('gère proprement les URL malformées, vides ou surdimensionnées', () => {
    expect(redactUrlForLog('')).toBe('[EMPTY_OR_NON_STRING_URL]');
    expect(redactUrlForLog(null)).toBe('[EMPTY_OR_NON_STRING_URL]');
    expect(redactUrlForLog('not a valid url')).toBe('[MALFORMED_URL]');
    expect(redactUrlForLog('https://example.com/' + 'a'.repeat(5000))).toBe(
      '[OVERSIZED_URL_INPUT]'
    );
  });
});
