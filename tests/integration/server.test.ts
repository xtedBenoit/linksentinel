import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../../src/http/app.js';
import { loadConfig } from '../../src/infrastructure/config/env.js';

describe('Serveur HTTP Fastify — Socle et sécurité (Phase 2)', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    if (app) {
      await app.close();
      app = undefined;
    }
  });

  it('répond 200 sur GET /api/v1/health avec les en-têtes de sécurité Helmet', async () => {
    const config = loadConfig({ NODE_ENV: 'test' });
    app = await buildApp({ config });

    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/health',
    });

    expect(response.statusCode).toBe(200);
    const payload = response.json<{ status: string; service: string; timestamp: string }>();
    expect(payload.status).toBe('ok');
    expect(payload.service).toBe('linksentinel');
    expect(() => new Date(payload.timestamp).toISOString()).not.toThrow();

    // Vérification des en-têtes de sécurité (Helmet)
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['referrer-policy']).toBe('no-referrer');
    expect(response.headers['content-security-policy']).toContain("default-src 'self'");
    expect(response.headers['content-security-policy']).toContain("frame-ancestors 'none'");
  });

  it('rejette les charges utiles dépassant la limite de 4096 octets avec un code 413', async () => {
    const config = loadConfig({ NODE_ENV: 'test' });
    app = await buildApp({ config });

    // Route factice pour tester la limite de taille sur un POST JSON
    app.post('/test-payload', async () => ({ ok: true }));

    const oversizedBody = JSON.stringify({ data: 'x'.repeat(5000) });
    const response = await app.inject({
      method: 'POST',
      url: '/test-payload',
      headers: { 'content-type': 'application/json' },
      payload: oversizedBody,
    });

    expect(response.statusCode).toBe(413);
    expect(response.json()).toMatchObject({
      code: 'PAYLOAD_TOO_LARGE',
    });
  });

  it('applique la limitation de débit (Rate Limiting) avec un code 429', async () => {
    const config = loadConfig({
      NODE_ENV: 'test',
      RATE_LIMIT_MAX: '2',
      RATE_LIMIT_WINDOW_MS: '60000',
    });
    app = await buildApp({ config });

    const first = await app.inject({ method: 'GET', url: '/api/v1/health' });
    const second = await app.inject({ method: 'GET', url: '/api/v1/health' });
    const third = await app.inject({ method: 'GET', url: '/api/v1/health' });

    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
    expect(third.statusCode).toBe(429);
    expect(third.json()).toMatchObject({
      code: 'RATE_LIMIT_EXCEEDED',
    });
  });
});
