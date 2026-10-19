import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../../src/http/app.js';
import { loadConfig } from '../../src/infrastructure/config/env.js';

describe('Interface Web (Frontend statique — Phase 5)', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    if (app) {
      await app.close();
      app = undefined;
    }
  });

  it('sert la page d’accueil GET / avec le formulaire d’analyse et les en-têtes CSP', async () => {
    app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test' }),
    });

    const response = await app.inject({
      method: 'GET',
      url: '/',
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/html');
    expect(response.headers['content-security-policy']).toContain("script-src 'self'");
    expect(response.body).toContain('LinkSentinel');
    expect(response.body).toContain('id="analyze-form"');
    expect(response.body).toContain('data-sample-url=');
  });

  it('sert les ressources statiques /styles.css et /app.js et garantit l’absence de innerHTML ou de secrets', async () => {
    app = await buildApp({
      config: loadConfig({
        NODE_ENV: 'test',
        GOOGLE_SAFE_BROWSING_API_KEY: 'super-secret-gsb-key-not-for-frontend',
        URLHAUS_AUTH_KEY: 'super-secret-urlhaus-key-not-for-frontend',
      }),
    });

    const cssRes = await app.inject({ method: 'GET', url: '/styles.css' });
    expect(cssRes.statusCode).toBe(200);
    expect(cssRes.headers['content-type']).toContain('text/css');

    const jsRes = await app.inject({ method: 'GET', url: '/app.js' });
    expect(jsRes.statusCode).toBe(200);
    expect(jsRes.headers['content-type']).toMatch(/javascript/);

    // Vérification de sécurité anti-XSS : aucun usage de innerHTML, outerHTML ou eval
    expect(jsRes.body).not.toMatch(/\.innerHTML\s*=/);
    expect(jsRes.body).not.toMatch(/\.outerHTML\s*=/);
    expect(jsRes.body).not.toMatch(/\beval\s*\(/);

    // Vérification qu'aucune clé API configurée côté serveur n'est exposée au frontend
    expect(jsRes.body).not.toContain('super-secret-gsb-key-not-for-frontend');
    expect(jsRes.body).not.toContain('super-secret-urlhaus-key-not-for-frontend');
  });
});
