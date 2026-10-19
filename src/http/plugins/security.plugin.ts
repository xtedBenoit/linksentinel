import type { FastifyInstance } from 'fastify';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import type { AppConfig } from '../../infrastructure/config/env.js';

/**
 * Enregistre les protections HTTP de base :
 * - En-têtes de sécurité stricts via @fastify/helmet (CSP, X-Frame-Options, etc.)
 * - Limitation de débit (Rate Limiting) par IP via @fastify/rate-limit
 */
export async function registerSecurityPlugins(
  app: FastifyInstance,
  config: AppConfig
): Promise<void> {
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    referrerPolicy: {
      policy: 'no-referrer',
    },
  });

  await app.register(rateLimit, {
    max: config.rateLimitMax,
    timeWindow: config.rateLimitWindowMs,
    errorResponseBuilder: (_request, context) => ({
      statusCode: 429,
      error: 'Too Many Requests',
      code: 'RATE_LIMIT_EXCEEDED',
      message: `Limite de requêtes atteinte. Réessayez dans ${Math.ceil(context.ttl / 1000)} seconde(s).`,
    }),
  });
}
