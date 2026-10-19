import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Fastify, { type FastifyError, type FastifyInstance } from 'fastify';
import fastifyStatic from '@fastify/static';
import { type AppConfig, loadConfig } from '../infrastructure/config/env.js';
import { registerSecurityPlugins } from './plugins/security.plugin.js';
import type { ThreatIntelligenceProvider } from '../domain/ports/threat-provider.js';
import { SafeBrowsingProvider } from '../infrastructure/providers/safe-browsing.provider.js';
import { UrlHausProvider } from '../infrastructure/providers/urlhaus.provider.js';
import { AnalyzeUrlUseCase } from '../application/analyze-url.use-case.js';
import { registerAnalyzeRoutes } from './routes/analyze.route.js';

import type { DestinationStream } from 'pino';

export interface BuildAppOptions {
  readonly config?: AppConfig;
  readonly providers?: readonly ThreatIntelligenceProvider[];
  readonly loggerStream?: DestinationStream;
}

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(currentDir, '../../public');

/**
 * Construit et configure l'application Fastify.
 * Séparé de server.ts pour permettre les tests d'intégration par injection (app.inject)
 * sans ouvrir de port réseau réel.
 */
export async function buildApp(options: BuildAppOptions = {}): Promise<FastifyInstance> {
  const config = options.config ?? loadConfig();

  const app = Fastify({
    logger: {
      level: config.logLevel,
      stream: options.loggerStream,
      // Sécurité : on ne journalise que la méthode et la route de l'API,
      // jamais les en-têtes d'autorisation ni le corps contenant l'URL soumise.
      serializers: {
        req(request) {
          return {
            method: request.method,
            url: request.routeOptions?.url ?? request.url.split('?')[0],
          };
        },
      },
    },
    // Limite stricte de la taille de requête (4 Ko) pour prévenir les DoS par payload massif
    bodyLimit: 4096,
    // Validation JSON Schema stricte (pas de coercition implicite ni de suppression silencieuse des champs inconnus)
    ajv: {
      customOptions: {
        removeAdditional: false,
        coerceTypes: false,
        allErrors: false,
      },
    },
  });

  await registerSecurityPlugins(app, config);

  // Serveur de fichiers statiques pour l'interface Web (public/)
  await app.register(fastifyStatic, {
    root: publicDir,
    prefix: '/',
    index: ['index.html'],
  });

  const providers: readonly ThreatIntelligenceProvider[] = options.providers ?? [
    new SafeBrowsingProvider({
      apiKey: config.googleSafeBrowsingApiKey,
      timeoutMs: config.providerTimeoutMs,
    }),
    new UrlHausProvider({
      authKey: config.urlhausAuthKey,
      timeoutMs: config.providerTimeoutMs,
    }),
  ];

  const analyzeUrlUseCase = new AnalyzeUrlUseCase({
    providers,
    maxUrlLength: config.maxUrlLength,
  });

  // Route de santé technique
  app.get('/api/v1/health', async () => {
    return {
      status: 'ok',
      service: 'linksentinel',
      timestamp: new Date().toISOString(),
    };
  });

  // Route principale d'analyse d'URL
  registerAnalyzeRoutes(app, analyzeUrlUseCase);

  // Gestionnaire d'erreurs centralisé garantissant l'absence de fuite de stacktrace ou d'URL brute
  app.setErrorHandler((error: FastifyError, request, reply) => {
    if (error.statusCode === 429) {
      return reply.status(429).send({
        error: 'Too Many Requests',
        code: error.code || 'RATE_LIMIT_EXCEEDED',
        message: error.message,
      });
    }

    if (error.code === 'FST_ERR_CTP_BODY_TOO_LARGE' || error.statusCode === 413) {
      return reply.status(413).send({
        error: 'Payload Too Large',
        code: 'PAYLOAD_TOO_LARGE',
        message: 'La taille de la requête dépasse la limite autorisée (4096 octets).',
      });
    }

    if (error.validation || error.statusCode === 400) {
      return reply.status(400).send({
        error: 'Bad Request',
        code: 'INVALID_REQUEST_PAYLOAD',
        message: 'La requête est malformée ou ne respecte pas le schéma attendu.',
      });
    }

    request.log.error(
      { errCode: error.code, statusCode: error.statusCode ?? 500 },
      'Erreur interne lors du traitement de la requête'
    );

    return reply.status(500).send({
      error: 'Internal Server Error',
      code: 'INTERNAL_SERVER_ERROR',
      message: 'Une erreur interne est survenue lors du traitement de la demande.',
    });
  });

  return app;
}
