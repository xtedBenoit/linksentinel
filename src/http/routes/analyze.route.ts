import type { FastifyInstance } from 'fastify';
import type { AnalyzeUrlUseCase } from '../../application/analyze-url.use-case.js';
import { UrlValidationError } from '../../domain/services/url-normalizer.js';
import { redactUrlForLog } from '../../infrastructure/logging/url-redactor.js';

interface AnalyzeRequestBody {
  readonly url: string;
}

const analyzeBodySchema = {
  type: 'object',
  required: ['url'],
  additionalProperties: false,
  properties: {
    url: {
      type: 'string',
    },
  },
} as const;

export function registerAnalyzeRoutes(
  app: FastifyInstance,
  analyzeUrlUseCase: AnalyzeUrlUseCase
): void {
  app.post<{ Body: AnalyzeRequestBody }>(
    '/api/v1/analyze',
    {
      schema: {
        body: analyzeBodySchema,
      },
    },
    async (request, reply) => {
      const rawUrl = request.body.url;
      const redactedUrl = redactUrlForLog(rawUrl);

      try {
        const report = await analyzeUrlUseCase.execute(rawUrl);

        request.log.info(
          {
            redactedUrl,
            hostname: report.hostname,
            status: report.status,
          },
          'Analyse d’URL terminée'
        );

        return await reply.status(200).send(report);
      } catch (err) {
        if (err instanceof UrlValidationError) {
          request.log.warn(
            {
              redactedUrl,
              validationCode: err.code,
            },
            'Rejet d’une URL invalide ou non autorisée'
          );

          return await reply.status(400).send({
            error: 'Bad Request',
            code: err.code,
            message: err.message,
          });
        }

        throw err;
      }
    }
  );
}
