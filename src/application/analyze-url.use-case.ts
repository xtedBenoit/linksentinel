import type { AnalysisReport } from '../domain/models/analysis-report.js';
import type { ProviderResult } from '../domain/models/provider-result.js';
import type { ThreatIntelligenceProvider } from '../domain/ports/threat-provider.js';
import { normalizeAndValidateUrl } from '../domain/services/url-normalizer.js';
import { evaluateUrlHeuristics } from '../domain/services/url-heuristics.js';
import { aggregateAnalysisReport } from '../domain/services/verdict-aggregator.js';

export interface AnalyzeUrlUseCaseOptions {
  readonly providers: readonly ThreatIntelligenceProvider[];
  readonly maxUrlLength?: number;
}

/**
 * Orchestre l'analyse complète d'une URL :
 * 1. Validation syntaxique et normalisation (sans requête réseau ni DNS)
 * 2. Analyse heuristique locale
 * 3. Interrogation parallèle et résiliente des fournisseurs de réputation (sauf cible réseau interne)
 * 4. Agrégation en un rapport explicable
 */
export class AnalyzeUrlUseCase {
  private readonly providers: readonly ThreatIntelligenceProvider[];
  private readonly maxUrlLength: number;

  constructor(options: AnalyzeUrlUseCaseOptions) {
    this.providers = options.providers;
    this.maxUrlLength = options.maxUrlLength ?? 2048;
  }

  public async execute(rawUrl: unknown): Promise<AnalysisReport> {
    const normalizedTarget = normalizeAndValidateUrl(rawUrl, {
      maxLength: this.maxUrlLength,
    });

    const heuristicFindings = evaluateUrlHeuristics(normalizedTarget);

    // Sécurité & Confidentialité : si l'URL pointe vers une adresse IP privée/loopback/interne,
    // on n'expose jamais cette URL interne à des fournisseurs tiers externes.
    const isInternalTarget = heuristicFindings.some(
      (f) => f.code === 'PRIVATE_OR_RESERVED_IP'
    );

    let providerResults: ProviderResult[];

    if (isInternalTarget) {
      const checkedAt = new Date().toISOString();
      providerResults = this.providers.map((provider) => ({
        providerName: provider.name,
        displayName: provider.displayName,
        status: 'UNAVAILABLE',
        unavailableReason: 'NOT_CONFIGURED',
        summary:
          'Consultation externe ignorée par sécurité : l’URL cible une adresse réseau locale ou privée.',
        checkedAt,
      }));
    } else {
      const settledResults = await Promise.allSettled(
        this.providers.map((provider) => provider.checkUrl(normalizedTarget))
      );

      providerResults = settledResults.map((settled, index) => {
        if (settled.status === 'fulfilled') {
          return settled.value;
        }
        const provider = this.providers[index];
        return {
          providerName: provider?.name ?? 'unknown_provider',
          displayName: provider?.displayName ?? 'Fournisseur externe',
          status: 'UNAVAILABLE',
          unavailableReason: 'NETWORK_ERROR',
          summary: 'Erreur inattendue lors de l’interrogation du fournisseur.',
          checkedAt: new Date().toISOString(),
        };
      });
    }

    return aggregateAnalysisReport(normalizedTarget, heuristicFindings, providerResults);
  }
}
