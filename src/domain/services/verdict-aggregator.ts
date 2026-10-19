import type {
  AnalysisReport,
  Finding,
  GlobalStatus,
} from '../models/analysis-report.js';
import type { ProviderResult } from '../models/provider-result.js';
import type { NormalizedUrl } from '../ports/threat-provider.js';

function buildProviderFindings(providers: readonly ProviderResult[]): Finding[] {
  const providerFindings: Finding[] = [];

  for (const provider of providers) {
    if (provider.status === 'THREAT_FOUND') {
      const threatsLabel =
        provider.threatTypes && provider.threatTypes.length > 0
          ? provider.threatTypes.join(', ')
          : 'MENACE_SIGNALÉE';

      providerFindings.push({
        code: 'PROVIDER_THREAT_MATCH',
        category: 'CONFIRMED_REPUTATION',
        severity: 'CRITICAL',
        title: `Menace signalée par ${provider.displayName}`,
        description: `${provider.summary} (Catégorie(s) : ${threatsLabel}).`,
        source: provider.providerName,
      });
    } else if (provider.status === 'UNAVAILABLE') {
      providerFindings.push({
        code: 'PROVIDER_UNAVAILABLE',
        category: 'PROVIDER_STATUS',
        severity: 'INFO',
        title: `Source ${provider.displayName} indisponible`,
        description: provider.summary,
        source: provider.providerName,
      });
    } else {
      providerFindings.push({
        code: 'PROVIDER_NO_KNOWN_THREAT',
        category: 'PROVIDER_STATUS',
        severity: 'NEUTRAL',
        title: `Aucune menace connue auprès de ${provider.displayName}`,
        description: provider.summary,
        source: provider.providerName,
      });
    }
  }

  return providerFindings;
}

function determineGlobalStatus(
  heuristicFindings: readonly Finding[],
  providers: readonly ProviderResult[]
): GlobalStatus {
  const hasProviderThreat = providers.some((p) => p.status === 'THREAT_FOUND');
  const hasCriticalHeuristic = heuristicFindings.some((f) => f.severity === 'CRITICAL');

  if (hasProviderThreat || hasCriticalHeuristic) {
    return 'CONFIRMED_THREAT';
  }

  const hasWarningHeuristic = heuristicFindings.some((f) => f.severity === 'WARNING');
  if (hasWarningHeuristic) {
    return 'SUSPICIOUS';
  }

  const hasUnavailableProvider =
    providers.length === 0 || providers.some((p) => p.status === 'UNAVAILABLE');
  if (hasUnavailableProvider) {
    return 'INCOMPLETE';
  }

  return 'NO_KNOWN_THREAT';
}

function buildStatusSummary(
  status: GlobalStatus,
  providers: readonly ProviderResult[]
): string {
  switch (status) {
    case 'CONFIRMED_THREAT': {
      const flaggedByProvider = providers.some((p) => p.status === 'THREAT_FOUND');
      return flaggedByProvider
        ? 'Alerte critique : ce lien est signalé comme potentiellement dangereux (hameçonnage ou logiciel malveillant) par au moins une source de renseignement.'
        : 'Alerte critique : ce lien présente une anomalie structurelle critique (adresse interne/locale ou adresse IP obfusquée).';
    }
    case 'SUSPICIOUS':
      return (
        'Prudence accrue : aucune menace n’est confirmée dans les bases consultées, ' +
        'mais la structure de l’URL comporte un ou plusieurs signaux suspects.'
      );
    case 'INCOMPLETE':
      return (
        'Analyse incomplète : aucun signal suspect local n’a été détecté, mais au moins une source de réputation ' +
        'n’a pas pu être consultée. Ce résultat ne doit en aucun cas être interprété comme une garantie de sécurité.'
      );
    case 'NO_KNOWN_THREAT':
      return (
        'Aucune menace connue détectée à cet instant. Attention : l’absence de signalement ne garantit jamais ' +
        'qu’un lien est sûr (un site frauduleux très récent peut ne pas encore être répertorié).'
      );
  }
}

function buildRecommendations(
  status: GlobalStatus,
  heuristicFindings: readonly Finding[]
): readonly string[] {
  const codes = new Set(heuristicFindings.map((f) => f.code));
  const recommendations: string[] = [];

  if (status === 'CONFIRMED_THREAT') {
    recommendations.push(
      'N’ouvrez pas ce lien et ne téléchargez aucun fichier associé.',
      'Ne saisissez jamais vos identifiants, codes reçus par SMS (2FA) ou coordonnées bancaires.',
      'Si ce lien provient d’un proche ou d’un collègue, prévenez-le par un autre canal (son compte peut être compromis).'
    );
    return recommendations;
  }

  if (codes.has('URL_SHORTENER_DETECTED')) {
    recommendations.push(
      'Ce lien utilise un raccourcisseur qui masque la destination finale : demandez l’URL complète à l’expéditeur avant de cliquer.'
    );
  }

  if (codes.has('PUNYCODE_HOMOGRAPH_RISK') || codes.has('EMBEDDED_CREDENTIALS')) {
    recommendations.push(
      'L’adresse utilise une syntaxe pouvant imiter un site officiel : accédez au service souhaité en tapant vous-même son adresse habituelle dans votre navigateur.'
    );
  }

  if (codes.has('SUSPICIOUS_FILE_EXTENSION')) {
    recommendations.push(
      'Ce lien pointe vers un fichier exécutable ou une archive : n’exécutez jamais un programme reçu par message non sollicité.'
    );
  }

  if (status === 'INCOMPLETE') {
    recommendations.push(
      'Une ou plusieurs sources de réputation étant indisponibles, traitez ce lien comme non vérifié et abstenez-vous de l’ouvrir en cas de doute.'
    );
  }

  // Recommandations générales permanentes (y compris pour NO_KNOWN_THREAT)
  recommendations.push(
    'Un résultat sans menace connue ne garantit pas qu’un site est légitime : les campagnes de phishing récentes apparaissent souvent avant d’être signalées.',
    'En cas de message urgent (colis bloqué, compte suspendu, remboursement), passez toujours par l’application officielle ou un favori connu plutôt que par le lien reçu.'
  );

  return recommendations;
}

/**
 * Agrège de manière déterministe et explicable les résultats heuristiques locaux
 * et les retours des fournisseurs de Threat Intelligence.
 */
export function aggregateAnalysisReport(
  target: NormalizedUrl,
  heuristicFindings: readonly Finding[],
  providers: readonly ProviderResult[],
  analyzedAt: Date = new Date()
): AnalysisReport {
  const providerFindings = buildProviderFindings(providers);
  const allFindings: Finding[] = [...providerFindings, ...heuristicFindings];
  const status = determineGlobalStatus(heuristicFindings, providers);
  const statusSummary = buildStatusSummary(status, providers);
  const recommendations = buildRecommendations(status, heuristicFindings);

  return Object.freeze({
    status,
    statusSummary,
    submittedUrl: target.maskedUrl,
    defangedUrl: target.defangedUrl,
    hostname: target.hostname,
    scheme: target.scheme,
    findings: Object.freeze(allFindings),
    providers: Object.freeze([...providers]),
    recommendations: Object.freeze(recommendations),
    analyzedAt: analyzedAt.toISOString(),
  });
}
