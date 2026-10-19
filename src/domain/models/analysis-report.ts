import type { ProviderResult } from './provider-result.js';

/**
 * Statut global explicable du rapport d'analyse :
 * - CONFIRMED_THREAT : Menace confirmée par une source de réputation ou cible réseau interne interdite
 * - SUSPICIOUS       : Signaux heuristiques suspects détectés sur la structure de l'URL
 * - INCOMPLETE       : Analyse incomplète (au moins un fournisseur indisponible, aucun signal suspect local)
 * - NO_KNOWN_THREAT  : Aucune menace connue détectée (ne garantit jamais à 100% la légitimité du site)
 */
export type GlobalStatus =
  | 'CONFIRMED_THREAT'
  | 'SUSPICIOUS'
  | 'INCOMPLETE'
  | 'NO_KNOWN_THREAT';

export type FindingCategory =
  | 'CONFIRMED_REPUTATION'
  | 'HEURISTIC_SIGNAL'
  | 'POSITIVE_OBSERVATION'
  | 'PROVIDER_STATUS';

export type FindingSeverity = 'CRITICAL' | 'WARNING' | 'INFO' | 'NEUTRAL';

export interface Finding {
  readonly code: string;
  readonly category: FindingCategory;
  readonly severity: FindingSeverity;
  readonly title: string;
  readonly description: string;
  readonly source: string;
}

export interface AnalysisReport {
  readonly status: GlobalStatus;
  readonly statusSummary: string;
  readonly submittedUrl: string;
  readonly defangedUrl: string;
  readonly hostname: string;
  readonly scheme: 'http' | 'https';
  readonly findings: readonly Finding[];
  readonly providers: readonly ProviderResult[];
  readonly recommendations: readonly string[];
  readonly analyzedAt: string;
}
