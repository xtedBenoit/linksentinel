import type { ProviderResult } from '../models/provider-result.js';

export interface NormalizedUrl {
  readonly rawSubmitted: string;
  readonly normalizedUrl: string;
  readonly maskedUrl: string;
  readonly defangedUrl: string;
  readonly scheme: 'http' | 'https';
  readonly hostname: string;
  readonly unicodeHostname: string;
  readonly port: string;
  readonly pathname: string;
  readonly search: string;
  readonly hash: string;
  readonly hasEmbeddedCredentials: boolean;
}

/**
 * Port (interface) commun à tous les fournisseurs de Threat Intelligence.
 * Permet d'ajouter, remplacer ou mocker un fournisseur sans modifier le moteur d'analyse.
 */
export interface ThreatIntelligenceProvider {
  readonly name: string;
  readonly displayName: string;
  checkUrl(target: NormalizedUrl): Promise<ProviderResult>;
}
