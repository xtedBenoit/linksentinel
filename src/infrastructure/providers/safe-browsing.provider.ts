import type {
  ProviderResult,
  ProviderThreatType,
} from '../../domain/models/provider-result.js';
import type {
  NormalizedUrl,
  ThreatIntelligenceProvider,
} from '../../domain/ports/threat-provider.js';

const SAFE_BROWSING_V4_ENDPOINT =
  'https://safebrowsing.googleapis.com/v4/threatMatches:find';

export interface SafeBrowsingProviderOptions {
  readonly apiKey?: string;
  readonly timeoutMs?: number;
  readonly fetchFn?: typeof fetch;
}

interface SafeBrowsingMatch {
  readonly threatType?: unknown;
}

interface SafeBrowsingResponsePayload {
  readonly matches?: unknown;
}

function mapGoogleThreatType(rawType: unknown): ProviderThreatType {
  switch (rawType) {
    case 'SOCIAL_ENGINEERING':
      return 'PHISHING_OR_SOCIAL_ENGINEERING';
    case 'MALWARE':
      return 'MALWARE';
    case 'UNWANTED_SOFTWARE':
      return 'UNWANTED_SOFTWARE';
    case 'POTENTIALLY_HARMFUL_APPLICATION':
      return 'POTENTIALLY_HARMFUL_APPLICATION';
    default:
      return 'OTHER_THREAT';
  }
}

function isAbortOrTimeoutError(err: unknown): boolean {
  if (!(err instanceof Error)) {
    return false;
  }
  return err.name === 'TimeoutError' || err.name === 'AbortError';
}

/**
 * Adaptateur pour Google Safe Browsing Lookup API (v4).
 * Respecte les directives OWASP SSRF :
 * - URL d'endpoint constante codée en dur
 * - Aucun suivi de redirection (redirect: 'error')
 * - Délai d'attente strict (AbortSignal.timeout)
 */
export class SafeBrowsingProvider implements ThreatIntelligenceProvider {
  public readonly name = 'google_safe_browsing';
  public readonly displayName = 'Google Safe Browsing';

  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;

  constructor(options: SafeBrowsingProviderOptions = {}) {
    this.apiKey = options.apiKey?.trim() || undefined;
    this.timeoutMs = options.timeoutMs ?? 3000;
    this.fetchFn = options.fetchFn ?? globalThis.fetch;
  }

  public async checkUrl(target: NormalizedUrl): Promise<ProviderResult> {
    const checkedAt = new Date().toISOString();

    if (!this.apiKey) {
      return {
        providerName: this.name,
        displayName: this.displayName,
        status: 'UNAVAILABLE',
        unavailableReason: 'NOT_CONFIGURED',
        summary:
          'Fournisseur non configuré (clé GOOGLE_SAFE_BROWSING_API_KEY absente). Vérification ignorée.',
        checkedAt,
      };
    }

    const startTime = performance.now();
    const requestUrl = `${SAFE_BROWSING_V4_ENDPOINT}?key=${encodeURIComponent(this.apiKey)}`;

    const requestBody = {
      client: {
        clientId: 'linksentinel',
        clientVersion: '0.1.0',
      },
      threatInfo: {
        threatTypes: [
          'MALWARE',
          'SOCIAL_ENGINEERING',
          'UNWANTED_SOFTWARE',
          'POTENTIALLY_HARMFUL_APPLICATION',
        ],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: target.normalizedUrl }],
      },
    };

    try {
      const response = await this.fetchFn(requestUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(requestBody),
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      const latencyMs = Math.round(performance.now() - startTime);

      if (response.status === 429) {
        return {
          providerName: this.name,
          displayName: this.displayName,
          status: 'UNAVAILABLE',
          unavailableReason: 'RATE_LIMITED',
          summary: 'Limite de requêtes atteinte auprès de Google Safe Browsing (HTTP 429).',
          checkedAt,
          latencyMs,
        };
      }

      if (!response.ok) {
        return {
          providerName: this.name,
          displayName: this.displayName,
          status: 'UNAVAILABLE',
          unavailableReason: 'HTTP_ERROR',
          summary: `Réponse en erreur de Google Safe Browsing (HTTP ${response.status}).`,
          checkedAt,
          latencyMs,
        };
      }

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        return {
          providerName: this.name,
          displayName: this.displayName,
          status: 'UNAVAILABLE',
          unavailableReason: 'MALFORMED_RESPONSE',
          summary: 'Réponse JSON illisible reçue depuis Google Safe Browsing.',
          checkedAt,
          latencyMs,
        };
      }

      if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
        return {
          providerName: this.name,
          displayName: this.displayName,
          status: 'UNAVAILABLE',
          unavailableReason: 'MALFORMED_RESPONSE',
          summary: 'Structure de réponse inattendue reçue depuis Google Safe Browsing.',
          checkedAt,
          latencyMs,
        };
      }

      const typedPayload = payload as SafeBrowsingResponsePayload;
      if (typedPayload.matches === undefined) {
        return {
          providerName: this.name,
          displayName: this.displayName,
          status: 'NO_KNOWN_THREAT',
          summary:
            'Aucune menace connue signalée par Google Safe Browsing au moment de la vérification.',
          checkedAt,
          latencyMs,
        };
      }

      if (!Array.isArray(typedPayload.matches)) {
        return {
          providerName: this.name,
          displayName: this.displayName,
          status: 'UNAVAILABLE',
          unavailableReason: 'MALFORMED_RESPONSE',
          summary: 'Champ "matches" invalide dans la réponse Google Safe Browsing.',
          checkedAt,
          latencyMs,
        };
      }

      if (typedPayload.matches.length === 0) {
        return {
          providerName: this.name,
          displayName: this.displayName,
          status: 'NO_KNOWN_THREAT',
          summary:
            'Aucune menace connue signalée par Google Safe Browsing au moment de la vérification.',
          checkedAt,
          latencyMs,
        };
      }

      const threatTypes = Array.from(
        new Set(
          (typedPayload.matches as SafeBrowsingMatch[]).map((m) =>
            mapGoogleThreatType(m?.threatType)
          )
        )
      );

      return {
        providerName: this.name,
        displayName: this.displayName,
        status: 'THREAT_FOUND',
        threatTypes,
        summary:
          'Google Safe Browsing signale cette URL comme potentiellement dangereuse (hameçonnage ou programme malveillant).',
        checkedAt,
        latencyMs,
      };
    } catch (err) {
      const latencyMs = Math.round(performance.now() - startTime);
      if (isAbortOrTimeoutError(err)) {
        return {
          providerName: this.name,
          displayName: this.displayName,
          status: 'UNAVAILABLE',
          unavailableReason: 'TIMEOUT',
          summary: `Délai d’attente dépassé (${this.timeoutMs} ms) lors de la consultation de Google Safe Browsing.`,
          checkedAt,
          latencyMs,
        };
      }

      return {
        providerName: this.name,
        displayName: this.displayName,
        status: 'UNAVAILABLE',
        unavailableReason: 'NETWORK_ERROR',
        summary: 'Erreur de communication réseau lors de la consultation de Google Safe Browsing.',
        checkedAt,
        latencyMs,
      };
    }
  }
}
