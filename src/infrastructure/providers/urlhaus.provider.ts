import type { ProviderResult } from '../../domain/models/provider-result.js';
import type {
  NormalizedUrl,
  ThreatIntelligenceProvider,
} from '../../domain/ports/threat-provider.js';

const URLHAUS_V1_URL_ENDPOINT = 'https://urlhaus-api.abuse.ch/v1/url/';

export interface UrlHausProviderOptions {
  readonly authKey?: string;
  readonly timeoutMs?: number;
  readonly fetchFn?: typeof fetch;
}

interface UrlHausResponsePayload {
  readonly query_status?: unknown;
  readonly threat?: unknown;
  readonly url_status?: unknown;
}

function isAbortOrTimeoutError(err: unknown): boolean {
  if (!(err instanceof Error)) {
    return false;
  }
  return err.name === 'TimeoutError' || err.name === 'AbortError';
}

/**
 * Adaptateur pour l'API communautaire URLhaus (abuse.ch).
 * Spécialisée dans la détection de liens de distribution de malwares.
 */
export class UrlHausProvider implements ThreatIntelligenceProvider {
  public readonly name = 'urlhaus';
  public readonly displayName = 'URLhaus (abuse.ch)';

  private readonly authKey?: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;

  constructor(options: UrlHausProviderOptions = {}) {
    this.authKey = options.authKey?.trim() || undefined;
    this.timeoutMs = options.timeoutMs ?? 3000;
    this.fetchFn = options.fetchFn ?? globalThis.fetch;
  }

  public async checkUrl(target: NormalizedUrl): Promise<ProviderResult> {
    const checkedAt = new Date().toISOString();

    if (!this.authKey) {
      return {
        providerName: this.name,
        displayName: this.displayName,
        status: 'UNAVAILABLE',
        unavailableReason: 'NOT_CONFIGURED',
        summary:
          'Fournisseur non configuré (clé URLHAUS_AUTH_KEY absente). Vérification ignorée.',
        checkedAt,
      };
    }

    const startTime = performance.now();
    const formBody = new URLSearchParams({ url: target.normalizedUrl }).toString();

    try {
      const response = await this.fetchFn(URLHAUS_V1_URL_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          'Auth-Key': this.authKey,
          'User-Agent': 'LinkSentinel/0.1.0 (Non-Commercial Security Prototype)',
        },
        body: formBody,
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      const latencyMs = Math.round(performance.now() - startTime);

      if (response.status === 429 || response.status === 509) {
        return {
          providerName: this.name,
          displayName: this.displayName,
          status: 'UNAVAILABLE',
          unavailableReason: 'RATE_LIMITED',
          summary: `Limite de débit atteinte auprès de URLhaus (HTTP ${response.status}).`,
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
          summary: `Réponse en erreur de URLhaus (HTTP ${response.status}).`,
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
          summary: 'Réponse JSON illisible reçue depuis URLhaus.',
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
          summary: 'Structure JSON invalide reçue depuis URLhaus.',
          checkedAt,
          latencyMs,
        };
      }

      const typedPayload = payload as UrlHausResponsePayload;

      if (typedPayload.query_status === 'no_results') {
        return {
          providerName: this.name,
          displayName: this.displayName,
          status: 'NO_KNOWN_THREAT',
          summary: 'Aucune menace connue répertoriée dans la base URLhaus (abuse.ch).',
          checkedAt,
          latencyMs,
        };
      }

      if (typedPayload.query_status === 'ok') {
        const threatDetail =
          typeof typedPayload.threat === 'string' ? typedPayload.threat : 'malware_download';
        const urlStatus =
          typeof typedPayload.url_status === 'string' ? typedPayload.url_status : 'inconnu';

        return {
          providerName: this.name,
          displayName: this.displayName,
          status: 'THREAT_FOUND',
          threatTypes: ['MALWARE'],
          summary: `URL répertoriée par URLhaus comme source de logiciel malveillant (type : ${threatDetail}, état : ${urlStatus}).`,
          checkedAt,
          latencyMs,
        };
      }

      return {
        providerName: this.name,
        displayName: this.displayName,
        status: 'UNAVAILABLE',
        unavailableReason: 'MALFORMED_RESPONSE',
        summary: 'Statut de réponse URLhaus inattendu ou non pris en charge.',
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
          summary: `Délai d’attente dépassé (${this.timeoutMs} ms) lors de la consultation de URLhaus.`,
          checkedAt,
          latencyMs,
        };
      }

      return {
        providerName: this.name,
        displayName: this.displayName,
        status: 'UNAVAILABLE',
        unavailableReason: 'NETWORK_ERROR',
        summary: 'Erreur de communication réseau lors de la consultation de URLhaus.',
        checkedAt,
        latencyMs,
      };
    }
  }
}
