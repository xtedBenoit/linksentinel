export type ProviderStatus = 'THREAT_FOUND' | 'NO_KNOWN_THREAT' | 'UNAVAILABLE';

export type ProviderThreatType =
  | 'PHISHING_OR_SOCIAL_ENGINEERING'
  | 'MALWARE'
  | 'UNWANTED_SOFTWARE'
  | 'POTENTIALLY_HARMFUL_APPLICATION'
  | 'OTHER_THREAT';

export type UnavailableReason =
  | 'NOT_CONFIGURED'
  | 'TIMEOUT'
  | 'RATE_LIMITED'
  | 'NETWORK_ERROR'
  | 'HTTP_ERROR'
  | 'MALFORMED_RESPONSE';

export interface ProviderResult {
  readonly providerName: string;
  readonly displayName: string;
  readonly status: ProviderStatus;
  readonly threatTypes?: readonly ProviderThreatType[];
  readonly unavailableReason?: UnavailableReason;
  readonly summary: string;
  readonly checkedAt: string;
  readonly latencyMs?: number;
}
