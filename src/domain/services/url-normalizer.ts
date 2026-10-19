import { domainToUnicode } from 'node:url';
import { isIP } from 'node:net';
import type { NormalizedUrl } from '../ports/threat-provider.js';

export type UrlValidationErrorCode =
  | 'EMPTY_URL'
  | 'URL_TOO_LONG'
  | 'CONTROL_CHARACTERS_DETECTED'
  | 'MALFORMED_URL'
  | 'UNSUPPORTED_SCHEME'
  | 'INVALID_HOSTNAME';

export class UrlValidationError extends Error {
  public readonly code: UrlValidationErrorCode;

  constructor(code: UrlValidationErrorCode, message: string) {
    super(message);
    this.name = 'UrlValidationError';
    this.code = code;
  }
}

const CONTROL_CHARS_REGEX = /[\u0000-\u001F\u007F]/;

export interface NormalizeUrlOptions {
  readonly maxLength?: number;
}

function isSyntacticallyValidHostname(hostname: string): boolean {
  if (!hostname || hostname.length > 253) {
    return false;
  }

  // Cas IPv6 entre crochets : ex. [2001:db8::1]
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    const bareIpv6 = hostname.slice(1, -1);
    return isIP(bareIpv6) === 6;
  }

  // Cas IPv4 canonique
  if (isIP(hostname) === 4) {
    return true;
  }

  // Cas localhost explicite
  if (hostname === 'localhost') {
    return true;
  }

  // Un nom de domaine standard doit comporter au moins deux labels séparés par un point
  // et aucun label vide, ni commençant/terminant par un tiret
  if (hostname.startsWith('.') || hostname.endsWith('.') || hostname.includes('..')) {
    return false;
  }

  const labels = hostname.split('.');
  if (labels.length < 2) {
    return false;
  }

  for (const label of labels) {
    if (
      label.length === 0 ||
      label.length > 63 ||
      label.startsWith('-') ||
      label.endsWith('-')
    ) {
      return false;
    }
  }

  const tld = labels[labels.length - 1];
  // Le TLD ne peut pas être purement numérique (un hôte numérique serait une IPv4)
  if (!tld || tld.length < 2 || /^\d+$/.test(tld)) {
    return false;
  }

  return true;
}

function buildMaskedUrl(parsed: URL): string {
  if (!parsed.username && !parsed.password) {
    return parsed.toString();
  }
  const clone = new URL(parsed.toString());
  if (clone.username) {
    clone.username = '***';
  }
  if (clone.password) {
    clone.password = '***';
  }
  return clone.toString();
}

function buildDefangedUrl(maskedUrl: string, hostname: string): string {
  const defangedScheme = maskedUrl.replace(/^http(s?):\/\//i, 'hxxp$1://');
  const defangedHost = hostname.replace(/\./g, '[.]');
  return defangedScheme.replace(hostname, defangedHost);
}

/**
 * Valide et normalise une URL soumise par l'utilisateur sans effectuer aucune requête réseau.
 * S'appuie sur le parser standard WHATWG URL de Node.js (prévention OWASP SSRF).
 */
export function normalizeAndValidateUrl(
  rawInput: unknown,
  options: NormalizeUrlOptions = {}
): NormalizedUrl {
  const maxLength = options.maxLength ?? 2048;

  if (typeof rawInput !== 'string') {
    throw new UrlValidationError('EMPTY_URL', 'L’URL fournie doit être une chaîne de caractères.');
  }

  const trimmed = rawInput.trim();
  if (trimmed.length === 0) {
    throw new UrlValidationError('EMPTY_URL', 'L’URL fournie ne peut pas être vide.');
  }

  if (trimmed.length > maxLength) {
    throw new UrlValidationError(
      'URL_TOO_LONG',
      `L’URL dépasse la longueur maximale autorisée (${maxLength} caractères).`
    );
  }

  if (CONTROL_CHARS_REGEX.test(trimmed)) {
    throw new UrlValidationError(
      'CONTROL_CHARACTERS_DETECTED',
      'L’URL contient des caractères de contrôle non autorisés.'
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new UrlValidationError(
      'MALFORMED_URL',
      'Le format de l’URL est invalide (exemple attendu : https://exemple.fr/chemin).'
    );
  }

  // Liste blanche stricte des schémas (OWASP SSRF : http et https uniquement)
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new UrlValidationError(
      'UNSUPPORTED_SCHEME',
      `Le schéma "${parsed.protocol.replace(/:$/, '')}" n’est pas autorisé. Seuls HTTP et HTTPS sont acceptés.`
    );
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!isSyntacticallyValidHostname(hostname)) {
    throw new UrlValidationError(
      'INVALID_HOSTNAME',
      'Le nom d’hôte ou de domaine de l’URL est invalide ou incomplet.'
    );
  }

  const scheme = parsed.protocol === 'https:' ? 'https' : 'http';
  const unicodeHostname = hostname.startsWith('[')
    ? hostname
    : domainToUnicode(hostname) || hostname;

  const hasEmbeddedCredentials = parsed.username.length > 0 || parsed.password.length > 0;
  const maskedUrl = buildMaskedUrl(parsed);
  const defangedUrl = buildDefangedUrl(maskedUrl, hostname);

  return Object.freeze({
    rawSubmitted: trimmed,
    normalizedUrl: parsed.toString(),
    maskedUrl,
    defangedUrl,
    scheme,
    hostname,
    unicodeHostname,
    port: parsed.port,
    pathname: parsed.pathname,
    search: parsed.search,
    hash: parsed.hash,
    hasEmbeddedCredentials,
  });
}
