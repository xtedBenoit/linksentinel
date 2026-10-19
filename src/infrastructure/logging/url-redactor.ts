/**
 * Masque les éléments sensibles d'une URL (identifiants user:pass, chemin complet,
 * paramètres de requête, fragment) avant toute écriture dans les logs.
 *
 * Exigence de sécurité :
 * "Ne pas conserver les URL complètes par défaut."
 * "Ne pas inscrire les URL complètes dans les logs."
 */
export function redactUrlForLog(rawInput: unknown): string {
  if (typeof rawInput !== 'string' || rawInput.trim().length === 0) {
    return '[EMPTY_OR_NON_STRING_URL]';
  }

  // Éviter de parser des chaînes géantes dans le logger
  if (rawInput.length > 4096) {
    return '[OVERSIZED_URL_INPUT]';
  }

  try {
    const parsed = new URL(rawInput.trim());
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return `[UNSUPPORTED_SCHEME:${parsed.protocol.replace(/:$/, '')}]`;
    }

    const hasPathOrQuery =
      (parsed.pathname !== '' && parsed.pathname !== '/') ||
      parsed.search.length > 0 ||
      parsed.hash.length > 0;

    const portSegment = parsed.port ? `:${parsed.port}` : '';
    const suffix = hasPathOrQuery ? '/[REDACTED]' : '/';

    return `${parsed.protocol}//${parsed.hostname.toLowerCase()}${portSegment}${suffix}`;
  } catch {
    return '[MALFORMED_URL]';
  }
}
