import { isIP } from 'node:net';
import type { Finding } from '../models/analysis-report.js';
import type { NormalizedUrl } from '../ports/threat-provider.js';

const KNOWN_URL_SHORTENERS: ReadonlySet<string> = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'rb.gy',
  'cutt.ly',
  'ow.ly',
  'rebrand.ly',
  'shorturl.at',
  'tiny.cc',
  'buff.ly',
  'bl.ink',
  'v.gd',
]);

const SUSPICIOUS_EXTENSIONS: ReadonlySet<string> = new Set([
  '.exe',
  '.scr',
  '.bat',
  '.cmd',
  '.msi',
  '.vbs',
  '.ps1',
  '.jar',
  '.apk',
  '.dmg',
  '.iso',
  '.hta',
  '.lnk',
  '.zip',
  '.rar',
  '.7z',
]);

const LOCAL_OR_INTERNAL_SUFFIXES: readonly string[] = [
  '.localhost',
  '.local',
  '.internal',
  '.home.arpa',
  '.lan',
];

function stripIpv6Brackets(hostname: string): string {
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    return hostname.slice(1, -1);
  }
  return hostname;
}

function isPrivateOrReservedIpv4(ip: string): boolean {
  const parts = ip.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) {
    return false;
  }
  const [a = 0, b = 0, c = 0] = parts;

  // 0.0.0.0/8 (Réseau courant)
  if (a === 0) return true;
  // 10.0.0.0/8 (Privé RFC 1918)
  if (a === 10) return true;
  // 100.64.0.0/10 (Carrier-Grade NAT RFC 6598)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 169.254.0.0/16 (Link-local & Cloud Metadata 169.254.169.254)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 (Privé RFC 1918)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.0.0.0/24 (Réservé IETF)
  if (a === 192 && b === 0 && c === 0) return true;
  // 192.168.0.0/16 (Privé RFC 1918)
  if (a === 192 && b === 168) return true;
  // 198.18.0.0/15 (Benchmarking RFC 2544)
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 224.0.0.0/4 (Multicast) et 240.0.0.0/4 (Réservé / Broadcast)
  if (a >= 224) return true;

  return false;
}

function isPrivateOrReservedIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === '::1' || normalized === '::' || normalized === '0:0:0:0:0:0:0:1') {
    return true;
  }
  // Link-local fe80::/10
  if (/^fe[89ab][0-9a-f]:/.test(normalized)) {
    return true;
  }
  // Unique Local Address fc00::/7 (fc00:: à fdff::)
  if (/^f[cd][0-9a-f]{2}:/.test(normalized)) {
    return true;
  }
  // Multicast ff00::/8
  if (normalized.startsWith('ff')) {
    return true;
  }
  // IPv4-mapped IPv6 (ex. ::ffff:127.0.0.1 ou forme hexadécimale canonique ::ffff:7f00:1)
  if (normalized.startsWith('::ffff:')) {
    return true;
  }
  return false;
}

function isInternalHostname(hostname: string): boolean {
  if (hostname === 'localhost') {
    return true;
  }
  return LOCAL_OR_INTERNAL_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

function extractRawHostAuthority(rawUrl: string): string | undefined {
  const match = /^https?:\/\/([^/?#]+)/i.exec(rawUrl);
  if (!match?.[1]) {
    return undefined;
  }
  const authority = match[1];
  const atIndex = authority.lastIndexOf('@');
  const hostPort = atIndex >= 0 ? authority.slice(atIndex + 1) : authority;
  if (hostPort.startsWith('[')) {
    const closeBracket = hostPort.indexOf(']');
    return closeBracket >= 0 ? hostPort.slice(0, closeBracket + 1).toLowerCase() : hostPort;
  }
  return hostPort.split(':')[0]?.toLowerCase();
}

function extractMatchingExtension(pathname: string): string | undefined {
  const lowerPath = pathname.toLowerCase();
  for (const ext of SUSPICIOUS_EXTENSIONS) {
    if (lowerPath.endsWith(ext)) {
      return ext;
    }
  }
  return undefined;
}

/**
 * Exécute l'analyse heuristique locale sur une URL normalisée.
 * Ne réalise aucune requête HTTP ni aucune résolution DNS vers la cible.
 */
export function evaluateUrlHeuristics(target: NormalizedUrl): readonly Finding[] {
  const findings: Finding[] = [];
  const bareHost = stripIpv6Brackets(target.hostname);
  const ipVersion = isIP(bareHost);

  // 1. Détection d'hôtes internes, loopback, privés ou métadonnées cloud (Critique / Anti-SSRF)
  if (
    isInternalHostname(target.hostname) ||
    (ipVersion === 4 && isPrivateOrReservedIpv4(bareHost)) ||
    (ipVersion === 6 && isPrivateOrReservedIpv6(bareHost))
  ) {
    findings.push({
      code: 'PRIVATE_OR_RESERVED_IP',
      category: 'HEURISTIC_SIGNAL',
      severity: 'CRITICAL',
      title: 'Cible réseau locale, privée ou réservée détectée',
      description:
        `L’hôte "${target.hostname}" pointe vers une adresse interne, de bouclage (loopback) ou de métadonnées réseau. ` +
        'Un lien public légitime ne doit jamais cibler une ressource réseau locale.',
      source: 'local_heuristics',
    });
  } else if (ipVersion === 4 || ipVersion === 6) {
    // 2. Adresse IP publique brute au lieu d'un nom de domaine
    findings.push({
      code: 'RAW_IP_HOST',
      category: 'HEURISTIC_SIGNAL',
      severity: 'WARNING',
      title: 'Utilisation d’une adresse IP brute au lieu d’un nom de domaine',
      description:
        `L’URL utilise directement l’adresse IP "${bareHost}" sans nom de domaine. ` +
        'Cette pratique est fréquente pour héberger temporairement des pages de phishing ou des charges malveillantes.',
      source: 'local_heuristics',
    });
  }

  // 2bis. Détection d'une adresse IP obfusquée (décimale, octale ou hexadécimale) dans l'URL soumise
  const rawHost = extractRawHostAuthority(target.rawSubmitted);
  if (ipVersion === 4 && rawHost && rawHost !== target.hostname) {
    findings.push({
      code: 'OBFUSCATED_IP_ENCODING',
      category: 'HEURISTIC_SIGNAL',
      severity: 'CRITICAL',
      title: 'Encodage d’adresse IP obfusqué (décimal, octal ou hexadécimal)',
      description:
        `L’hôte soumis ("${rawHost}") utilise une notation numérique obfusquée qui se résout vers l’adresse IP "${target.hostname}". ` +
        'Cette technique sert presque exclusivement à contourner les filtres de sécurité.',
      source: 'local_heuristics',
    });
  }

  // 3. Identifiants intégrés dans l'URL (user:pass@host)
  if (target.hasEmbeddedCredentials) {
    findings.push({
      code: 'EMBEDDED_CREDENTIALS',
      category: 'HEURISTIC_SIGNAL',
      severity: 'WARNING',
      title: 'Présence d’identifiants ou du symbole "@" dans l’autorité de l’URL',
      description:
        'L’URL contient une section "utilisateur@" avant le véritable nom de domaine. ' +
        'Les attaquants utilisent souvent cette syntaxe (ex. https://site-connu.fr@domaine-piege.test) pour tromper la lecture visuelle.',
      source: 'local_heuristics',
    });
  }

  // 4. Domaine internationalisé (IDN / Punycode xn--) — Risque d'attaque homographe
  if (target.hostname.includes('xn--')) {
    findings.push({
      code: 'PUNYCODE_HOMOGRAPH_RISK',
      category: 'HEURISTIC_SIGNAL',
      severity: 'WARNING',
      title: 'Domaine internationalisé (Punycode / IDN) détecté',
      description:
        `Le domaine utilise l’encodage Punycode "${target.hostname}" (affiché "${target.unicodeHostname}"). ` +
        'Vérifiez attentivement qu’il ne s’agit pas d’une imitation visuelle d’une marque connue à l’aide d’alphabets similaires (attaque homographe).',
      source: 'local_heuristics',
    });
  }

  // 5. Raccourcisseur d'URL connu
  if (KNOWN_URL_SHORTENERS.has(target.hostname)) {
    findings.push({
      code: 'URL_SHORTENER_DETECTED',
      category: 'HEURISTIC_SIGNAL',
      severity: 'WARNING',
      title: 'Service de raccourcissement d’URL détecté',
      description:
        `Le domaine "${target.hostname}" est un raccourcisseur de lien. ` +
        'La véritable destination finale est masquée derrière une redirection que LinkSentinel ne suit pas par sécurité.',
      source: 'local_heuristics',
    });
  }

  // 6. Port réseau non standard
  if (target.port !== '' && target.port !== '80' && target.port !== '443') {
    findings.push({
      code: 'NON_STANDARD_PORT',
      category: 'HEURISTIC_SIGNAL',
      severity: 'WARNING',
      title: `Port réseau non standard (:${target.port})`,
      description:
        `L’URL spécifie explicitement le port ${target.port}. ` +
        'Les sites grand public légitimes utilisent presque exclusivement les ports standards (443 pour HTTPS, 80 pour HTTP).',
      source: 'local_heuristics',
    });
  }

  // 7. Profondeur excessive de sous-domaines et abus de tirets (uniquement pour les noms de domaine)
  if (ipVersion === 0 && !isInternalHostname(target.hostname)) {
    const labels = target.hostname.split('.');
    if (labels.length >= 5) {
      findings.push({
        code: 'EXCESSIVE_SUBDOMAINS',
        category: 'HEURISTIC_SIGNAL',
        severity: 'WARNING',
        title: `Nombre élevé de sous-domaines (${labels.length} niveaux)`,
        description:
          'L’empilement de nombreux sous-domaines est fréquemment utilisé pour masquer le véritable domaine principal sur les écrans mobiles.',
        source: 'local_heuristics',
      });
    }

    const hyphenCount = (target.hostname.match(/-/g) ?? []).length;
    if (hyphenCount >= 4 && !target.hostname.includes('xn--')) {
      findings.push({
        code: 'EXCESSIVE_HYPHENS_IN_DOMAIN',
        category: 'HEURISTIC_SIGNAL',
        severity: 'WARNING',
        title: 'Nombre inhabituel de tirets dans le nom de domaine',
        description:
          `Le nom d’hôte "${target.hostname}" comporte ${hyphenCount} tirets, un motif courant dans les domaines enregistrés pour des campagnes d’hameçonnage.`,
        source: 'local_heuristics',
      });
    }
  }

  // 8. Extension de fichier exécutable ou archive dans le chemin
  const matchedExt = extractMatchingExtension(target.pathname);
  if (matchedExt) {
    findings.push({
      code: 'SUSPICIOUS_FILE_EXTENSION',
      category: 'HEURISTIC_SIGNAL',
      severity: 'WARNING',
      title: `Lien pointant vers un fichier potentiellement exécutable ou une archive (${matchedExt})`,
      description:
        `Le chemin de l’URL se termine par "${matchedExt}". ` +
        'L’ouverture de ce lien pourrait déclencher le téléchargement direct d’un programme ou d’une archive malveillante.',
      source: 'local_heuristics',
    });
  }

  // 9. Longueur inhabituelle de l'URL
  if (target.normalizedUrl.length > 250) {
    findings.push({
      code: 'EXCESSIVE_URL_LENGTH',
      category: 'HEURISTIC_SIGNAL',
      severity: 'WARNING',
      title: `URL particulièrement longue (${target.normalizedUrl.length} caractères)`,
      description:
        'Une URL très longue peut dissimuler une redirection ouverte, des paramètres encodés ou tenter de masquer la destination réelle.',
      source: 'local_heuristics',
    });
  }

  // 10. Analyse du schéma de transport (HTTP vs HTTPS)
  if (target.scheme === 'http') {
    findings.push({
      code: 'UNENCRYPTED_HTTP',
      category: 'HEURISTIC_SIGNAL',
      severity: 'WARNING',
      title: 'Protocole HTTP non chiffré',
      description:
        'Le lien utilise HTTP sans chiffrement TLS. Toute donnée saisie sur ce site transiterait en clair sur le réseau.',
      source: 'local_heuristics',
    });
  } else {
    findings.push({
      code: 'HTTPS_SCHEME_PRESENT',
      category: 'POSITIVE_OBSERVATION',
      severity: 'NEUTRAL',
      title: 'Protocole HTTPS utilisé (chiffrement du transport uniquement)',
      description:
        'Le lien utilise HTTPS. Attention : la présence du cadenas HTTPS indique uniquement que la connexion est chiffrée, ' +
        'mais ne garantit en aucun cas que le site est légitime ou digne de confiance.',
      source: 'local_heuristics',
    });
  }

  return findings;
}
