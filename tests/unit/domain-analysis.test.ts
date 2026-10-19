import { describe, expect, it } from 'vitest';
import {
  normalizeAndValidateUrl,
  UrlValidationError,
} from '../../src/domain/services/url-normalizer.js';
import { evaluateUrlHeuristics } from '../../src/domain/services/url-heuristics.js';
import { aggregateAnalysisReport } from '../../src/domain/services/verdict-aggregator.js';
import type { ProviderResult } from '../../src/domain/models/provider-result.js';

describe('Normalisation et validation d’URL (normalizeAndValidateUrl)', () => {
  it('normalise une URL HTTPS valide et génère la version défangée', () => {
    const result = normalizeAndValidateUrl('  HTTPS://Sub.Example.COM/Path?q=1#frag  ');

    expect(result.scheme).toBe('https');
    expect(result.hostname).toBe('sub.example.com');
    expect(result.normalizedUrl).toBe('https://sub.example.com/Path?q=1#frag');
    expect(result.maskedUrl).toBe('https://sub.example.com/Path?q=1#frag');
    expect(result.defangedUrl).toBe('hxxps://sub[.]example[.]com/Path?q=1#frag');
    expect(result.hasEmbeddedCredentials).toBe(false);
  });

  it('masque les identifiants user:password dans maskedUrl et détecte hasEmbeddedCredentials', () => {
    const result = normalizeAndValidateUrl('https://banque.fr:secret@evil.example.test/login');

    expect(result.hostname).toBe('evil.example.test');
    expect(result.hasEmbeddedCredentials).toBe(true);
    expect(result.maskedUrl).toBe('https://***:***@evil.example.test/login');
    expect(result.maskedUrl).not.toContain('secret');
  });

  it('rejette les schémas dangereux ou non supportés (javascript, data, file, ftp)', () => {
    for (const dangerousUrl of [
      'javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'file:///etc/passwd',
      'ftp://files.example.com/archive.zip',
      'gopher://example.com:70/1',
    ]) {
      expect(() => normalizeAndValidateUrl(dangerousUrl)).toThrowError(UrlValidationError);
      try {
        normalizeAndValidateUrl(dangerousUrl);
      } catch (err) {
        expect((err as UrlValidationError).code).toBe('UNSUPPORTED_SCHEME');
      }
    }
  });

  it('rejette les URL vides, malformées, contenant des caractères de contrôle ou trop longues', () => {
    expect(() => normalizeAndValidateUrl('   ')).toThrowError(/vide/);
    expect(() => normalizeAndValidateUrl('pas-une-url')).toThrowError(/invalide/);
    expect(() => normalizeAndValidateUrl('https://example.com/\u0000test')).toThrowError(
      /contrôle/
    );
    expect(() =>
      normalizeAndValidateUrl('https://example.com/' + 'a'.repeat(2100), { maxLength: 2048 })
    ).toThrowError(/longueur maximale/);
  });

  it('rejette les noms d’hôtes structurellement invalides', () => {
    for (const invalidHostUrl of [
      'https://singleword/path',
      'https://-startdash.example.com/',
      'https://example..com/',
      'https://example.123/',
    ]) {
      expect(() => normalizeAndValidateUrl(invalidHostUrl)).toThrowError(UrlValidationError);
    }
  });
});

describe('Moteur d’heuristiques locales (evaluateUrlHeuristics)', () => {
  it('signale en CRITICAL les adresses IP privées, loopback, link-local (métadonnées cloud) et hôtes internes', () => {
    const internalTargets = [
      'http://127.0.0.1:8080/admin',
      'http://169.254.169.254/latest/meta-data/',
      'http://192.168.1.254/login',
      'http://10.0.0.1/',
      'http://172.20.0.5/',
      'http://[::1]/',
      'https://intranet.internal/auth',
      'http://localhost:3000/',
    ];

    for (const raw of internalTargets) {
      const normalized = normalizeAndValidateUrl(raw);
      const findings = evaluateUrlHeuristics(normalized);
      const critical = findings.find((f) => f.code === 'PRIVATE_OR_RESERVED_IP');

      expect(critical, `Devrait bloquer ${raw}`).toBeDefined();
      expect(critical?.severity).toBe('CRITICAL');
    }
  });

  it('détecte l’encodage d’adresse IP obfusqué (décimal / hexadécimal)', () => {
    // 2130706433 === 127.0.0.1
    const normalized = normalizeAndValidateUrl('http://2130706433/login');
    const findings = evaluateUrlHeuristics(normalized);

    expect(findings.some((f) => f.code === 'OBFUSCATED_IP_ENCODING')).toBe(true);
    expect(findings.some((f) => f.code === 'PRIVATE_OR_RESERVED_IP')).toBe(true);
  });

  it('signale en WARNING une adresse IP publique brute (plage de documentation RFC 5737)', () => {
    const normalized = normalizeAndValidateUrl('https://198.51.100.42/verify');
    const findings = evaluateUrlHeuristics(normalized);

    expect(findings.some((f) => f.code === 'RAW_IP_HOST' && f.severity === 'WARNING')).toBe(true);
    expect(findings.some((f) => f.code === 'PRIVATE_OR_RESERVED_IP')).toBe(false);
  });

  it('détecte le Punycode (IDN), les identifiants embarqués (@), le port non standard et les extensions exécutables', () => {
    const normalized = normalizeAndValidateUrl(
      'https://support:1234@xn--pple-43d.example.test:8443/update/facture.exe'
    );
    const findings = evaluateUrlHeuristics(normalized);
    const codes = findings.map((f) => f.code);

    expect(codes).toContain('EMBEDDED_CREDENTIALS');
    expect(codes).toContain('PUNYCODE_HOMOGRAPH_RISK');
    expect(codes).toContain('NON_STANDARD_PORT');
    expect(codes).toContain('SUSPICIOUS_FILE_EXTENSION');
  });

  it('détecte les raccourcisseurs d’URL connus', () => {
    const normalized = normalizeAndValidateUrl('https://bit.ly/3SyntheticExample');
    const findings = evaluateUrlHeuristics(normalized);

    expect(findings.some((f) => f.code === 'URL_SHORTENER_DETECTED')).toBe(true);
  });

  it('détecte l’empilement excessif de sous-domaines et l’abus de tirets', () => {
    const normalized = normalizeAndValidateUrl(
      'https://login.secure.account.verify-user-session-now-alert.example.test/auth'
    );
    const findings = evaluateUrlHeuristics(normalized);
    const codes = findings.map((f) => f.code);

    expect(codes).toContain('EXCESSIVE_SUBDOMAINS');
    expect(codes).toContain('EXCESSIVE_HYPHENS_IN_DOMAIN');
  });
});

describe('Agrégateur de verdict et rapport explicable (aggregateAnalysisReport)', () => {
  const cleanProvider: ProviderResult = {
    providerName: 'google_safe_browsing',
    displayName: 'Google Safe Browsing',
    status: 'NO_KNOWN_THREAT',
    summary: 'Aucune menace répertoriée par Google Safe Browsing.',
    checkedAt: '2026-10-16T15:00:00.000Z',
  };

  const threatProvider: ProviderResult = {
    providerName: 'urlhaus',
    displayName: 'URLhaus (abuse.ch)',
    status: 'THREAT_FOUND',
    threatTypes: ['MALWARE'],
    summary: 'URL répertoriée comme distribuant un logiciel malveillant.',
    checkedAt: '2026-10-16T15:00:00.000Z',
  };

  const unavailableProvider: ProviderResult = {
    providerName: 'urlhaus',
    displayName: 'URLhaus (abuse.ch)',
    status: 'UNAVAILABLE',
    unavailableReason: 'TIMEOUT',
    summary: 'Délai d’attente dépassé lors de l’interrogation de URLhaus.',
    checkedAt: '2026-10-16T15:00:00.000Z',
  };

  it('retourne CONFIRMED_THREAT lorsqu’un fournisseur confirme une menace', () => {
    const target = normalizeAndValidateUrl('https://example.com/clean-looking-path');
    const heuristics = evaluateUrlHeuristics(target);
    const report = aggregateAnalysisReport(target, heuristics, [cleanProvider, threatProvider]);

    expect(report.status).toBe('CONFIRMED_THREAT');
    expect(report.findings.some((f) => f.code === 'PROVIDER_THREAT_MATCH')).toBe(true);
  });

  it('retourne SUSPICIOUS lorsque les fournisseurs ne signalent rien mais qu’une heuristique WARNING se déclenche', () => {
    const target = normalizeAndValidateUrl('https://bit.ly/3SyntheticLink');
    const heuristics = evaluateUrlHeuristics(target);
    const report = aggregateAnalysisReport(target, heuristics, [cleanProvider]);

    expect(report.status).toBe('SUSPICIOUS');
    expect(report.recommendations.some((r) => r.includes('raccourcisseur'))).toBe(true);
  });

  it('retourne INCOMPLETE lorsqu’aucun signal suspect n’est détecté mais qu’un fournisseur est indisponible', () => {
    const target = normalizeAndValidateUrl('https://example.com/articles/news');
    const heuristics = evaluateUrlHeuristics(target);
    const report = aggregateAnalysisReport(target, heuristics, [
      cleanProvider,
      unavailableProvider,
    ]);

    expect(report.status).toBe('INCOMPLETE');
    expect(report.statusSummary).toContain('Analyse incomplète');
  });

  it('retourne NO_KNOWN_THREAT sans jamais garantir que le site est sûr à 100%', () => {
    const target = normalizeAndValidateUrl('https://example.com/documentation');
    const heuristics = evaluateUrlHeuristics(target);
    const report = aggregateAnalysisReport(target, heuristics, [cleanProvider]);

    expect(report.status).toBe('NO_KNOWN_THREAT');
    expect(report.statusSummary).toContain('ne garantit jamais');
    expect(report.recommendations.some((r) => r.includes('ne garantit pas'))).toBe(true);
  });
});
