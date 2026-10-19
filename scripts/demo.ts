import { buildApp } from '../src/http/app.js';
import { loadConfig } from '../src/infrastructure/config/env.js';
import type { ThreatIntelligenceProvider, NormalizedUrl } from '../src/domain/ports/threat-provider.js';
import type { ProviderResult } from '../src/domain/models/provider-result.js';
import type { AnalysisReport } from '../src/domain/models/analysis-report.js';

/**
 * Fournisseur de démonstration déterministe utilisant exclusivement des domaines synthétiques
 * (RFC 2606 : .test, .example) afin de ne jamais manipuler de liens frauduleux actifs.
 */
class SyntheticDemoProvider implements ThreatIntelligenceProvider {
  public readonly name = 'synthetic_threat_intel';
  public readonly displayName = 'Synthetic Threat Feed (Démo)';

  public async checkUrl(target: NormalizedUrl): Promise<ProviderResult> {
    const checkedAt = new Date().toISOString();

    if (target.hostname === 'synthetic-phish.example.test') {
      return {
        providerName: this.name,
        displayName: this.displayName,
        status: 'THREAT_FOUND',
        threatTypes: ['PHISHING_OR_SOCIAL_ENGINEERING'],
        summary: 'Domaine synthétique répertorié dans le jeu d’essai comme page d’hameçonnage.',
        checkedAt,
        latencyMs: 12,
      };
    }

    if (target.hostname === 'timeout-demo.example.test') {
      return {
        providerName: this.name,
        displayName: this.displayName,
        status: 'UNAVAILABLE',
        unavailableReason: 'TIMEOUT',
        summary: 'Délai d’attente dépassé (simulation d’indisponibilité de la source externe).',
        checkedAt,
        latencyMs: 3000,
      };
    }

    return {
      providerName: this.name,
      displayName: this.displayName,
      status: 'NO_KNOWN_THREAT',
      summary: 'Aucune menace connue dans le flux de démonstration au moment de la vérification.',
      checkedAt,
      latencyMs: 8,
    };
  }
}

interface DemoScenario {
  readonly title: string;
  readonly url: string;
}

const SCENARIOS: readonly DemoScenario[] = [
  {
    title: 'Scénario 1 — Menace confirmée par une source de réputation',
    url: 'https://synthetic-phish.example.test/auth/verify-account',
  },
  {
    title: 'Scénario 2 — Signaux heuristiques multiples (Punycode + @ + port non standard + .exe)',
    url: 'https://service-client@xn--pple-43d.example.test:8443/documents/facture_2026.exe',
  },
  {
    title: 'Scénario 3 — Tentative d’accès interne / SSRF (Métadonnées Cloud 169.254.169.254)',
    url: 'http://169.254.169.254/latest/meta-data/iam/',
  },
  {
    title: 'Scénario 4 — Fournisseur externe indisponible (Timeout -> Analyse INCOMPLETE)',
    url: 'https://timeout-demo.example.test/accueil',
  },
  {
    title: 'Scénario 5 — Lien HTTPS standard sans menace connue (Prudence maintenue)',
    url: 'https://www.example.com/documentation/securite',
  },
  {
    title: 'Scénario 6 — Rejet d’une entrée dangereuse (Schéma javascript: interdit)',
    url: 'javascript:alert(document.cookie)',
  },
];

async function runDemo(): Promise<void> {
  const config = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent' });
  const app = await buildApp({
    config,
    providers: [new SyntheticDemoProvider()],
  });

  console.log('================================================================================');
  console.log('🛡️  DÉMONSTRATION REPRODUCTIBLE — LINKSENTINEL (Jeu de données synthétique)');
  console.log('================================================================================\n');

  try {
    for (const scenario of SCENARIOS) {
      console.log(`▶ ${scenario.title}`);
      console.log(`  Entrée soumise : ${scenario.url}`);

      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/analyze',
        payload: { url: scenario.url },
      });

      if (response.statusCode !== 200) {
        const errBody = response.json<{ code: string; message: string }>();
        console.log(`  Code HTTP      : ${response.statusCode}`);
        console.log(`  Code d’erreur  : ${errBody.code}`);
        console.log(`  Message        : ${errBody.message}\n`);
        continue;
      }

      const report = response.json<AnalysisReport>();
      console.log(`  Code HTTP      : ${response.statusCode}`);
      console.log(`  Statut global  : ${report.status}`);
      console.log(`  Domaine extrait: ${report.hostname}`);
      console.log(`  URL défangée   : ${report.defangedUrl}`);
      console.log(`  Synthèse       : ${report.statusSummary}`);
      console.log(
        `  Indices (${report.findings.length})    : ${report.findings
          .map((f) => `[${f.severity}] ${f.code}`)
          .join(', ')}`
      );
      console.log(`  Conseil clé    : ${report.recommendations[0]}\n`);
    }
  } finally {
    await app.close();
  }

  console.log('================================================================================');
  console.log('✅ Démonstration terminée avec succès (aucune requête envoyée vers les cibles).');
  console.log('================================================================================');
}

void runDemo();
