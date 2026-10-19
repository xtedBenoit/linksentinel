/**
 * Client JavaScript léger pour LinkSentinel.
 * Sécurité :
 * - Manipulation du DOM exclusivement via textContent et createElement (zéro innerHTML)
 * - Aucun rendu de balise <a href="..."> vers l'URL analysée (prévention du clic accidentel)
 * - Aucun appel réseau vers la cible : seul l'endpoint local POST /api/v1/analyze est appelé
 */
(() => {
  const form = document.getElementById('analyze-form');
  const urlInput = document.getElementById('url-input');
  const submitBtn = document.getElementById('submit-btn');
  const clearBtn = document.getElementById('clear-btn');
  const copyDefangedBtn = document.getElementById('copy-defanged-btn');

  const errorSection = document.getElementById('error-section');
  const errorTitle = document.getElementById('error-title');
  const errorCode = document.getElementById('error-code');
  const errorMessage = document.getElementById('error-message');

  const reportSection = document.getElementById('report-section');
  const verdictBanner = document.getElementById('verdict-banner');
  const verdictBadge = document.getElementById('verdict-badge');
  const verdictTitle = document.getElementById('verdict-title');
  const verdictSummary = document.getElementById('verdict-summary');
  const analyzedAtEl = document.getElementById('analyzed-at');

  const metaHostname = document.getElementById('meta-hostname');
  const metaScheme = document.getElementById('meta-scheme');
  const metaDefanged = document.getElementById('meta-defanged');
  const metaSubmitted = document.getElementById('meta-submitted');

  const providersList = document.getElementById('providers-list');
  const findingsList = document.getElementById('findings-list');
  const recommendationsList = document.getElementById('recommendations-list');

  const STATUS_PRESENTATION = {
    CONFIRMED_THREAT: {
      badge: 'MENACE OU CRITIQUE',
      title: 'Menace confirmée ou anomalie critique détectée',
      cssClass: 'status-confirmed-threat',
    },
    SUSPICIOUS: {
      badge: 'SUSPECT',
      title: 'Signaux structurels suspects détectés',
      cssClass: 'status-suspicious',
    },
    INCOMPLETE: {
      badge: 'ANALYSE INCOMPLÈTE',
      title: 'Vérification partielle (source externe indisponible)',
      cssClass: 'status-incomplete',
    },
    NO_KNOWN_THREAT: {
      badge: 'AUCUNE MENACE CONNUE',
      title: 'Aucune menace connue détectée (vigilance maintenue)',
      cssClass: 'status-no-known-threat',
    },
  };

  const PROVIDER_STATUS_LABELS = {
    THREAT_FOUND: { label: 'Menace signalée', severityClass: 'severity-critical' },
    NO_KNOWN_THREAT: { label: 'Aucune menace connue', severityClass: 'severity-positive' },
    UNAVAILABLE: { label: 'Indisponible / Non configuré', severityClass: 'severity-info' },
  };

  const CATEGORY_LABELS = {
    CONFIRMED_REPUTATION: 'Menace Réputation',
    HEURISTIC_SIGNAL: 'Signal Heuristique',
    POSITIVE_OBSERVATION: 'Observation Technique',
    PROVIDER_STATUS: 'État Fournisseur',
  };

  const SEVERITY_CLASSES = {
    CRITICAL: 'severity-critical',
    WARNING: 'severity-warning',
    INFO: 'severity-info',
    NEUTRAL: 'severity-neutral',
  };

  function clearChildren(element) {
    while (element.firstChild) {
      element.removeChild(element.firstChild);
    }
  }

  function showError(title, code, message) {
    reportSection.hidden = true;
    errorTitle.textContent = title;
    errorCode.textContent = code || 'ERROR';
    errorMessage.textContent = message;
    errorSection.hidden = false;
  }

  function hideFeedback() {
    errorSection.hidden = true;
    reportSection.hidden = true;
  }

  function renderProviders(providers) {
    clearChildren(providersList);

    for (const provider of providers) {
      const item = document.createElement('div');
      const statusMeta = PROVIDER_STATUS_LABELS[provider.status] || {
        label: provider.status,
        severityClass: 'severity-neutral',
      };
      item.className = `list-item ${statusMeta.severityClass}`;

      const header = document.createElement('div');
      header.className = 'item-header';

      const title = document.createElement('span');
      title.className = 'item-title';
      title.textContent = provider.displayName;

      const tag = document.createElement('span');
      tag.className = 'item-tag';
      const latencySuffix =
        typeof provider.latencyMs === 'number' ? ` (${provider.latencyMs} ms)` : '';
      tag.textContent = `${statusMeta.label}${latencySuffix}`;

      header.appendChild(title);
      header.appendChild(tag);

      const desc = document.createElement('p');
      desc.className = 'item-desc';
      desc.textContent = provider.summary;

      item.appendChild(header);
      item.appendChild(desc);
      providersList.appendChild(item);
    }
  }

  function renderFindings(findings) {
    clearChildren(findingsList);

    for (const finding of findings) {
      const item = document.createElement('div');
      const sevClass = SEVERITY_CLASSES[finding.severity] || 'severity-neutral';
      item.className = `list-item ${sevClass}`;

      const header = document.createElement('div');
      header.className = 'item-header';

      const title = document.createElement('span');
      title.className = 'item-title';
      title.textContent = finding.title;

      const tag = document.createElement('span');
      tag.className = 'item-tag';
      const catLabel = CATEGORY_LABELS[finding.category] || finding.category;
      tag.textContent = `${catLabel} • ${finding.severity}`;

      header.appendChild(title);
      header.appendChild(tag);

      const desc = document.createElement('p');
      desc.className = 'item-desc';
      desc.textContent = finding.description;

      item.appendChild(header);
      item.appendChild(desc);
      findingsList.appendChild(item);
    }
  }

  function renderRecommendations(recommendations) {
    clearChildren(recommendationsList);

    for (const rec of recommendations) {
      const li = document.createElement('li');
      li.textContent = rec;
      recommendationsList.appendChild(li);
    }
  }

  function renderReport(report) {
    errorSection.hidden = true;

    const presentation = STATUS_PRESENTATION[report.status] || {
      badge: report.status,
      title: 'Résultat de l’analyse',
      cssClass: 'status-incomplete',
    };

    verdictBanner.className = `card verdict-banner ${presentation.cssClass}`;
    verdictBadge.textContent = presentation.badge;
    verdictTitle.textContent = presentation.title;
    verdictSummary.textContent = report.statusSummary;

    const dateObj = new Date(report.analyzedAt);
    analyzedAtEl.textContent = Number.isNaN(dateObj.getTime())
      ? report.analyzedAt
      : `Analysé le ${dateObj.toLocaleString('fr-FR')}`;

    metaHostname.textContent = report.hostname;
    metaScheme.textContent = report.scheme.toUpperCase();
    metaDefanged.textContent = report.defangedUrl;
    metaSubmitted.textContent = report.submittedUrl;

    renderProviders(Array.isArray(report.providers) ? report.providers : []);
    renderFindings(Array.isArray(report.findings) ? report.findings : []);
    renderRecommendations(Array.isArray(report.recommendations) ? report.recommendations : []);

    reportSection.hidden = false;
  }

  async function submitAnalysis(urlToAnalyze) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Analyse en cours...';

    try {
      const response = await fetch('/api/v1/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ url: urlToAnalyze }),
      });

      const data = await response.json().catch(() => null);

      if (!response.ok || !data) {
        const errTitle =
          response.status === 400
            ? 'URL invalide ou non autorisée'
            : response.status === 429
              ? 'Limite de requêtes atteinte'
              : 'Erreur lors de l’analyse';
        const code = data && data.code ? data.code : `HTTP_${response.status}`;
        const message =
          data && data.message
            ? data.message
            : 'La demande n’a pas pu aboutir. Vérifiez le format du lien soumis.';
        showError(errTitle, code, message);
        return;
      }

      renderReport(data);
    } catch {
      showError(
        'Erreur de communication',
        'NETWORK_FAILURE',
        'Impossible de joindre le serveur local LinkSentinel.'
      );
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Analyser le lien';
    }
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const value = urlInput.value.trim();
    if (!value) {
      showError('Champ requis', 'EMPTY_URL', 'Veuillez saisir ou coller une URL à analyser.');
      return;
    }
    void submitAnalysis(value);
  });

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    hideFeedback();
    urlInput.focus();
  });

  copyDefangedBtn.addEventListener('click', async () => {
    const text = metaDefanged.textContent || '';
    if (!text || !navigator.clipboard) {
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      const originalLabel = copyDefangedBtn.textContent;
      copyDefangedBtn.textContent = 'Copié !';
      setTimeout(() => {
        copyDefangedBtn.textContent = originalLabel;
      }, 1500);
    } catch {
      // Presse-papiers non disponible dans ce contexte
    }
  });

  const sampleButtons = document.querySelectorAll('[data-sample-url]');
  for (const button of sampleButtons) {
    button.addEventListener('click', () => {
      const sample = button.getAttribute('data-sample-url');
      if (sample) {
        urlInput.value = sample;
        void submitAnalysis(sample);
      }
    });
  }
})();
