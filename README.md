# 🛡️ LinkSentinel

**LinkSentinel** est une application web et une API REST d'analyse défensive d'URL conçue en **Node.js**, **TypeScript** et **Fastify**.  
Elle aide les utilisateurs à évaluer si un lien reçu par SMS, WhatsApp, Messenger ou e-mail présente des indices d'hameçonnage (*phishing*), de distribution de logiciels malveillants (*malware*) ou d'anomalies techniques **avant de l'ouvrir**.

> [!IMPORTANT]
> **Principe fondamental de sécurité :** LinkSentinel **ne garantit jamais qu'un lien est sûr à 100 %** sous prétexte qu'aucune menace n'a été trouvée. Une campagne d'hameçonnage très récente (*zero-day*) peut ne pas encore figurer dans les bases de réputation.

---

## 1. Fonctionnalités clés

* **Analyse passive *Zero-Touch Target*** : LinkSentinel **n'ouvre jamais l'URL soumise**, ne suit aucune redirection du site suspect et **n'effectue aucune requête DNS** vers la cible.
* **Moteur heuristique local** :
  * Détection des adresses IPv4/IPv6 privées, loopback (`127.0.0.1`, `::1`), link-local / métadonnées cloud (`169.254.169.254`) et hôtes internes (`localhost`, `.internal`, `.local`).
  * Détection des notations d'adresses IP obfusquées (décimale `2130706433`, octale, hexadécimale).
  * Détection des adresses IP publiques brutes utilisées à la place d'un nom de domaine.
  * Détection des domaines internationalisés Punycode (`xn--`) pouvant servir aux attaques homographes IDN.
  * Détection des identifiants intégrés dans l'autorité (`utilisateur@domaine-piege.test`).
  * Détection des services de raccourcissement d'URL (`bit.ly`, `tinyurl.com`, `t.co`, etc.) masquant la destination finale.
  * Détection des ports non standards, de l'empilement excessif de sous-domaines, de l'abus de tirets et des extensions exécutables/archives (`.exe`, `.scr`, `.msi`, `.zip`, etc.).
* **Intégration multi-fournisseurs de Threat Intelligence** :
  * **Google Safe Browsing Lookup API v4** (phishing / ingénierie sociale, malwares, logiciels indésirables).
  * **URLhaus API v1 — abuse.ch** (distribution de charges malveillantes).
  * Fonctionnement autonome et résilient : si aucune clé API n'est configurée ou si un fournisseur subit une panne / un timeout, l'analyse aboutit proprement avec le statut `INCOMPLETE` (ou `SUSPICIOUS` / `CONFIRMED_THREAT` selon les autres signaux).
* **Confidentialité dès la conception (*Privacy by Design*)** :
  * Aucune base de données requise.
  * Les URL complètes, jetons de réinitialisation ou paramètres de requête (`?token=...`) **ne sont jamais inscrits dans les logs**.

---

## 2. Architecture logicielle

Le projet applique une **Architecture Propre (Hexagonale)** séparant strictement quatre couches :

```text
src/
├── domain/          # Logique métier pure (0 dépendance HTTP ou framework)
│   ├── models/      # AnalysisReport, GlobalStatus, Finding, ProviderResult
│   ├── ports/       # Interface ThreatIntelligenceProvider et NormalizedUrl
│   └── services/    # Validation WHATWG URL, heuristiques locales, agrégateur de verdict
├── application/     # Orchestration du cas d'usage (AnalyzeUrlUseCase)
├── infrastructure/  # Adaptateurs externes (SafeBrowsing, URLhaus), env.ts, url-redactor.ts
├── http/            # Serveur Fastify, plugins de sécurité (Helmet, Rate-Limit), routes et schémas
└── server.ts        # Point d'entrée et gestion de l'arrêt gracieux (SIGINT/SIGTERM)
public/              # Interface web statique (HTML5, CSS3, JavaScript vanilla sécurisé)
tests/               # Suites de tests unitaires et d'intégration (Vitest)
```

---

## 3. Sécurité applicative (Conformité OWASP SSRF)

1. **Prévention SSRF (OWASP Case 1)** :
   * Le serveur n'émet jamais de requête vers l'URL fournie par l'utilisateur.
   * Les seuls appels réseau sortants ciblent des constantes HTTPS codées en dur (`https://safebrowsing.googleapis.com/...` et `https://urlhaus-api.abuse.ch/...`) avec `redirect: 'error'` et un délai d'attente strict (`AbortSignal.timeout`).
   * Si l'URL soumise cible une adresse IP privée ou locale, elle est bloquée localement en `CONFIRMED_THREAT` et n'est même pas transmise aux fournisseurs externes.
2. **Validation stricte des entrées** :
   * Parsing exclusivement via le standard WHATWG `new URL()` de Node.js.
   * Liste blanche stricte des schémas : seuls `http:` et `https:` sont acceptés (`javascript:`, `data:`, `file:`, `ftp:`, `gopher:` sont rejetés en `HTTP 400`).
   * Plafond de taille de requête (`bodyLimit: 4096` octets -> `HTTP 413`), longueur maximale d'URL (`2048` caractères) et limitation de débit par IP (`@fastify/rate-limit` -> `HTTP 429`).
3. **Protection du Frontend (Anti-XSS & Anti-Clic)** :
   * Content-Security-Policy (CSP) stricte via `@fastify/helmet` (`default-src 'self'`, `script-src 'self'`, `frame-ancestors 'none'`).
   * Manipulation du DOM exclusivement via `textContent` et `createElement` (aucun usage de `innerHTML`).
   * L'URL analysée est affichée sous forme de texte inerte et défangé (`hxxps://exemple[.]com`), jamais dans un lien cliquable `<a href="...">`.

---

## 4. Installation et démarrage rapide

### Prérequis
* **Node.js** `>= 20.0.0` et **npm**.

### 1. Installer les dépendances
```bash
npm install
```

### 2. Configurer l'environnement (optionnel pour le mode local)
Copiez le fichier d'exemple :
```bash
cp .env.example .env
```
* **Sans clés API** : LinkSentinel démarre immédiatement. Le moteur heuristique local fonctionne à 100 % et les fournisseurs non configurés apparaissent clairement comme `UNAVAILABLE` (`NOT_CONFIGURED`).
* **Avec clés API gratuites (usage non commercial)** :
  * `GOOGLE_SAFE_BROWSING_API_KEY` : clé gratuite via la [Console Google Cloud](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com).
  * `URLHAUS_AUTH_KEY` : clé communautaire gratuite via le portail [abuse.ch Auth Portal](https://auth.abuse.ch/).

### 3. Commandes utiles
```bash
npm run dev         # Lance le serveur en mode développement avec rechargement à chaud (http://127.0.0.1:3000)
npm run demo        # Exécute la démonstration reproductible en ligne de commande (6 scénarios synthétiques)
npm run typecheck   # Vérifie le typage TypeScript sans générer de fichiers
npm run build       # Compile TypeScript vers le dossier dist/
npm start           # Démarre la version compilée de production (node dist/server.js)
npm test            # Exécute l'intégralité des tests unitaires, d'intégration et de sécurité
```

### 4. Exécution avec Docker
```bash
# Construire l'image multi-stage sécurisée (utilisateur non-root)
docker build -t linksentinel:latest .

# Lancer le conteneur sur le port 3000
docker run --rm -p 3000:3000 --env-file .env.example linksentinel:latest
```

---

## 5. Contrat de l'API REST

### `POST /api/v1/analyze`

* **En-tête** : `Content-Type: application/json`
* **Corps de la requête** :
```json
{
  "url": "https://banque-securite@xn--pple-43d.example.test:8443/documents/facture_2026.exe"
}
```

* **Statuts globaux possibles (`status`)** :
  * `CONFIRMED_THREAT` : Menace confirmée par au moins un fournisseur de réputation **ou** anomalie critique locale (adresse IP privée/loopback/métadonnées cloud, encodage d'IP obfusqué).
  * `SUSPICIOUS` : Aucune menace confirmée dans les bases, mais un ou plusieurs signaux heuristiques suspects ont été détectés sur la structure de l'URL.
  * `INCOMPLETE` : Aucun signal suspect local ni menace confirmée, mais au moins un fournisseur de réputation est indisponible ou non configuré.
  * `NO_KNOWN_THREAT` : Tous les fournisseurs actifs ont répondu `NO_KNOWN_THREAT` et aucun signal heuristique suspect n'a été relevé.

---

## 6. Ajouter un nouveau fournisseur de Threat Intelligence

Grâce au port [`ThreatIntelligenceProvider`](src/domain/ports/threat-provider.ts), l'ajout d'une nouvelle source ne nécessite aucune modification du moteur métier :

1. Créer une classe dans `src/infrastructure/providers/` implémentant `ThreatIntelligenceProvider` (`name`, `displayName`, `checkUrl(target: NormalizedUrl): Promise<ProviderResult>`).
2. Appliquer les règles de sécurité sortantes : URL d'API constante, `redirect: 'error'`, `AbortSignal.timeout(this.timeoutMs)` et capture de toutes les erreurs réseau/JSON pour retourner un `ProviderResult` avec `status: 'UNAVAILABLE'`.
3. Injecter l'instance dans le tableau `providers` de [`buildApp`](src/http/app.ts).

---

## 7. Limites connues du système

1. **Absence de visite de la page cible** : Par sécurité (prévention SSRF, tracking et exploits), LinkSentinel ne télécharge pas le contenu HTML/JS de la page. Une page de phishing hébergée sur une infrastructure légitime compromise ou un service cloud de confiance avec une URL d'apparence anodine ne sera détectée que si elle est connue des fournisseurs de réputation.
2. **Liens raccourcis non déroulés automatiquement** : Suivre les redirections d'un raccourcisseur (`bit.ly`, etc.) exposerait le serveur à des redirections vers des ressources internes (SSRF) ou validerait le clic auprès de l'attaquant (confirmation d'adresse active). LinkSentinel signale donc les raccourcisseurs en statut `SUSPICIOUS` et recommande la prudence.
3. **Délai d'indexation des menaces (*Zero-Day*)** : Les bases externes mettent parfois plusieurs minutes à plusieurs heures avant de répertorier un nouveau domaine malveillant.
4. **Restrictions d'usage des API gratuites** : Les API communautaires Google Safe Browsing (v4) et URLhaus sont strictement réservées à un usage non commercial.
