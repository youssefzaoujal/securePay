# Rapport SecurePay — Session de mise au point & démonstration complète

**Date :** 8 septembre 2026
**Objet :** Démarrage du lab complet, correction de 3 bugs critiques, validation du paiement E2E (tokenisation → fraude → 3DS2 → core COBOL) et démonstration du pipeline SOC (attaque carding → Sigma → SOAR → blocage IP enforced par la gateway).
**Statut :** Stack 21/21 conteneurs UP · Tests unitaires & sécurité : 120 réussis.

---

## 1. Vue d'ensemble

SecurePay est un **laboratoire bancaire simulé** ("simulation-only") qui couvre :

| Domaine | Brique |
|---|---|
| **PSP / plateforme de paiement** | Gateway, Tokenisation (PCI), Fraud (ML), Payment, 3DS2 (EMV 3-D Secure), legacy core COBOL |
| **SOC (Security Operations)** | Moteur Sigma (règles YAML), SOAR (blocklist IP auto), TheHive (tickets), OpenCTI (enrichissement STIX), MITRE ATT&CK |
| **Observabilité** | Prometheus + Grafana + Loki + Promtail |
| **Identity** | Keycloak (OAuth2 / OIDC, JWT RS256) |
| **Chiffrement / Secrets** | Vault (AWS KMS simulé), AES-256-GCM pour le PAN |
| **Canal DAB / PFA** (profil `atm`) | KaNest-lite, ARGAUS-lite, APTRA Vision-lite, ALM-lite, MXA/VTE (ISO 8583 simulé) |
| **Kubernetes durci** (docs/conf) | Kyverno, OPA Gatekeeper, Falco, NetworkPolicies default-deny, Istio mTLS |
| **Chaos engineering** (profil `chaos`) | Toxiproxy (injection de pannes, fail-closed) |
| **SIEM alternatifs** (profils) | Wazuh (`siem`), Elastic + Kibana (`elk`), webhook receiver, Juice Shop, SonarQube |

**Le rapport couvre spécifiquement :**
1. L'environnement et le redémarrage de la plateforme
2. Les **3 bugs** identifiés et corrigés pendant la session
3. La **trace E2E complète** d'un paiement "succeed"
4. Le pipeline **SOC autonome** (attaque → détection → réponse → enforcement)
5. Les améliorations du **Command Center** (le dashboard)
6. L'état des tests et les points de vigilance

---

## 2. Environnement & prérequis

| Élément | Valeur |
|---|---|
| OS | Windows 10+ (shell : PowerShell 5.1) |
| Moteur Docker | **Server 29.4.0 / Client 29.4.0** |
| Docker Desktop | Relancé manuellement (le daemon n'était pas démarré) |
| Environnement Python | `pip install -e ".[dev]"` effectué en local |
| Répertoire | `C:\Users\zaoujal\Documents\securepay` |
| Cadre | 100 % simulation — aucune donnée carte réelle. PAN de test : `4111111111111111` |
| Profils compose | `app` (microservices), `atm`, `siem`, `elk`, `chaos` |

---

## 3. La stack — topologie des conteneurs

### 3.1 Conteneurs démarrés (21/21 UP)

| Conteneur | Rôle | Port publié (hôte → conteneur) |
|---|---|---|
| `securepay-postgres` | Base principale (payments, tokens, comptes) | `5433 → 5432` |
| `securepay-redis` | Cache + rate limiting + vélocité | `6380 → 6379` |
| `securepay-rabbitmq` | File de messages (événements) | `5672`, `15672` |
| `securepay-keycloak` | OAuth2 / OIDC — realm `securepay` | `8081 → 8080` |
| `securepay-vault` | Secrets / clés maîtres (KV) | `8200` |
| `securepay-prometheus` | Métriques | `9090` |
| `securepay-grafana` | Dashboards | `3000` |
| `securepay-nginx` | Front WAF (TLS, rate limit) | `8088 → 80` |
| `securepay-loki` | Logs centralisés | `3100` |
| `securepay-promtail` | Collecteur de logs pour Loki | — |
| `securepay-detection` | **Moteur SOC** (Sigma + SOAR + TheHive) | `8010` |
| `securepay-commandcenter` | **Dashboard "Command Center"** (FastAPI) | `9000` |
| `securepay-gateway` | API publique FastAPI (JWT, BOLA, correlation-id) | `8000` |
| `securepay-payment` | Service paiement / capture | `8001` |
| `securepay-tokenization` | Coffre PAN AES-256-GCM | `8002` |
| `securepay-fraud` | Scoring fraude (vélocité + Isolation Forest) | `8003` |
| `securepay-legacy-core` | Mainframe simulé — **GnuCOBOL** `VALIDATE`, wrapper mTLS | `8004` (TLS) |
| `securepay-three-ds-server` | 3DS2 Server (authentification = "bank simulateur") | `8020` |
| `securepay-directory-server` | Répertoire 3DS2 (DS) | `8021` |
| `securepay-acs-simulator` | ACS (Access Control Server) | `8022` |
| `securepay-legacy-3ds1` | Simulateur 3DS1 (fallback) | `8023` |

> Services optionnels définis dans le compose (non démarrés dans cette session) :
> `atm-adapter` (8016, profil `atm`), `toxiproxy` (8474/13800, profil `chaos`), `wazuh` (1514/1515/55000, profil `siem`), `es` (9200) + `kibana` (5601) + `filebeat` (profil `elk`), `webhook-receiver` (8015), `juiceshop` (3001), `sonarqube` (9002).

### 3.2 Chaîne d'appel d'un paiement

```
Client HTTPS
  → NGINX (8088) [TLS 1.3, WAF, rate-limit]
    → Gateway FastAPI (8000)  [JWT JWKS Keycloak · BOLA · middleware SOAR+rate-limit]
      → Tokenization (8002)   [AES-256-GCM, CVV détruit, ne renvoie pas le PAN]
      → Fraud (8003)          [vélocité carding + Isolation Forest → score/risk_level]
      → three-ds-server (8020) → directory-server (8021) → acs-simulator (8022)
        (et legacy-3ds1 (8023) en fallback)
      → Payment (8001)        [capture simulée · webhook HMAC-SHA256]
        → Adapter mTLS → legacy-core (8004) GnuCOBOL VALIDATE (solde compte marchand)
  → Toute la chaîne écrit des événements JSONL → detection (8010) → Sigma → SOAR
```

### 3.3 Santé des services (mesure depuis `/api/health`, Command Center)

| Service | État | Latence |
|---|---|---|
| keycloak | ✅ 200 | 118 ms |
| gateway | ✅ 200 | 132 ms |
| payment | ✅ 200 | 113 ms |
| tokenization | ✅ 200 | 105 ms |
| fraud | ✅ 200 | 96 ms |
| three-ds-server | ✅ 200 | 88 ms |
| directory-server | ✅ 200 | 75 ms |
| acs-simulator | ✅ 200 | 59 ms |
| detection | ✅ 200 | 46 ms |
| legacy-core | ✅ 200 | 49 ms |

**Résultat : 10/10 services en ligne.**

---

## 4. Mise en route de Docker

### 4.1 Le problème

Au départ, toute la stack était arrêtée. `docker info` échouait :

```
error during connect: failed to connect to the docker API at
npipe:////./pipe/dockerDesktopLinuxEngine  ...
```

Le daemon Docker Desktop n'était **pas démarré**.

### 4.2 La solution

```powershell
Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
```

Puis attente du moteur (boucle de 3 min, poll toutes les 5 s) jusqu'à :

```
Server: Docker Engine 29.4.0  (OK)
```

### 4.3 Démarrage de la stack

```powershell
docker compose up -d                    # plan data + SOC + observabilité + vault
docker compose --profile app up -d      # microservices (gateway, payment, …)
```

Sortie : **21 conteneurs** `Started` / `Running`, dont postgres `(healthy)`, redis `(healthy)`, legacy-core `(healthy)`, gateway `(healthy)`.

---

## 5. Bugs corrigés (3 bugs réels, documentés)

### 5.1 Bug n°1 — `credentials.claims` incompatible (HTTP 500 sur tout paiement)

**Symptôme :** `POST /api/v1/payments` → HTTP `500`.

**Cause racine :** dans `shared/auth.py` (ligne ~137) :

```python
credentials.claims = result  # ValueError: "HTTPAuthorizationCredentials" object has no field "claims"
```

L'image Docker embarque une version de **FastAPI/Starlette plus ancienne** que le Python local (0.136). L'objet `HTTPAuthorizationCredentials` de l'image n'accepte pas d'attribut `claims`.

**Impact :** la gateway, mais **aussi** la tokenisation, le payment et le fraud (tous les services qui valident le JWT) rencontraient la même erreur → **aucun paiement possible**.

**Correction :** envelopper l'assignation dans un try/except silencieux (aucun appelant ne lit ce champ — 1 seule occurrence) :

```python
try:
    credentials.claims = result
except (AttributeError, ValueError):
    pass
```

**Diffusion :** reconstruction des 4 images :
```powershell
docker compose up -d --build gateway tokenization payment fraud
```

### 5.2 Bug n°2 — URLs internes 3DS sans chemin (`/api/v1/ds`, `/api/v1/acs`) → 404 en cascade

**Symptôme :** après le fix du bug n°1, `POST /api/v1/payments` renvoyait un 404 **triple imbriqué** :

```json
{"detail": {"detail": {"detail": "Not Found"}}}
```

**Diagnostic (par sondes directes des backends) :**

| Backend sondé | Résultat |
|---|---|
| `tokenization` (8002) / tokenize | HTTP **201** ✅ |
| `fraud` (8003) / check | HTTP **200** ✅ |
| `three-ds-server` (8020) / `api/v1/authenticate` | HTTP **404** ❌ |

**Cause racine :** dans `docker-compose.yml`, les constantes `DS_URL` et `ACS_URL` étaient **sans préfixe de chemin** :

```yaml
DS_URL: http://directory-server:8021        # ← manquait /api/v1/ds
ACS_URL: http://acs-simulator:8022           # ← manquait /api/v1/acs
```

Or le code construit les appels en concaténant le chemin :
```python
f"{DS_URL}/authenticate"   # et f"{ACS_URL}/authenticate", f"{ACS_URL}/challenge"
```
→ les requêtes partaient sur `/authenticate` au lieu de `/api/v1/ds/authenticate` et `/api/v1/acs/authenticate`.

**Correction :** aligner le compose sur les constantes du code (la source de vérité est le code) :

```yaml
# dans three-ds-server ET directory-server
DS_URL: http://directory-server:8021/api/v1/ds
ACS_URL: http://acs-simulator:8022/api/v1/acs
```

**Recréation :** `three-ds-server` et `directory-server` recréés. Succès.

### 5.3 Bug n°3 — Dashboard : bouton "Obtenir un token merchant" cassé

**Symptôme :** clic sur "Obtenir un token merchant" → erreur JS :

```
SyntaxError: Unexpected token 'I', "Internal S"... is not valid JSON
```

**Explication du symptôme :** le JavaScript attendait du JSON mais recevait du **texte brut** `"Internal Server Error..."` (erreur 500 FastAPI). La première lettre `I` de "Internal" n'est pas un JSON valide.

**Cause racine :** le conteneur `commandcenter` lisait la variable **`KEYCLOAK_PUBLIC_URL`** (`dashboard.py`, ligne 25) :

```python
KEYCLOAK = os.getenv("KEYCLOAK_PUBLIC_URL", "http://localhost:8081")
```

mais `docker-compose.yml` ne définissait que **`KEYCLOAK_URL`**. Dans le conteneur, le défaut `/localhost:8081/` était utilisé → Keycloak introuvable → connexion refusée → 500 texte brut.

**Corrections (2 niveaux) :**

1. **Root cause** — ajouter la variable attendue au service `commandcenter` :
   ```yaml
   KEYCLOAK_PUBLIC_URL: http://keycloak:8080
   ```

2. **Robustesse** — durcir `/api/test/oauth` pour qu'il **réponde toujours en JSON** (aucun crash UI possible) :
   - si le statut Keycloak ≥ 400 → `{"ok": false, "status": …, "detail": …}`
   - si exception réseau → `{"ok": false, "detail": "<Exception>: <msg>"}`
   - le JS gère désormais `d.ok === false` et affiche une ligne d'erreur propre.

### 5.4 Incidents annexes

- **Conflit de noms de conteneurs** lors des reconstructions (conteneurs orphelins, suffixe `_securepay-payment` / `_securepay-commandcenter`). Résolution :
  ```powershell
  docker rm -f securepay-payment; docker rm -f <id-orphelin>
  docker compose up -d ... # recréation propre
  ```

---

## 6. Paiement E2E validé (trace complète)

### 6.1 Requête

```
POST http://localhost:8000/api/v1/payments
```

### 6.2 Réponse (HTTP 201 — succeeded)

```
status            = succeeded
payment_id        = pay_9fd97ee4a1ab4ce7
correlation_id    = corr_3e74e3821a9a
idempotent_replay = false

tokenization:
  token        = tok_32108e…
  cvv_stored   = false          → conformité PCI Req 3.2 (CVV accepté puis détruit)
  algo         = AES-256-GCM

fraud:
  score            = 0.0
  recommendation   = approve

three_ds:
  status        = 3ds2_authenticated
  trans_status  = Y
  eci           = 05            → Authentification réussie Carte présente
  cavv          = <présent>     → cryptogramme
  method        = (challenge si review)

legacy_core_decision = approved   → GnuCOBOL : solde marchand suffisant (compte MERCHANTAP)
```

### 6.3 Trace SOC correspondante (logs/securepay-events.jsonl)

Les 6 derniers événements, dans l'ordre de la chaîne :

| # | event_type | status |
|---|---|---|
| 1 | three_ds | routed |
| 2 | three_ds | ok |
| 3 | three_ds | ok |
| 4 | legacy_core_decision | approved |
| 5 | payment_attempt | succeeded |
| 6 | … | correlation_id: `corr_3e74e3821a9a` |

C'est la preuve de la **traçabilité PCI Req 10** : chaque étape de la transaction produit un événement horodaté (JSONL), ingérable par le SOC.

---

## 7. Démonstration SOC — Attaque Carding → Sigma → SOAR → Gateway 403

C'est le **cœur de la démo "zero trust"** : le blocage est **automatique** et **appliqué en production** (pas un simple dashboard).

### 7.1 Maillon 1 — La règle Sigma (`detection/sigma/rules/card_testing_attack.yml`)

```yaml
title:       SecurePay - Card Testing Attack Detected
id:          8a3b1c2d-4e5f-6a7b-8c9d-0e1f2a3b4c5d
level:       critical
tags:        attack.carding · attack.t1657 · severity.critical
detection:
  selection_event:   event_type == payment_attempt
  selection_failure: status == failed
  condition:         selection_event and selection_failure
  timeframe: 5m
  count: 10          # ≤ 10 échecs en 5 min depuis la même source
output:
  mitre_attack: [TA0040 → T1657 Financial Theft]
```

### 7.2 Maillon 2 — Le SOAR (`detection/soar/responder.py`)

- `should_auto_block()` : blocage automatique si `severity ∈ {critical, high}` **ou** si le signal appartient à `{card_testing, carding, bola, jwt_replay, credential_stuffing, injection_probe, sql_injection}`.
- `auto_respond()` : écrit l'IP dans la **blocklist** (`block_ip`, TTL **3600 s = 1 h**) puis émet l'événement `soar_ip_block`.

### 7.3 Maillon 3 — Enforcement gateway (`gateway/middleware.py`)

À **chaque requête** entrante (avant le routage) :

```python
ip = forwarded or client_ip
if is_blocked(ip):
    emit_event({"event_type": "soar_block_enforced", ...})
    return JSONResponse({"detail": "IP bloquée par réponse automatique SOAR"}, status_code=403)
```

### 7.4 Déroulement réel de la session

**État initial** (baseline propre) :

```
BLOCKLIST (avant) : aucune IP bloquée
ALERTES    (avant) : aucune alerte
```

**Attaque** — 25 vraies requêtes vers la gateway, cartes aléatoires, **une seule IP** (`10.96.187.147`), via header `X-Forwarded-For` :

```powershell
python -m detection.simulator.attack_generator --scenario carding --attempts 25 --target http://localhost:8000
```

Sortie :

```
[CARDING] Démarrage: 25 tentatives depuis IP aléatoire
  [10/25] failed=10 success=0
  [20/25] failed=20 success=0
[CARDING] Terminé: 25 échecs, 0 succès
```

**Traces écrites** : `detection/simulator/logs/events_20260908.jsonl` — **26 lignes** (25 tentatives + 1 `carding_summary`), ex. :

```json
{"event_type":"payment_attempt","scenario":"card_testing","source_ip":"10.96.187.147",
 "card_token":"tok_8910c099376641fa","amount":536.02,"currency":"EUR",
 "merchant_id":"MERCH_001","status":"failed","http_status":401,
 "attempt_number":2,"timestamp":"2026-09-08T09:43:24.217733+00:00",
 "source":"securepay-attack-simulator"}
```

> `http_status: 401` : les tentatives échouent faute de JWT → c'est exactement le pattern "carding" (beaucoup de cartes, tout échoue, une seule IP).

**Évaluation Sigma** :

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8010/evaluate
```

Sortie (extraits) :

```
alertes_éveillées = 106   total = 106

[critical] SecurePay - Card Testing Attack Detected  rule=8a3b1c2d-…  ip=10.96.187.147  T1657   ← notre IP
[critical] SecurePay - Card Testing Attack Detected  rule=8a3b1c2d-…  ip=10.96.187.147  T1657

BLOCK ip=10.96.187.147  reason=SecurePay - Card Testing Attack Detected
```

> **Détail important :** `/evaluate` ré-ingère **tout l'historique JSONL** (jours précédents) → 106 alertes au total, comprenant aussi des runs antérieurs (credential stuffing, BOLA, SQLi, fraud spike) — normal et attendu.

**Blocage SOAR enregistré** :

```
/soar/blocks → BLOCK ip=10.96.187.147  reason=SecurePay - Card Testing Attack Detected  (TTL 1h)
```

**Preuve finale — enforcement réel sur la gateway :**

```powershell
curl.exe -H "X-Forwarded-For: 10.96.187.147" http://localhost:8000/health
```

```
{"detail":"IP bloquée par réponse automatique SOAR"}
HTTP 403
```

**Contrôle négatif** (IP innocente) :

```powershell
curl.exe -H "X-Forwarded-For: 198.51.100.5" http://localhost:8000/health
```

```
{"status":"healthy","service":"SecurePay",...}
HTTP 200
```

### 7.5 Synthèse du flux (à montrer en entretien)

```
25 essais de carte (même IP)          attack_generator.py
        │  X-Forwarded-For: 10.96.187.147 → gateway → 401 (pas de JWT)
        ▼
events_20260908.jsonl (26 l.)
        │  POST /evaluate (8010)
        ▼
SigmaEngine  →  règle 8a3b1c2d (email payment_attempt + failed, count≥10/5min)
        │  alerte CRITICAL · MITRE T1657 · ip=10.96.187.147
        ▼
SOAR responder  →  block_ip(ttl=1h)   +  événement soar_ip_block
        │
        ▼  blocklist (fichier JSONL partagé)
        │
Gateway middleware (is_blocked)  →  403 "IP bloquée par réponse automatique SOAR"
        ▼
Contrôle : IP innocente → 200 healthy ✔
```

---

## 8. Command Center — améliorations apportées (dashboard port 9000)

Au-delà du bug n°3 (section 5.3), l'interface a été rendue plus vivante et robuste :

| Amélioration | Détail |
|---|---|
| **Barre de statut "LIVE"** | En-tête temp réel : `LIVE n/10` + chaque service avec pastille verte/rouge et latence en ms, rafraîchi toutes les **5 s** via `GET /api/health` |
| **Flux d'événements live** | Onglet SOC : carte "Flux d'événements live" = tail de `logs/securepay-events.jsonl` (6 derniers), rafraîchi toutes les **4 s** via `GET /api/soc/feed`, coloré par statut |
| **OAuth robuste** | `/api/test/oauth` renvoie un JSON même en erreur ; le bouton "Obtenir un token merchant" affiche une erreur propre au lieu de crasher |
| **Probe santé Keycloak** | utilise `/realms/securepay` (200) au lieu de `/health/ready` (404 sur cette image) |

Endpoint santé ajouté (`dashboard.py`) :

```python
HEALTH_PROBES = [("keycloak", …, "/realms/securepay"),
                 ("gateway", …, "/health"), … (10 services)]
@app.get("/api/health")
async def api_health():
    # httpx.AsyncClient concurrent (asyncio.gather), timeout 2 s,
    # vérification mTLS spécifique pour legacy-core
    return {"services": [...], "up": n, "total": 10}
```

Résultat mesuré après redéploiement :

```
UP: 10/10   keycloak OK 118ms · gateway OK 132ms · payment OK 113ms
           tokenization OK 105ms · fraud OK 96ms · three-ds OK 88ms
           directory-server OK 75ms · acs OK 59ms · detection OK 46ms · legacy-core OK 49ms
```

---

## 9. Tests & qualité

```powershell
pytest tests/unit tests/security
```

**Résultat : 120 tests réussis.** (Couverture : BOLA, fail-secure, Sigma, SOAR, tokenisation, Idempotency/ledger, legacy core, network token, gRPC, ATM KaNest, qualité des règles Sigma, etc.)

Vérification syntaxique du dashboard avant reconstruction :

```powershell
python -m py_compile dashboard.py   # → OK
```

---

## 10. Points de vigilance

| Sujet | État | Détail |
|---|---|---|
| **Docker Desktop** | ⚠️ | Le daemon doit être lancé manuellement (`Start-Process '...\Docker Desktop.exe'`) avant toute session. La stack peut être arrêtée entre deux sessions → relancer `docker compose up -d` + `--profile app up -d`. |
| **Conflit de dépendances pip** | ⚠️ | `pip install -e ".[dev]"` a monté opentelemetry **1.44.0** alors que `opentelemetry-exporter-otlp-proto-grpc` reste en **1.41.0** (contrainte `==1.41.0`) → warning de conflit (non bloquant). À aligner si usage du traçage OTLP/gRPC. |
| **Conflits de noms Docker** | ⚠️ | Compose recrée parfois des conteneurs orphelins (suffixe `_<id>_…`). Si "name already in use", faire `docker rm -f <conteneur>` puis `docker compose up -d`. |
| **`/evaluate` ré-ingère l'historique** | ℹ️ | Il rejoue tout le JSONL → le compteur d'alertes peut être élevé (106) ; utiliser les alertes les plus récentes (filtre IP) pour la démo. |
| **Port physique de Keycloak** | ℹ️ | à l'intérieur du réseau compose : `http://keycloak:8080` ; sur l'hôte : `http://localhost:8081`. Ne jamais croiser les deux (bug n°3). |

---

## 11. Prochaines étapes du guide pas-à-pas

| Étape | Contenu | Commandes clés |
|---|---|---|
| **Étape 5** ✅ | Carding → Sigma → SOAR → 403 | attesté ci-dessus |
| **Étape 6** | Chaos engineering (fail-closed) | `docker compose --profile chaos up -d` · `powershell -File scripts/inject_chaos.ps1 FraudDown` → rejouer un paiement → **5xx, jamais approve** → `RecoverAll` |
| **Étape 7** | Modules Phase 2/3 sans Docker | `python -m scripts.hsm_demo` · `python -m compliance.assess --json` · `python -m kafka_events.consumer_probe` · `python -m scripts.reconcile_ledger` |
| **Étape 8** | K8s durci (confs) | kyverno, opa, falco, vault injector, istio — docs + chart Helm |

---

## 12. Annexe — références des fichiers clés

| Fichier | Rôle |
|---|---|
| `docker-compose.yml` | Définition de la stack (data plane + SOC + obs + Vault + profils) — corrigé : `DS_URL`/`ACS_URL` avec chemins, `KEYCLOAK_PUBLIC_URL` |
| `shared/auth.py` (≈ ligne 137) | Validation JWT — corrigé : compat `credentials.claims` |
| `dashboard.py` | Command Center — corrigé : OAuth JSON-robuste + endpoints `/api/health`, `/api/soc/feed` + UI live |
| `gateway/middleware.py` | Enforcement SOAR (403) + rate limiting Redis |
| `gateway/routes.py` | Flux `create_payment` (tokenize → fraud → 3DS → payment → legacy) validé E2E |
| `detection/engine/main.py` | API SOC : `/evaluate`, `/alerts`, `/soar/blocks`, `/coverage`, `/mitre/navigator` |
| `detection/sigma/rules/card_testing_attack.yml` | Règle carding (T1657, critical, count≥10/5min) |
| `detection/soar/responder.py` | Réponse automatique (blocklist TTL 1h) |
| `detection/soar/blocklist.py` | Persistance/lecture de la blocklist |
| `detection/simulator/attack_generator.py` | Simulateur d'attaques (carding, credential stuffing, BOLA, fraud spike) |
| `detection/pipeline.py` | Post-alerte : SOAR + TheHive + enrichissement STIX + layer ATT&CK |
| `logs/securepay-events.jsonl` | Trace SOC PCI Req 10 (source du flux live) |
| `detection/simulator/logs/events_*.jsonl` | Traces d'attaques simulées (source de `/evaluate`) |
```

---

## 13. Checklist — Projet SecurePay

Organisée comme le repo lui-même : socle commun, puis les **3 briefs** (passerelle paiement, lab SOC, plateforme K8s), puis le transverse risque/conformité et la prépa entretien/soutenance. À cocher au fil de l'eau — sert de recette technique *et* de fiche de révision.

### 0. Socle commun

- [ ] Bus d'événements JSONL partagé actif entre les 3 briefs (`logs/securepay-events.jsonl`)
- [ ] `merchant_id` toujours dérivé du JWT, jamais du body (cf. scénario spoofing du threat model)
- [ ] Cloisonnement des données respecté : PAN nulle part hors coffre tokenization (payment = `tok_`, legacy-core = `account_id` seul, logs SOC rédigés)
- [ ] AuthN OAuth2 Client Credentials (Keycloak) + JWKS RS256 opérationnelle sur tous les services
- [ ] Anti-replay `jti` actif (cache mémoire lab / Redis prod)
- [ ] Dashboard admin protégé OIDC + MFA
- [ ] Chaque profil `docker compose` démarre proprement : défaut, `app`, `atm`, `purple`, `siem`/`elk`, + stack Kafka dédiée (`infra/kafka/docker-compose.kafka.yml`)
- [ ] Command Center (`localhost:9000`) affiche bien les cartes de chaque brief (SOC, Core COBOL, DAB/PFA…)

### Brief 1 — Passerelle de paiement

#### 1.1 Flux de paiement & 3DS
- [ ] Paiement bout-en-bout testé : tokenize → fraud score → (3DS si besoin) → capture
- [ ] Frictionless : `transStatus=Y`, CAVV + ECI `05` bien propagés au service payment
- [ ] Challenge : `C` → OTP → `CReq/CRes` → `RReq/RRes` → `Y`/`N`
- [ ] Les 6 `transStatus` gérés (Y, A, U, C, N, R) avec le bon mapping SecurePay
- [ ] Démo 3DS 1.0 legacy (`legacy-3ds1-mpi`, port 8023) conservée pour l'argumentaire UX/mobile-first
- [ ] Mapping vers EMVCo 3DS Core Spec v2.3 à jour

#### 1.2 Banking stack avancé (10 modules)
- [ ] Kafka : producteur/consommateur + repli JSONL + pont automatique testés
- [ ] gRPC interne : `InternalService` route vers la vraie logique (fraud/payment/ledger), pas un doublon REST
- [ ] Vault : creds DB dynamiques (TTL 15 min) + certs mTLS PKI émis/révoqués correctement
- [ ] Zero Trust mesh (Istio) : `PeerAuthentication STRICT` + `AuthorizationPolicy` default-deny par identité SPIFFE
- [ ] ISO 20022 : `pacs.008` / `pacs.002` / `camt.053` générés et reparsés (round-trip) sans perte
- [ ] Network Tokenization : provision / authenticate / deactivate + idempotence de la provision vérifiées
- [ ] HSM simulé : clé non-extractible, `sign_data` fonctionnel, fallback logiciel assumé et su expliquer
- [ ] Open Banking/PSD2 : parcours consentement AISP/PISP jusqu'au paiement initié
- [ ] Observabilité : `correlation_id`/`traceparent` propagés de bout en bout
- [ ] Compliance as Code : `assess.py` + règles Rego produisent un rapport exploitable
- [ ] Suite de tests unitaires des 10 modules verte

#### 1.3 Canal DAB / ATM-PFA
- [ ] Translateur ISO 8583 0200/0210 validé
- [ ] Profils constructeurs NCR / Diebold / WNX / DN chargés
- [ ] 5 scénarios KaNest-lite (retrait/dépôt V/NV/LSB) passent
- [ ] PV de recette HTML généré (`logs/pv-recette-dab.html`)
- [ ] Cycle ALM-lite NEW→CLOSED visible dans l'onglet DAB du Command Center
- [ ] ARGAUS + APTRA Vision lite + journaux MXA/VTE fonctionnels
- [ ] Hors-scope assumé et explicite (licences réelles, switch certifié CB/Visa, hardware GAB)

#### 1.4 Core banking legacy (COBOL)
- [ ] Binaire GnuCOBOL compilé + wrapper FastAPI opérationnels
- [ ] Isolation confirmée : le wrapper n'a pas de `DATABASE_URL`
- [ ] Anti-injection vérifié : regex `account_id`, montant borné, pas de `shell=True`
- [ ] Rate-limit 30 req/min actif
- [ ] mTLS payment → legacy-core fonctionnel (CA lab + cert client)
- [ ] NetworkPolicy : seul `payment` peut joindre le pod legacy-core
- [ ] Démo reproductible : 100 € APPROVED / 600 000 € DECLINED

#### 1.5 Front Office — Portail marchand (nouveau)
- [ ] Nouveau service `front-office/` (BFF) qui appelle payment/fraud/tokenization via le backbone gRPC existant — jamais le PAN
- [ ] Auth réutilisée : OIDC Keycloak rôle `merchant`, scoping `merchant_id` du JWT, mêmes garde-fous BOLA que le reste du repo
- [ ] Dashboard : volumétrie, taux d'approbation, taux de fraude, répartition frictionless/challenge 3DS
- [ ] Liste + détail transaction (recherche/filtre date, statut, montant) — jamais de PAN en clair, juste `tok_`/last4
- [ ] Remboursement partiel/total — nouvel endpoint `POST /payments/{id}/refund` à créer côté `payment`
- [ ] Statements exportables : réutiliser `camt.053` (déjà généré côté ISO 20022) plutôt que réinventer un export
- [ ] Gestion API keys / webhook (URL + secret HMAC) en self-service
- [ ] Tests BOLA dédiés : un merchant ne voit/n'édite jamais les données d'un autre sur ce nouveau service

#### 1.6 Back Office — Support / Réconciliation (nouveau)
- [ ] Nouveau service `back-office/` (ou extension du Command Center existant — à trancher) pour le staff interne
- [ ] Rôle dédié au-delà de l'`admin` générique (ex. `support_agent`, `ops_reconciliation`), permissions fines type BFLA (API5 OWASP)
- [ ] Recherche cross-merchant : chaque accès loggé dans `audit_logs` avec motif, pas juste un log technique
- [ ] File de revue fraude manuelle : transactions en statut `review` → approuver/rejeter depuis l'UI
- [ ] Workflow dispute/chargeback (reçu → instruction → gagné/perdu) avec pièces jointes
- [ ] Écran de réconciliation : ledger (Kafka/JSONL) vs `legacy-core` (COBOL) vs relevé PSP — contrepartie opérationnelle de la règle Sigma `ledger_reconciliation_breakdown` déjà écrite
- [ ] Onboarding/KYC marchand : validation, activation/suspension de compte
- [ ] Visualiseur `audit_logs` (déjà en base) exposé en lecture

#### 1.7 Sécurité des nouvelles surfaces
- [ ] Front office : reste hors CDE, aucun PAN ne transite même masqué — mettre à jour le tableau des plans de données (`architecture.md`)
- [ ] Back office : MFA obligatoire (politique déjà en place) + step-up auth sur les actions sensibles (chargeback, statut marchand)
- [ ] Nouvelle règle Sigma à envisager : accès admin à N marchands distincts en peu de temps (compte compromis/scraping), sur le modèle de `credential_stuffing`/`rate_limit_abuse`
- [ ] STRIDE rejoué pour ces 2 services, en particulier Elevation of Privilege et Information Disclosure (nouvelle surface à fort privilège)
- [ ] NetworkPolicy : back-office ne parle qu'aux services internes nécessaires, jamais en direct à `legacy-core`

### Brief 2 — Lab SOC

#### 2.1 Detection engineering & ADS
- [ ] Moteur Sigma-lite charge les 11 règles sans erreur, mapping MITRE à jour
- [ ] Chaque règle a sa fiche ADS complète (Goal, Catégorisation, Strategy, Technical Context, Blind Spots, False Positives, Validation, Priority)
- [ ] CI `test_sigma_rule_quality.py` verte : zéro silence sur corpus malveillant, zéro FP critical/high sur corpus bénin
- [ ] Endpoints répondent : `/evaluate`, `/coverage`, `/alerts`, `/hive/cases`, `/intel`, `/mitre/navigator`

#### 2.2 Attack lab & purple team
- [ ] Les 4 scénarios (credential stuffing, BOLA, card testing, JWT replay) rejoués : chacun déclenche la bonne défense (429, 403, vélocité fraude, cache `jti` 401) **et** finit bloqué côté SOAR (`/soar/blocks`, TTL 1h, déblocage testé)
- [ ] Rapport purple-team à jour : gap initial + fix documentés pour les 6 techniques (y compris T1190 SQLi préventif et T1059 Falco)
- [ ] Layer ATT&CK Navigator exporté et importable
- [ ] (Optionnel) Juice Shop monté (`profile purple`) pour l'angle « WAF vs app métier »

#### 2.3 SOC-as-Code
- [ ] Chaîne complète : alerte Sigma → blocage SOAR → case TheHive (JSONL) → enrichissement STIX/OpenCTI → layer Navigator auto
- [ ] Bundle STIX 2.1 importable dans un vrai OpenCTI
- [ ] Procédure de branchement d'un vrai TheHive documentée (coût RAM/Elasticsearch assumé)

### Brief 3 — Plateforme K8s

#### 3.1 Admission & runtime
- [ ] Kyverno : no-root, no-privileged, limits, no `:latest`, gate image-scan actifs
- [ ] OPA Gatekeeper en miroir de la même posture
- [ ] Falco : règles runtime déclenchent (shell, egress, fichiers secrets, binaires, miner, Keycloak)

#### 3.2 Réseau / secrets / IaC
- [ ] NetworkPolicy default-deny appliqué au namespace
- [ ] Vault k8s (injector) fonctionnel
- [ ] Lab k3s + Terraform cloud + Helm chart cohérents entre eux

#### 3.3 CSPM
- [ ] Les 3 modes (`fixture`, `terraform`, `aws`) exécutés au moins une fois
- [ ] Rapport HTML/JSON généré et lisible
- [ ] Les 7 contrôles CIS couverts (1.4, 1.16, 2.1.1, 2.1.4, 2.2.1, 3.1, 5.2)

#### 3.4 Supply chain (SLSA/Sigstore)
- [ ] Provenance signée générée sur un tag `v*`
- [ ] SBOM (Syft/Trivy CycloneDX) produit en CI
- [ ] Image signée Cosign (keyless OIDC) + attestation SBOM
- [ ] Vérification Kyverno en mode Audit sur les images signées
- [ ] Écart lab ↔ SLSA Build L3 réel (hosted builder, Rekor public) su et explicable

### Transverse — Risque & conformité

- [ ] STRIDE complet : 6 catégories, menace/impact/contrôle renseignés pour chacune
- [ ] Les 6 scénarios d'attaque du threat model testés, résultat attendu confirmé
- [ ] EBIOS RM : ateliers 1/2/5 renseignés, **risques résiduels assumés** (HTTP en lab, Vault dev, secrets Keycloak en `.env`, TheHive non déployé par défaut)
- [ ] OWASP API Top 10 : 10/10 mappés à un contrôle + un test réel
- [ ] `security-controls.md` : les 7 catégories mappées PCI-DSS, avec MFA (Req 8.4.2) et revue de logs auto (Req 10.4.1.1) mises en avant comme réponses aux exigences v4.0.1
- [ ] Matrice ISO 27001 Annexe A renseignée, `pci_audit.py` exécuté et lu

### Preuves & présentation

- [ ] `python -m scripts.security_metrics` relancé récemment — chiffres datés, aucune valeur inventée
- [ ] Chiffres clés en tête : recall fraude, FPR, precision/F1, MTTD, latence SOAR, couverture ATT&CK
- [ ] Historique des métriques versionné pour montrer une tendance dans le temps
- [ ] Une démo end-to-end chronométrée (paiement → 3DS → fraude → détection → SOAR) prête à montrer
- [ ] Écart lab/prod assumé et articulable pour chaque brique (Vault `-dev`, HSM logiciel, pas de TLS sur `:8088`, TheHive non déployé…)
- [ ] Vocabulaire métier maîtrisé et redéfinissable simplement : CAVV, ECI, ISO 8583, ISO 20022, SPIFFE, BOLA, MTTD…

### Commandes de vérification rapide

```bash
# Stack applicative
docker compose --profile app up -d --build

# Tests unitaires (échantillon large)
python -m pytest tests/unit -q

# SOC
curl -X POST http://localhost:8010/evaluate
curl http://localhost:8010/coverage

# Preuves / conformité
python -m scripts.security_metrics
python scripts/pci_audit.py
python -m cspm --mode fixture

# DAB / PFA
python -m pytest tests/unit/test_atm_kanest.py -q
```