# SecurePay — Banking Stack (Phase 2 / Phase 3)

> Tous les modules de cette page sont **implémentés dans le repo** et couverts par
> des tests. C'est le vocabulaire "banque/PSP" : event streaming, gRPC interne,
> secrets dynamiques, identity mesh, ISO 20022, network tokens, HSM, PSD2.

---

## 1. Kafka — event streaming des paiements

`kafka_events/` fournit un **producteur + consommateur asynchrone** (aiokafka).

- `KafkaEventBus.bootstrap_servers` (env `KAFKA_BOOTSTRAP_SERVERS`). Vide → repli
  JSONL automatique (le lab tourne sans broker, la CI aussi).
- `emit_event()` a la **même signature** que `shared.events.emit_event` : un service
  peut publier sur Kafka en changeant une variable d'env, sans toucher au code.
- Sérialisation : JSON structuré **sans PAN** (`shared.redaction`), timestamp,
  `correlation_id`, champ carte rédigé (req 10 PCI).
- **Pont automatique** (`kafka_events/bridge.py`) : depuis le commit "Kafka bridge",
  `shared.events.emit_event` pousse le même événement vers Kafka **et** l'archive
  JSONL dès que `KAFKA_BOOTSTRAP_SERVERS` est renseigné — aucun service n'a à
  changer. Le pont tourne sur un thread daemon (loop dédiée), ne bloque jamais le
  chemin de paiement, et retombe sur le JSONL si le broker est down.

```python
from kafka_events.producer import KafkaEventBus

bus = KafkaEventBus()               # lit KAFKA_BOOTSTRAP_SERVERS
await bus.send({"event_type": "capture", "status": "succeeded", "amount": 99.50})
```

Usage démo :
```powershell
docker compose -f infra/kafka/docker-compose.kafka.yml up -d
python -m kafka_events.consumer_probe --seconds 5   # écoute le topic events
```

Pourquoi Kafka et pas (seulement) RabbitMQ : **parcours de paiement = flux
append-only réutilisable** (ledger, fraude temps réel, réconciliation, relecture
pour audit). RabbitMQ reste pour le RPC/worker ; Kafka devient la **source de
vérité événementielle**.

---

## 2. gRPC — backbone interne à faible latence

`grpc_svc/` : protos + implémentation interne (`InternalService`) + client.

- Contrat : `protos/internal.proto` (`PaymentService.ProcessCapture`,
  `FraudService.EvaluateRisk`). Le PAN n'existe jamais dans ces messages.
- `InternalService.dispatch("Method", request)` route vers les **mêmes moteurs que
  le REST** (fraud.engine, payment.routes, ledger) : le backbone gRPC est branché
  sur la vraie logique, pas un doublon.
- `InProcessChannel` / `run_server` : exécution sans socket pour les tests et une
  démo "assemble me" ; le client gRPC réel passe par `grpc_svc.client.InternalClient`
  quand `USE_GRPC=true`.
- REST reste la surface exposée (marchands, iframe, SDK) ; gRPC est interne.

Raison industrielle : les passerelles paiement à fort débit (gateway → risk →
capture) utilisent gRPC/Protobuf pour la **latence et le typage strict** des
messages internes, et gardent REST pour le monde externe.

---

## 3. HashiCorp Vault — secrets dynamiques

`vault_integration/client.py` :

- `get_db_credentials(role)` : **PostgreSQL dynamic credentials** — username/password
  jetables (TTL 15 min), rotés automatiquement, révoqués à expiration (jamais en dur).
- `issue_pki_cert("fraud.svc")` : certificat mTLS interne (PKI secrets engine) pour
  l'identité de service.
- `DevVaultClient` : implémentation mémoire-test qui **reproduit exactement les
  contrats** (creds uniques par créneau, lease revocation, cert X.509 valide).

Provisionnement : `python -m scripts.configure_vault` (active database + pki,
crée CA racine et rôles). `python -m scripts.configure_vault --dev` vérifie les
contrats sans Vault.

En prod : `VAULT_TOKEN` jamais committé ; Vault lui-même au backend Raft/HA, clé de
déchiffrement hors-ligne (unseal distribué). Même si le lab est un Vault dev en
container, le **contrat dynamique** (creds courtes + PKI) est celui des équipes
paiement.

---

## 4. Zero Trust — wire identity (Istio + SPIFFE/SPIRE)

`infra/istio/mesh-security.yaml` :

- `PeerAuthentication` **STRICT** : tout trafic sans mTLS est refusé.
- `AuthorizationPolicy` **default-deny** + règles par **identité SPIFFE**
  (`spiffe://cluster.local/ns/securepay/sa/<sa>`) : gateway→payment,
  gateway→fraud, payment→legacy-core. Aucune règle par IP.
- `Gateway`/`VirtualService` en tête : ingress HTTPS TLS 1.3, credential mis par
  Vault PKI.

SPIRE : le mesh consomme des **Workload Identities SPIFFE** exactement comme les
émetteurs de certificats SPIRE que les architectures bancaires modernes déploient.
En lab, Istio fournit déjà l'identité SPIFFE ; SPIRE (registration + workload API)
est la même brique côté "registre d'identités". Mappage :

| Concept | En place |
|---|---|
| Workload identity | SPIFFE ID `spiffe://cluster.local/ns/<ns>/sa/<sa>` |
| Certificate distribution | Istiod CA |
| Registration/autorisation | ISTIO_MESHCONFIG + AuthorizationPolicy |
| Vrai CA de lab | Vault PKI (section 3) |

---

## 5. ISO 20022

`iso20022/` — messages XML conformes au schéma (construction + parsing) :

- `pacs.008` (CreditTransfer) — virement initié
- `pacs.002` (PaymentStatusReport)
- `camt.053` (BankToCustomerStatement)

Utilisés par la démo "virement" et par le pipeline fraude/test. S'appuie sur
`namespace` ISO réel (`urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08`).
C'est là qu'on parle de **DBTR/Crédit de virement** : SWIFT migre vers ce
standard — le mentionner et savoir en lire/écrire un message est un signal fort.

```python
msg = PACS008(...).build()       # ElementTree → XML
parsed = PACS008(msg).load()     # round-trip contrôlé
```

---

## 6. Network Tokenization (type VTS / MDES)

`network_token/` — cycle de vie d'un **token réseau** (différent de la tokenisation
PAN interne) :

- `POST /api/v1/tokens/provision` : PAN → token réseau (`ntk_…`), lié au **domaine**
  (marchand/rappeur) — un token doit être utilisé dans le contexte qui l'a émis.
- `POST /api/v1/tokens/authenticate` : usage du token (= crypto du porte-monnaie).
- `POST/DELETE /api/v1/tokens/{id}/deactivate` : cycle de vie complet.
- Idempotence : provision répété retourne la même `token_reference`.

Différence clé à raconter : la tokenisation **interne** retient le PAN hors de la
payment service ; la **tokenization réseau** (Visa VTS / Mastercard MDES) donne un
**jeton d'usage** au porteur — substituable sur le réseau, protégé par cryptogram,
non-dérivable vers le PAN. C'est le cœur des paiements mobiles/click-to-pay.

---

## 7. HSM simulé (SoftHSM/PKCS#11)

`hsm/` — contrat HSM :

- `HSM.provision()` une clé **non-extractible** (CKA_EXTRACTABLE=0) dans un slot.
- `HSM.sign_data(cavv, ...)` / `HSM.generate_kek()` : la matière cryptographique
  **reste dans le HSM** ; le process app ne voit que des handles.
- Backend réel : `python-pkcs11` + SoftHSM2 (bibliothèque `.so`).
- Backend fallback : `SoftwareHSM` (mémoire, mêmes garanties d'API, marque "lab").

C'est le fondement CAVV/ACI de la section 3DS : dans une banque, l'authentication
value est produite **dans** le HSM. Ici, `hsm/` expose ce chemin et `acs_simulator`
y est raccordé optionnellement via `HSM_URL`.

```powershell
python -m pytest tests/unit/test_hsm.py -q
python -m scripts.hsm_demo             # provision + sign sur SoftHSM (si dispo) sinon fallback
```

---

## 8. Open Banking / PSD2

`openbanking/` — le flow de **consentement OAuth2** (authorization code) :

- Rôles : **AISP** (consulter comptes) et **PISP** (initier un paiement).
- `POST /api/v1/consents` (solution) → `GET /api/v1/authorize?consent_id=` (API
  banque simulée) → callback `redirect_uri` → `POST /api/v1/consents/{id}/token`.
- `POST /api/v1/payment-initiation` : l'ordre de paiement exige un **consent actif**
  liste blanche (SCA pour PISP).

Contexte réglementaire : PSD2 (RTS 2018/389) impose SCA et des API de tiers
(AISP/PISP). Avoir un bout de "consent management" démontre l'immersion dans le
paysage réglementaire EU — pas seulement du REST.

---

## 9. Observabilité distribuée (Otel) — déjà en place

`shared/tracing.py` : spans contextvar, `traceparent` propagé par le gateway,
export OTLP optionnel + fallback JSONL. Raccorder l'export au collector OTel
(`OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318`) pour une stack complète
(Tempo → traces distribuées par `correlation_id`).

Chaos Mesh : `infra/chaos-mesh/` (PodChaos kill + NetworkChaos latency) — complète
Toxiproxy pour la résilience pod-level, documenté avec les tests fail-closed.

---

## 10. Compliance as Code (OPA + OSCAL)

`compliance/` :

- `compliance/controls.yaml` — inventaire des contrôles PCI-DSS v4.0.1 mappés aux
  artefacts du repo.
- `compliance/assess.py` — évalue chaque control (présence réelle de l'artefact,
  tests verts) et produit un rapport **OSCAL-like** (`assessment_results`).
- `compliance/rego/pci.rego` — règles au format OPA (évaluables avec `opa eval`
  quand dispo ; miroir en Python pour la CI). 

Objectif : la conformité **s'exécute**, le programme d'assurance répond à la
question "où sont vos preuves ?" avec un job CI qui produit le rapport.

---

## Annexes : démonstrations rapides

```powershell
python -m pytest tests/unit/test_grpc_svc.py tests/unit/test_kafka_events.py tests/unit/test_vault_integration.py -q
python -m pytest tests/unit/test_network_token.py tests/unit/test_hsm.py tests/unit/test_openbanking.py tests/unit/test_iso20022.py tests/unit/test_compliance.py -q

python -m scripts.configure_vault --dev
```