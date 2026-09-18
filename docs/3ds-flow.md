# EMV 3DS 2.x — SecurePay 3D Secure

> Références : **EMVCo 3DS Core Spec v2.3.0** (EPC-2209), EPC-2010 v1.0 (Device).

Ce module modélise le **triangle 3DS** utilisé par les banques/PSP :
**3DS Server (Requestor)** ↔ **Directory Server (réseau)** ↔ **ACS (émetteur)**.
Un mini-flux **3DS 1.0 legacy** (MPI + PARes/PAReq XML, iframe) est fourni pour
illustrer pourquoi EMV 3DS 2.x existe (UX, données device, mobile-first).

## Services

| Service | Port | Rôle réel |
|---------|------|-----------|
| `three-ds-server` | 8020 | DSL/Requestor : construit l'AReq, gère challenge CReq/CRes, propage CAVV+ECI |
| `directory-server` | 8021 | Réseau (Visa/MC) : vérifie le Requestor, route AReq→ACS, bufferise RReq |
| `acs-simulator` | 8022 | Banque émettrice : Risk-Based Auth, décide frictionless/challenge, signe le CAVV |
| `legacy-3ds1-mpi` | 8023 | MPI 3DS 1.0 (pédagogie) : PAReq/PARes XML signé, redirection iframe |

## Flux (sequence diagram)

### Frictionless (pas d'interaction utilisateur)

```
Client        Gateway          3DS Server       DS (réseau)       ACS (émetteur)
  │  POST /payments                │                 │                 │
  ├─────────────►                  │                 │                 │
  │   [tokenize → fraud score]     │                 │                 │
  │   challenge_required=false     │                 │                 │
  │                                │  AReq           │                 │
  │                                ├────────────────►│                 │
  │                                │                 │  verify 3DS Req │
  │                                │                 ├────────────────►│
  │                                │                 │  RBA score      │
  │                                │                 │  transStatus=Y  │
  │                                │  ARes (Y)       │◄────────────────┤
  │                                │◄────────────────┤                 │
  │   ──CAVV + ECI (05)──► PAYMENT►                  │                 │
  │                                │  authorize + CAVV│                │
  │    201 Created                 │                 │                 │
  │◄───────────────────────────────│                 │                 │
```

### Challenge (OSS OTP — cas PSD2 SCA > 30 € ou règle émetteur)

```
Client        Gateway          3DS Server       DS (réseau)       ACS (émetteur)
  │  POST /payments                │                 │                 │
  ├─────────────►                  │                 │                 │
  │   fraud challenge_required     │                 │                 │
  │                                │  AReq           │                 │
  │                                ├────────────────►│                 │
  │                                │                 ├────────────────►│
  │                                │                 │  transStatus=C  │
  │                                │  ARes (C+URL)   │◄────────────────┤
  │                                │◄────────────────┤                 │
  │   challenge_pending (202)      │                 │                 │
  │◄───────────────────────────────│                 │                 │
  │                                │                 │                 │
  │  POST /3ds/challenge (OTP)     │                 │                 │
  ├─────────────►                  │  CReq (OTP)     │                 │
  │                                ├────────────────►│                 │
  │                                │                 ├────────────────►│
  │                                │                 │  CRes (Y/N)     │
  │                                │                 │◄────────────────┤
  │                                │  RReq (CAVV+ECI)│                 │
  │                                ├────────────────►│                 │
  │                                │◄────────────────┤  RRes           │
  │   ──status=3ds2_authenticated──► PAYMENT         │                 │
  │                                │  authorize      │                 │
  │    201 Created                 │                 │                 │
  │◄───────────────────────────────│                 │                 │
```

## Middleware / schémas (EMVCo)

| Message | Source | Cible | Contenu clé |
|---------|--------|-------|-------------|
| AReq | 3DS Server | DS | `threeDSMethodData`, `merchant`, `transaction`, `device`, cardbrand |
| ARes | ACS (par DS) | 3DS Server | `transStatus`, `eci`, `cavv`, `acsUrl`, `acsTransId` |
| CReq/CRes | 3DS Server ↔ ACS | — | `otp_code` (lab), `challengeWindowSize` |
| RReq/RRes | DS → ACS → DS | 3DS Server | `transStatus` final, `authenticationValue` |

### transStatus (EMVCo §A.4)

| Code | Signification | ECI | Flux SecurePay |
|------|---------------|-----|----------------|
| Y | Auth OK (frictionless/challenge) | 05 | `3ds2_authenticated` |
| A | Attempts (émetteur sans 3DS) | 06 | `3ds2_A` |
| U | Auth indisponible | 07 | `3ds2_U` |
| C | Challenge requis | — | challenge → OTP → Y/N |
| N | Auth échouée | 07 | refusé avant autorisation |
| R | Rejetée par l'émetteur | 07 | refusé avant autorisation |

## Intégration dans le flux de paiement

1. `gateway:POST /api/v1/payments` — tokenize (CDE) → fraud score (SentinelPay).
2. Si `challenge_required` (fraude) **ou** règle émetteur (ACS RBA), le gateway
   appelle `three-ds-server:POST /api/v1/authenticate`.
3. `AReq` → `directory-server` → `acs-simulator` :
   - Frictionless ⇒ `transStatus=Y` + `CAVV` + `ECI`.
   - Challenge ⇒ `transStatus=C` + `acsUrl` + session.
4. Le gateway rejoue **le même AReq** (ou complète le challenge)
   `POST /api/v1/challenge/complete` avec l'OTP → `CRes` → `RReq` → `RRes`.
5. `CAVV` + `ECI` sont transmis au `payment` service via
   `three_ds_status` / `three_ds_eci` / `three_ds_cavv` (payload `/process`).

## Différences avec la tokenisation interne

- La tokenisation **SecurePay** (CDE) remplace le PAN par un `tok_` (coffre AES-256-GCM).
- Le **CAVV** est une valeur d'authentification **3DS** distincte du token ;
  il prouve au réseau que le porteur a été authentifié par l'émetteur.

## Démonstration

```bash
# 1. Monter la stack (phase app)
docker compose --profile app up -d

# 2. Authentifier (Keycloak) puis :
curl -s localhost:8000/api/v1/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 150.00, "currency":"EUR",
       "card_number":"4111111111111111","card_expiry":"12/29","card_cvv":"123"}'

# 3. Si challenge (montant élevé / BIN 555555) :
curl -s localhost:8000/api/v1/payments/pay_xxx/3ds/challenge \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"challenge_id":"3dss_...","otp_code":"123456"}'
```

## 3DS 1.0 (legacy — pourquoi 2.0 existe)

- UX : redirection **iframe**, formulaire de mot de passe de la banque, non
  responsive, pas de partage de contexte avec l'app.
- Données : pas de `deviceInfo` (SDK) → RBA "télégraphique" (montant/ipsilo).
- Taux d'abandon : historique ~ 10-20 pts de conversion en mobile.
- Protocole : `PAReq`/`PARes` en **XML signé RSA**, transport retour via POST.

Le service `legacy-3ds1-mpi` (port 8023) propose ce parcours en "démo cassée"
— voir `acs_simulated` (page HTML + POST PARes automatique).

## Mapping vers la spec EMVCo

| SecurePay | EMVCo 3DS Core Spec v2.3 |
|-----------|--------------------------|
| `protocol_version="2.3.0"` | §3DS Server Request / Message Version |
| `card` (token interne) | `threeDSRequestorAuthenticationInd` + PAN via détokenisation réseau |
| `device.device_channel` | `DeviceChannel` (02=BROWSER, 03=3DS_REQUESTOR_SDK) |
| `browser_*` | `BrowserAcceptHeader`, `BrowserUserAgent`… (§A.2.7) |
| `transStatus` | §A.4.1 |
| `eci` | §A.4.1 (`eci` = ECI 3DS du réseau) |
| `cavv` | `AuthValue` — 21 octets base64 (HMAC-SHA256 tronqué) |
| `challenge_type` (`02`) | §A.4 (`02` = Défi en 2 étapes OTP) |