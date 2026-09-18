"""SecurePay Command Center — PSP lab + SOC + plateforme Kubernetes."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from detection.engine.sigma_engine import SigmaEngine
from detection.pipeline import handle_alerts
from detection.soar.blocklist import list_blocks
from fraud.engine import FraudEngine
from tokenization.crypto import decrypt_token, encrypt_card

app = FastAPI(title="SecurePay Command Center")
ENGINE = SigmaEngine("detection/sigma/rules")
FRAUD = FraudEngine()
LOG_DIR = Path("./detection/simulator/logs")
EVENT_LOG = Path(os.getenv("SECUREPAY_EVENT_LOG", "logs/securepay-events.jsonl"))
KEYCLOAK = os.getenv("KEYCLOAK_PUBLIC_URL", "http://localhost:8081")
DETECTION_URL = os.getenv("DETECTION_URL", "http://localhost:8010")

HEALTH_PROBES = [
    ("keycloak", os.getenv("KEYCLOAK_PUBLIC_URL", "http://keycloak:8080"), "/realms/securepay"),
    ("gateway", os.getenv("GATEWAY_URL", "http://gateway:8000"), "/health"),
    ("payment", "http://payment:8001", "/health"),
    ("tokenization", "http://tokenization:8002", "/health"),
    ("fraud", "http://fraud:8003", "/health"),
    ("three-ds-server", "http://three-ds-server:8020", "/health"),
    ("directory-server", "http://directory-server:8021", "/health"),
    ("acs-simulator", "http://acs-simulator:8022", "/health"),
    ("detection", DETECTION_URL, "/health"),
    ("legacy-core", "https://legacy-core:8004", "/health"),
]

HTML = r"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>SecurePay Command Center</title>
  <style>
    :root { --bg:#071015; --surface:#0d1b20; --surface-raised:#12252b; --line:#234047; --ok:#57e3b3; --warn:#f5bd62; --bad:#ff7085; --muted:#8ba5a9; --txt:#edf7f5; --accent:#79b8ff; --cyan:#5dd8df; }
    * { box-sizing:border-box; margin:0; padding:0; }
    body { min-height:100vh; font-family: Georgia, 'Times New Roman', serif; background:radial-gradient(circle at 92% 0%, #12323a 0, transparent 34%), var(--bg); color:var(--txt); }
    button, code, .log, .feed, .flow, table, .statusline { font-family: 'Cascadia Code', Consolas, monospace; }
    .top { padding:28px clamp(18px, 5vw, 68px) 24px; border-bottom:1px solid var(--line); display:flex; justify-content:space-between; gap:28px; align-items:flex-end; flex-wrap:wrap; }
    .top-kicker { color:var(--cyan); font:11px 'Cascadia Code', Consolas, monospace; letter-spacing:.22em; text-transform:uppercase; margin-bottom:10px; }
    .top h1 { font-size:clamp(26px, 4vw, 42px); line-height:1; letter-spacing:-.03em; font-weight:500; }
    .top p { color:var(--muted); margin-top:10px; font-size:14px; }
    .top-meta { display:flex; align-items:center; gap:10px; color:var(--muted); font:11px 'Cascadia Code', Consolas, monospace; margin-top:12px; }
    .top-meta strong { color:var(--ok); font-weight:600; }
    .banner { background:#2b1d1b; color:#ffd0a1; border:1px solid #795044; padding:11px 14px; border-radius:4px; font:11px/1.45 'Cascadia Code', Consolas, monospace; max-width:390px; }
    .banner::before { content:'●'; color:var(--warn); margin-right:8px; }
    nav { display:flex; gap:6px; padding:12px clamp(18px, 5vw, 68px); border-bottom:1px solid var(--line); overflow-x:auto; scrollbar-width:thin; }
    nav button { flex:0 0 auto; background:transparent; color:var(--muted); border:1px solid transparent; padding:10px 13px; border-radius:3px; cursor:pointer; font-size:11px; letter-spacing:.03em; transition:background .2s, color .2s, border-color .2s; }
    nav button:hover { color:var(--txt); background:var(--surface); }
    nav button.active { color:var(--bg); background:var(--ok); border-color:var(--ok); font-weight:700; }
    main { padding:24px clamp(18px, 5vw, 68px) 56px; max-width:1440px; margin:0 auto; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:14px; }
    .card { background:linear-gradient(145deg, rgba(18,37,43,.98), rgba(10,25,30,.98)); border:1px solid var(--line); border-radius:4px; padding:18px; box-shadow:0 10px 30px rgba(0,0,0,.12); transition:transform .2s, border-color .2s; }
    .card:hover { transform:translateY(-2px); border-color:#3a6870; }
    .card h2 { font-size:15px; color:var(--ok); margin-bottom:10px; font-weight:500; letter-spacing:.01em; }
    .muted { color:var(--muted); font-size:12px; margin-bottom:10px; line-height:1.45; }
    button.act { background:#12332f; color:var(--ok); border:1px solid #4aaf91; padding:9px 12px; border-radius:3px; cursor:pointer; margin:0 6px 6px 0; font-size:11px; transition:filter .2s, transform .2s; }
    button.act:hover { filter:brightness(1.2); transform:translateY(-1px); }
    button.danger { background:#351b22; color:var(--bad); border-color:var(--bad); }
    button.warn { background:#342916; color:var(--warn); border-color:var(--warn); }
    .log { background:#071216; border:1px solid #1c363c; border-radius:3px; padding:11px; min-height:76px; max-height:220px; overflow:auto; font:11px/1.6 'Cascadia Code', Consolas, monospace; white-space:pre-wrap; margin-top:10px; }
    .ok { color:var(--ok); } .err { color:var(--bad); } .info { color:#8ea0ff; } .wn { color:var(--warn); }
    .kpis { display:grid; grid-template-columns:repeat(5, minmax(130px, 1fr)); gap:8px; margin:14px 0 22px; }
    .kpi { background:var(--surface); border:1px solid var(--line); padding:13px 14px; border-radius:3px; font:10px 'Cascadia Code', Consolas, monospace; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; }
    .kpi b { display:block; font:500 21px Georgia, 'Times New Roman', serif; color:var(--txt); margin-bottom:5px; text-transform:none; letter-spacing:0; }
    .overview { display:grid; grid-template-columns:minmax(0, 1.65fr) minmax(280px, 1fr); gap:14px; margin:0 0 22px; }
    .command-card { position:relative; overflow:hidden; background:linear-gradient(115deg, #123a3b 0%, #10262e 54%, #16253c 100%); border:1px solid #397b7d; border-radius:4px; padding:24px; }
    .command-card::after { content:''; position:absolute; width:260px; height:260px; right:-100px; top:-130px; border:1px solid rgba(93,216,223,.32); border-radius:50%; box-shadow:0 0 0 24px rgba(93,216,223,.06), 0 0 0 48px rgba(93,216,223,.035); }
    .eyebrow { color:var(--cyan); font:10px 'Cascadia Code', Consolas, monospace; letter-spacing:.18em; text-transform:uppercase; }
    .command-card h2 { max-width:650px; margin:12px 0 8px; color:var(--txt); font:500 clamp(24px, 3vw, 34px)/1.05 Georgia, 'Times New Roman', serif; }
    .command-card p { max-width:650px; color:#b4d2d0; font-size:13px; line-height:1.5; }
    .command-actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:18px; }
    .signal { color:var(--ok); font:11px 'Cascadia Code', Consolas, monospace; float:right; }
    .signal-dot { display:inline-block; width:7px; height:7px; margin-right:6px; border-radius:50%; background:var(--ok); box-shadow:0 0 12px var(--ok); animation:pulse 1.5s infinite; }
    .signal-bar { height:4px; max-width:650px; margin-top:22px; overflow:hidden; background:#16363b; border-radius:4px; }
    .signal-bar i { display:block; width:38%; height:100%; background:linear-gradient(90deg, transparent, var(--cyan), var(--ok), transparent); animation:scan 2.8s ease-in-out infinite; }
    .posture-card { background:var(--surface); border:1px solid var(--line); border-radius:4px; padding:20px; }
    .posture-card h2 { margin:10px 0 18px; font-size:17px; font-weight:500; }
    .posture-item { display:flex; justify-content:space-between; gap:12px; padding:10px 0; border-top:1px solid var(--line); color:var(--muted); font:11px 'Cascadia Code', Consolas, monospace; }
    .posture-item strong { color:var(--ok); font-weight:600; }
    .mitre { display:grid; grid-template-columns:repeat(auto-fill,minmax(170px,1fr)); gap:8px; }
    .tech { border:1px solid var(--line); padding:10px; border-radius:3px; background:var(--surface); font-size:12px; }
    .tech code { color:var(--accent); }
    table { width:100%; border-collapse:collapse; font-size:12px; }
    th, td { text-align:left; padding:8px; border-bottom:1px solid var(--line); }
    .flow { font:12px/1.6 'Cascadia Code', Consolas, monospace; background:#071216; padding:14px; border-radius:3px; border:1px solid var(--line); overflow:auto; }
    .statusline { display:flex; flex-wrap:wrap; gap:10px 14px; align-items:center; margin:0 0 4px; padding:11px 14px; background:var(--surface); border:1px solid var(--line); border-radius:3px; font-size:11px; }
    .statusline .live { color:var(--ok); font-weight:bold; letter-spacing:.14em; animation:pulse 1.8s infinite; }
    .svc { color:var(--muted); }
    .svc b { color:var(--txt); font-weight:600; }
    .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:5px; vertical-align:baseline; }
    .dot.up { background:var(--ok); box-shadow:0 0 6px var(--ok); }
    .dot.down { background:var(--bad); box-shadow:0 0 6px var(--bad); }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.35} }
    @keyframes scan { 0%{transform:translateX(-120%)} 55%,100%{transform:translateX(290%)} }
    .health-meta { margin-left:auto; color:var(--muted); font-size:10px; }
    .feed { font:11px/1.6 'Cascadia Code', Consolas, monospace; background:#071216; border:1px solid #1c363c; border-radius:3px; padding:10px; min-height:80px; max-height:220px; overflow:auto; white-space:pre-wrap; margin-top:10px; }
    @media (max-width:800px) { .overview { grid-template-columns:1fr; } .kpis { grid-template-columns:repeat(2, 1fr); } .health-meta { width:100%; margin-left:0; } }
    @media (max-width:480px) { .top { padding-top:22px; } .kpis { grid-template-columns:1fr 1fr; } .kpi b { font-size:18px; } }
  </style>
</head>
<body>
  <header class="top">
    <div>
      <div class="top-kicker">SecurePay / Operations Lab</div>
      <h1>SECUREPAY COMMAND CENTER</h1>
      <p>PSP simulé · SOC Sigma/MITRE · plateforme Kubernetes durcie</p>
      <div class="top-meta"><strong>ENV LAB</strong><span>•</span><span>Observabilité active</span></div>
    </div>
    <div class="banner">SIMULATION — aucune donnée carte réelle. PAN de test uniquement (ex. 4111111111111111).</div>
  </header>
  <nav>
    <button class="active" aria-current="page" data-tab="ops">Paiement</button>
    <button data-tab="soc">SOC / Detection</button>
    <button data-tab="dab">DAB / PFA</button>
    <button data-tab="platform">Plateforme K8s</button>
    <button data-tab="arch">Architecture</button>
  </nav>
  <main>
    <div class="statusline" id="svcHealth">Scan des services…</div>
    <div class="kpis">
      <div class="kpi"><b id="kRules">—</b>règles Sigma</div>
      <div class="kpi"><b id="kAlerts">—</b>alertes</div>
      <div class="kpi"><b>AES-256-GCM</b>coffre PAN</div>
      <div class="kpi"><b>BOLA deny</b>object-level auth</div>
      <div class="kpi"><b>NCR·DN·WNX</b>profils DAB lab</div>
    </div>
    <section class="overview" aria-label="Synthèse opérationnelle">
      <div class="command-card">
        <span class="eyebrow">Mission control <span class="signal"><i class="signal-dot"></i>signal nominal</span></span>
        <h2>La confiance se pilote en temps réel.</h2>
        <p>Orchestrez un paiement, observez le risque, puis déclenchez une réponse SOC depuis la même surface.</p>
        <div class="command-actions">
          <button class="act" onclick="openSoc()">Ouvrir la mission SOC</button>
          <button class="act warn" onclick="fraud(7500)">Simuler un risque</button>
        </div>
        <div class="signal-bar"><i></i></div>
      </div>
      <div class="posture-card">
        <span class="eyebrow">Security posture</span>
        <h2>Garde-fous actifs</h2>
        <div class="posture-item"><span>Card data boundary</span><strong>ENFORCED</strong></div>
        <div class="posture-item"><span>Object-level auth</span><strong>BOLA DENY</strong></div>
        <div class="posture-item"><span>Event observability</span><strong>LIVE</strong></div>
      </div>
    </section>

    <section id="ops">
      <div class="grid">
        <div class="card">
          <h2>OAuth2 Client Credentials</h2>
          <p class="muted">Keycloak realm <code>securepay</code> — JWT RS256, TTL court, anti-replay jti.</p>
          <button class="act" onclick="oauth()">Obtenir un token merchant</button>
          <div class="log" id="logOauth">En attente…</div>
        </div>
        <div class="card">
          <h2>Tokenisation PCI</h2>
          <p class="muted">PAN chiffré AES-256-GCM. CVV accepté puis détruit (Req 3.2). Le payment service ne voit jamais le PAN.</p>
          <button class="act" onclick="crypto()">Chiffrer / déchiffrer 4111…1111</button>
          <div class="log" id="logCrypto">En attente…</div>
        </div>
        <div class="card">
          <h2>Fraude + 3DS2</h2>
          <p class="muted">Vélocité (carding) + Isolation Forest + challenge SCA si review.</p>
          <button class="act" onclick="fraud(40)">40 EUR</button>
          <button class="act warn" onclick="fraud(7500)">7 500 EUR</button>
          <button class="act danger" onclick="fraud(15000)">15 000 EUR</button>
          <div class="log" id="logFraud">En attente…</div>
        </div>
        <div class="card">
          <h2>Webhooks HMAC</h2>
          <p class="muted">Chaque paiement succeeded est signé <code>t=,v1=</code> (HMAC-SHA256), fenêtre 5 min.</p>
          <button class="act" onclick="hmac()">Vérifier une signature</button>
          <div class="log" id="logHmac">En attente…</div>
        </div>
        <div class="card">
          <h2>Core COBOL (mainframe sim)</h2>
          <p class="muted">GnuCOBOL valide le solde du compte marchand (500 000 EUR fictifs). Wrapper mTLS + argv sanitizé — jamais <code>shell=True</code>.</p>
          <button class="act" onclick="cobol(100)">100 EUR</button>
          <button class="act danger" onclick="cobol(600000)">600 000 EUR</button>
          <div class="log" id="logCobol">En attente…</div>
        </div>
      </div>
    </section>

    <section id="soc" hidden>
      <div class="grid">
        <div class="card">
          <h2>Card testing (T1657)</h2>
          <p class="muted">25 PAN différents, même IP — pattern carding réel industrie.</p>
          <button class="act danger" onclick="attack('carding')">Lancer</button>
          <div class="log" id="logCarding"></div>
        </div>
        <div class="card">
          <h2>Credential stuffing (T1110.004)</h2>
          <button class="act danger" onclick="attack('credential_stuffing')">Lancer</button>
          <div class="log" id="logCredStuff"></div>
        </div>
        <div class="card">
          <h2>BOLA / IDOR (T1213)</h2>
          <p class="muted">Lecture cross-merchant. L'API refuse, le SOC alerte.</p>
          <button class="act danger" onclick="attack('bola')">Lancer</button>
          <div class="log" id="logBola"></div>
        </div>
        <div class="card">
          <h2>JWT replay + SQLi + fraude</h2>
          <button class="act danger" onclick="attack('jwt_replay')">Replay JWT</button>
          <button class="act danger" onclick="attack('sqli')">Probe SQLi</button>
          <button class="act danger" onclick="attack('fraud_spike')">Fraud spike</button>
          <div class="log" id="logMisc"></div>
        </div>
      </div>
      <div class="card" style="margin-top:14px;">
        <h2>Moteur Sigma</h2>
        <p class="muted">Évalue les JSONL (paiements + simulateur) contre <code>detection/sigma/rules/</code>.</p>
        <button class="act" onclick="evaluate()">Évaluer maintenant</button>
        <div class="log" id="logSigma" style="max-height:280px;"></div>
      </div>
      <div class="card" style="margin-top:14px;">
        <h2>SOAR — blocage IP auto</h2>
        <p class="muted">Alerte critique → IP dans la blocklist (TTL 1h) → gateway 403. Zero Trust enforce.</p>
        <div class="log" id="logSoar"></div>
      </div>
      <div class="card" style="margin-top:14px;">
        <h2>TheHive — tickets d'incident</h2>
        <p class="muted">Chaque alerte Sigma ouvre un case (JSONL lab, API TheHive si THEHIVE_URL). Enrichissement STIX 2.1 type OpenCTI.</p>
        <div class="log" id="logHive"></div>
      </div>
      <div class="card" style="margin-top:14px;">
        <h2>Couverture MITRE ATT&amp;CK</h2>
        <div class="mitre" id="mitre"></div>
      </div>
      <div class="card" style="margin-top:14px;">
        <h2>Flux d'événements live</h2>
        <p class="muted">Tail de <code>logs/securepay-events.jsonl</code> — trace PCI Req 10 (paiements, 3DS, décisions).</p>
        <div class="feed" id="logFeed">En attente…</div>
      </div>
    </section>

    <section id="dab" hidden>
      <div class="grid">
        <div class="card">
          <h2>KaNest-lite — recettes E2E</h2>
          <p class="muted">Retrait, dépôt valorisé / non valorisé, LSB. Simulateur maison — pas la licence Galitt. PAN de test uniquement.</p>
          <button class="act" onclick="kanest()">Lancer les 5 recettes</button>
          <a class="act" href="/api/atm/pv" target="_blank" style="display:inline-block;text-decoration:none;">Ouvrir le PV HTML</a>
          <div class="log" id="logKanest">En attente…</div>
        </div>
        <div class="card">
          <h2>ARGAUS-lite — parc automates</h2>
          <p class="muted">Supervision ONLINE / OFFLINE / MAINTENANCE (NCR Paris, Diebold Lyon, WNX Lille, DN Marseille).</p>
          <button class="act" onclick="argaus()">Rafraîchir la flotte</button>
          <button class="act warn" onclick="argausMaint()">Lille → MAINTENANCE</button>
          <div class="log" id="logArgaus">En attente…</div>
        </div>
        <div class="card">
          <h2>APTRA Vision-lite</h2>
          <p class="muted">Reporting technique × financier par DAB + réconciliation ledger.</p>
          <button class="act" onclick="aptra()">Générer le rapport</button>
          <div class="log" id="logAptra">En attente…</div>
        </div>
        <div class="card">
          <h2>MXA / VTE — journaux</h2>
          <p class="muted">MXA = technique automate. VTE = avis financiers. PAN masqué.</p>
          <button class="act" onclick="journals('mxa')">Logs MXA</button>
          <button class="act" onclick="journals('vte')">Logs VTE</button>
          <div class="log" id="logJournals">En attente…</div>
        </div>
        <div class="card">
          <h2>HP ALM-lite — anomalies</h2>
          <p class="muted">Workflow NEW → IN_PROGRESS → FIXED → CLOSED. Un FAIL KaNest crée un ticket.</p>
          <button class="act" onclick="alm()">Lister les défauts</button>
          <div class="log" id="logAlm">En attente…</div>
        </div>
      </div>
    </section>

    <section id="platform" hidden>
      <div class="card">
        <h2>Admission + runtime + secrets + réseau</h2>
        <table>
          <tr><th>Contrôle</th><th>Outil</th><th>Effet</th></tr>
          <tr><td>Pas de root / pas de privileged</td><td>Kyverno + OPA Gatekeeper</td><td>Enforce</td></tr>
          <tr><td>Limits CPU/RAM obligatoires</td><td>Kyverno</td><td>Enforce</td></tr>
          <tr><td>Image scan gate Trivy</td><td>Kyverno annotation + CI</td><td>Enforce HIGH/CRITICAL</td></tr>
          <tr><td>Pas de tag :latest</td><td>Kyverno</td><td>Enforce</td></tr>
          <tr><td>Shell dans un pod</td><td>Falco T1059</td><td>Alerte CRITICAL</td></tr>
          <tr><td>Default-deny NetworkPolicy</td><td>Kubernetes</td><td>CDE isolé</td></tr>
          <tr><td>VAULT_MASTER_KEY</td><td>Vault Agent Injector</td><td>Jamais en ConfigMap</td></tr>
          <tr><td>CSPM CIS AWS</td><td>python -m cspm</td><td>S3 public, SG 0.0.0.0/0, IAM admin</td></tr>
          <tr><td>SIEM</td><td>Loki (défaut) / Elastic profile elk / Wazuh siem</td><td>logs JSONL</td></tr>
          <tr><td>SOAR</td><td>blocklist IP</td><td>403 automatique</td></tr>
          <tr><td>TheHive / Cortex</td><td>connector JSONL + API optionnelle</td><td>tickets d'incident</td></tr>
          <tr><td>OpenCTI (STIX 2.1)</td><td>detection/intel/stix_bundle.json</td><td>enrichissement alertes</td></tr>
          <tr><td>Supply chain</td><td>Syft SBOM + Cosign + SLSA lab</td><td>signature images</td></tr>
          <tr><td>Core COBOL</td><td>GnuCOBOL + mTLS + NetPol payment-only</td><td>APPROVED / DECLINED</td></tr>
          <tr><td>Canal DAB / PFA</td><td>KaNest / ARGAUS / APTRA / ALM / MXA / VTE <em>lite</em></td><td>ISO 8583 lab, pas de licence constructeur</td></tr>
        </table>
      </div>
    </section>

    <section id="arch" hidden>
      <pre class="flow">Internet
  → NGINX (WAF / rate-limit / TLS 1.3)
    → Keycloak (OAuth2 client_credentials, OIDC admin)
      → Gateway FastAPI (JWT JWKS, BOLA, correlation-id)
        → Tokenization  [AES-256-GCM vault, NO CVV]
        → Fraud         [velocity + Isolation Forest → 3DS2]
        → Payment       [capture simulée, webhook HMAC]
          → Adapter mTLS → GnuCOBOL VALIDATE (solde compte)
      → Canal DAB : KaNest-lite --ISO 8583--> atm-adapter --fraude+COBOL--> 0210
      → MXA (technique) / VTE (avis) / ARGAUS / APTRA / ALM + PV
      → JSONL events ──► Sigma engine ──► MITRE / runbooks
      → Prometheus / Grafana
K8s: Kyverno + OPA + Falco + Vault + default-deny
      </pre>
    </section>
  </main>
<script>
const $ = id => document.getElementById(id);
function line(id, msg, cls='info'){ const el=$(id); el.innerHTML += '<span class="'+cls+'">'+msg+'</span>\\n'; el.scrollTop = el.scrollHeight; }
function activateTab(tab){
  const selected = document.querySelector('nav button[data-tab="'+tab+'"]');
  if(selected) selected.click();
}
function openSoc(){ activateTab('soc'); evaluate(); }
document.querySelectorAll('nav button').forEach(btn => btn.onclick = () => {
  document.querySelectorAll('nav button').forEach(b => { b.classList.remove('active'); b.removeAttribute('aria-current'); });
  btn.classList.add('active');
  btn.setAttribute('aria-current', 'page');
  ['ops','soc','dab','platform','arch'].forEach(t => $(t).hidden = t !== btn.dataset.tab);
});
async function oauth(){
  $('logOauth').innerHTML='';
  try {
    const r = await fetch('/api/test/oauth'); const d = await r.json();
    if(d.ok===false){ line('logOauth','erreur '+(d.status||'')+' — '+d.detail,'err'); return; }
    line('logOauth','token_type='+d.token_type+' expires_in='+d.expires_in,'ok');
    line('logOauth', (d.access_token||JSON.stringify(d)).slice(0,80)+'…','info');
  } catch(e){ line('logOauth', String(e), 'err'); }
}
async function crypto(){
  $('logCrypto').innerHTML='';
  const d = await (await fetch('/api/test/crypto')).json();
  line('logCrypto','algo='+d.algorithm+' cvv_stored='+d.cvv_stored,'ok');
  line('logCrypto','PAN chiffré='+d.encrypted_pan.slice(0,48)+'…','info');
  line('logCrypto','roundtrip='+d.decrypted_pan+'  PAN visible dans ciphertext='+d.pan_visible, d.pan_visible?'err':'ok');
}
async function fraud(amount){
  $('logFraud').innerHTML='';
  const d = await (await fetch('/api/test/fraud?amount='+amount)).json();
  line('logFraud', amount+' EUR → score '+d.risk_score+' '+d.risk_level+' → '+d.recommendation+(d.challenge_required?' (3DS)':''), d.risk_score>0.3?'wn':'ok');
  if(d.flags && d.flags.length) line('logFraud','flags: '+d.flags.join(' | '),'wn');
}
async function hmac(){
  $('logHmac').innerHTML='';
  const d = await (await fetch('/api/test/hmac')).json();
  line('logHmac','header='+d.header,'ok');
  line('logHmac','verify_ok='+d.verify_ok,'ok');
}
async function cobol(amount){
  $('logCobol').innerHTML='';
  const d = await (await fetch('/api/test/cobol?amount='+amount)).json();
  const ok = d.status==='APPROVED';
  line('logCobol', amount+' EUR → '+d.status+'  account='+(d.account||'')+'  via='+(d.via||''), ok?'ok':'err');
  if(d.detail) line('logCobol', d.detail, 'wn');
}
async function kanest(){
  $('logKanest').innerHTML='';
  try {
    const d = await (await fetch('/api/atm/kanest',{method:'POST'})).json();
    line('logKanest','exécuté='+d.executed+' PASS='+d.passed+' FAIL='+d.failed+'  PV='+(d.pv_path||''), d.failed?'err':'ok');
    (d.results||[]).forEach(r => line('logKanest', r.id+' ['+r.vendor+'] attendu='+r.expected_rc+' obtenu='+r.actual_rc+' → '+r.status, r.status==='PASS'?'ok':'err'));
  } catch(e){ line('logKanest', String(e), 'err'); }
}
async function argaus(){
  $('logArgaus').innerHTML='';
  const d = await (await fetch('/api/atm/fleet')).json();
  (d||[]).forEach(a => line('logArgaus', a.id+'  '+a.vendor+'  '+a.city+'  '+a.status, a.status==='ONLINE'?'ok':'wn'));
}
async function argausMaint(){
  $('logArgaus').innerHTML='';
  await fetch('/api/atm/fleet/DAB_LILLE_03/status?status=MAINTENANCE&reason=cassette',{method:'POST'});
  await argaus();
}
async function aptra(){
  $('logAptra').innerHTML='';
  const d = await (await fetch('/api/atm/aptra')).json();
  line('logAptra','source='+d.source+'  ledger.balanced='+((d.ledger||{}).balanced), 'ok');
  (d.atms||[]).forEach(a => line('logAptra', (a.atm_id||a.id)+'  tx='+ (a.tx||0)+'  approved='+(a.approved||0)+'  amount='+(a.amount||0)+' EUR','info'));
}
async function journals(kind){
  $('logJournals').innerHTML='';
  const d = await (await fetch('/api/atm/journals/'+kind)).json();
  line('logJournals', kind.toUpperCase()+'  '+d.length+' lignes', 'ok');
  d.slice(-8).forEach(e => line('logJournals', JSON.stringify(e), 'info'));
}
async function alm(){
  $('logAlm').innerHTML='';
  const d = await (await fetch('/api/atm/defects')).json();
  if(!d.length){ line('logAlm','Aucun défaut — les FAIL KaNest créent un ticket ALM.','ok'); return; }
  d.forEach(t => line('logAlm', t.id+'  '+t.status+'  '+t.priority+'  '+t.title, t.status==='CLOSED'?'ok':'wn'));
}
async function attack(s){
  const map={carding:'logCarding',credential_stuffing:'logCredStuff',bola:'logBola',jwt_replay:'logMisc',sqli:'logMisc',fraud_spike:'logMisc'};
  const id=map[s]||'logMisc'; $(id).innerHTML='';
  const d = await (await fetch('/api/attack/'+s)).json();
  line(id, d.events_created+' events  ip='+d.attacker_ip,'ok');
}
async function evaluate(){
  $('logSigma').innerHTML='';
  if($('logSoar')) $('logSoar').innerHTML='';
  const d = await (await fetch('/api/soc/evaluate',{method:'POST'})).json();
  line('logSigma','fired='+d.alerts_fired+' total='+d.alerts_total,'ok');
  (d.alerts||[]).slice(-12).forEach(a => line('logSigma', '['+a.severity+'] '+a.title+'  '+(a.mitre||[]).join(',')+'  ip='+(a.source_ip||''),'wn'));
  (d.soar_blocks||[]).forEach(b => line('logSoar', 'BLOCK '+b.ip+'  '+b.reason, 'err'));
  if($('logHive')){
    $('logHive').innerHTML='';
    (d.hive_cases||[]).slice(-8).forEach(c => line('logHive', (c.id||'')+'  '+c.severity+'  '+c.title+'  ip='+(c.source_ip||''),'wn'));
    const intel=(d.intel||[]).find(i => (i.opencti_matches||[]).length);
    if(intel) line('logHive','OpenCTI matches: '+intel.opencti_matches.join(', '),'ok');
  }
}
async function health(){
  try {
    const d = await (await fetch('/api/health')).json();
    const box = $('svcHealth'); if(!box) return;
    box.innerHTML = '<span class="live">LIVE '+d.up+'/'+d.total+'</span>' + (d.services||[]).map(s =>
      '<span class="svc"><i class="dot '+(s.up?'up':'down')+'"></i>'+s.name+' '+(s.ms!=null?'<b>'+s.ms+'ms</b>':'<b>down</b>')+'</span>').join('') +
      '<span class="health-meta">mis a jour a '+new Date().toLocaleTimeString('fr-FR')+'</span>';
  } catch(e){}
}
async function feed(){
  try {
    const d = await (await fetch('/api/soc/feed?limit=6')).json();
    const box = $('logFeed'); if(!box || box.dataset.busy==='1') return;
    box.dataset.busy='1';
    box.innerHTML='';
    (d.events||[]).slice().reverse().forEach(e => {
      const s = e.status||'';
      const cls = ['succeeded','ok','approved'].includes(s)?'ok':(['failed','blocked','declined','error'].includes(s)?'err':'info');
      line('logFeed', '['+(e.timestamp||'').slice(11,19)+'] '+e.event_type+'  '+s+'  '+(e.correlation_id||''), cls);
    });
    delete box.dataset.busy;
  } catch(e){}
}
async function boot(){
  try {
    const c = await (await fetch('/api/soc/coverage')).json();
    $('kRules').textContent = c.rules || '—';
    const box = $('mitre'); box.innerHTML='';
    Object.values(c.techniques||{}).forEach(t => {
      const el=document.createElement('div'); el.className='tech';
      el.innerHTML = '<code>'+(t.technique_id||'')+'</code><br>'+(t.name||'')+'<br><span class="muted">'+(t.tactic||'')+'</span>';
      box.appendChild(el);
    });
    const a = await (await fetch('/api/soc/evaluate',{method:'POST'})).json();
    $('kAlerts').textContent = a.alerts_total ?? 0;
  } catch(e) {}
}
boot();
health(); feed();
setInterval(health, 5000);
setInterval(feed, 4000);
</script>
</body></html>
"""


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML


@app.get("/api/test/oauth")
async def api_oauth():
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(
                f"{KEYCLOAK}/realms/securepay/protocol/openid-connect/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "merchant-api",
                    "client_secret": "CHANGE_ME_IN_PRODUCTION",
                },
            )
        if response.status_code >= 400:
            return {"ok": False, "status": response.status_code, "detail": response.text[:200]}
        return {"ok": True, **response.json()}
    except Exception as exc:
        return {"ok": False, "detail": f"{exc.__class__.__name__}: {exc}"}


@app.get("/api/health")
async def api_health():
    from payment.legacy_client import mtls_context

    async def probe(name: str, base: str, path: str) -> dict:
        url = f"{base.rstrip('/')}{path}"
        started = monotonic()
        try:
            kwargs = {"timeout": 2.0}
            if name == "legacy-core":
                kwargs["verify"] = mtls_context()
            async with httpx.AsyncClient(**kwargs) as client:
                response = await client.get(url)
            return {"name": name, "up": response.status_code < 500, "status": response.status_code, "ms": round((monotonic() - started) * 1000)}
        except Exception:
            return {"name": name, "up": False, "status": None, "ms": None}

    results = await asyncio.gather(*(probe(*spec) for spec in HEALTH_PROBES))
    return {"services": results, "up": sum(1 for r in results if r["up"]), "total": len(results)}


@app.get("/api/soc/feed")
async def api_feed(limit: int = 6):
    events = []
    if EVENT_LOG.exists():
        for raw in EVENT_LOG.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
    return {"events": events[-limit:]}


@app.get("/api/test/crypto")
async def api_crypto():
    result = encrypt_card("4111111111111111", "12/25", "123")
    decrypted = decrypt_token(result)
    return {
        "algorithm": result["algorithm"],
        "cvv_stored": result["cvv_stored"],
        "encrypted_pan": result["encrypted_pan"],
        "decrypted_pan": decrypted["card_number"],
        "pan_visible": "4111111111111111" in str(result),
    }


@app.get("/api/test/fraud")
async def api_fraud(amount: float = 100):
    return FRAUD.analyze(amount, "EUR", "tok_demo", "merchant-api", "192.0.2.10")


@app.get("/api/test/hmac")
async def api_hmac():
    from shared.webhooks import sign_payload, signature_header, verify_signature

    body = {"type": "payment.succeeded", "payment_id": "pay_demo", "amount": 42}
    ts, sig = sign_payload(body)
    return {
        "header": signature_header(ts, sig),
        "verify_ok": verify_signature(body, ts, sig),
    }


@app.get("/api/test/cobol")
async def api_cobol(amount: float = 100):
    from payment.legacy_client import mtls_context
    from legacy_core.cobol_runner import decide
    from legacy_core.sanitize import account_from_merchant

    account = account_from_merchant("merchant-api")
    url = os.getenv("LEGACY_CORE_URL", "").rstrip("/")
    if url:
        try:
            async with httpx.AsyncClient(timeout=3.0, verify=mtls_context()) as client:
                response = await client.post(
                    f"{url}/validate",
                    json={"account_id": account, "amount": amount},
                )
            data = response.json()
            data["via"] = "gnucobol-wrapper"
            return data
        except Exception as exc:
            fallback = {"detail": f"wrapper injoignable ({exc.__class__.__name__}), fallback Python"}
    else:
        fallback = {}
    os.environ["LEGACY_CORE_ALLOW_FALLBACK"] = "1"
    status = decide(account, amount)
    return {"status": status, "account": account, "amount": amount, "via": "fallback", **fallback}


@app.post("/api/atm/kanest")
async def api_atm_kanest():
    from atm.kanest.runner import run_all

    return await run_all()


@app.get("/api/atm/fleet")
async def api_atm_fleet():
    from atm import argaus

    return argaus.list_atms()


@app.post("/api/atm/fleet/{atm_id}/status")
async def api_atm_fleet_status(atm_id: str, status: str = "MAINTENANCE", reason: str = ""):
    from atm import argaus

    try:
        return argaus.set_status(atm_id, status, reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="DAB inconnu") from exc


@app.get("/api/atm/aptra")
async def api_atm_aptra():
    from atm import aptra

    return aptra.report()


@app.get("/api/atm/journals/{kind}")
async def api_atm_journals(kind: str, limit: int = 40):
    from atm.journals import tail

    if kind not in {"mxa", "vte"}:
        raise HTTPException(status_code=400, detail="kind=mxa|vte")
    return tail(kind, limit=limit)


@app.get("/api/atm/defects")
async def api_atm_defects():
    from atm import alm

    return alm.list_defects()


@app.get("/api/atm/pv", response_class=HTMLResponse)
async def api_atm_pv():
    path = Path(os.getenv("SECUREPAY_PV_DIR", "logs")) / "pv-recette-dab.html"
    if not path.exists():
        return HTMLResponse(
            "<p>Lancez les recettes KaNest d'abord (onglet DAB / PFA).</p>",
            status_code=404,
        )
    return HTMLResponse(path.read_text(encoding="utf-8"))


@app.api_route("/api/soc/evaluate", methods=["GET", "POST"])
async def api_evaluate():
    fired = []
    if EVENT_LOG.exists():
        fired.extend(ENGINE.ingest_file(EVENT_LOG))
    if LOG_DIR.exists():
        for path in LOG_DIR.glob("*.jsonl"):
            fired.extend(ENGINE.ingest_file(path))
    pipeline = handle_alerts(fired)
    return {
        "alerts_fired": len(fired),
        "alerts_total": len(ENGINE.alerts),
        "alerts": [a.__dict__ for a in ENGINE.alerts[-40:]],
        "soar_blocks": list_blocks(),
        "hive_cases": pipeline["hive_cases"],
        "intel": pipeline["intel"],
        "navigator_techniques": pipeline["navigator_techniques"],
    }


@app.get("/api/soc/coverage")
async def api_coverage():
    mapping = json.loads(Path("detection/sigma/mappings/mitre_attack.json").read_text(encoding="utf-8"))
    techniques = {}
    for spec in mapping.values():
        mitre = spec.get("mitre_attack") or {}
        techniques[mitre.get("technique_id")] = {
            "technique_id": mitre.get("technique_id"),
            "name": mitre.get("technique_name"),
            "tactic": mitre.get("tactic"),
        }
    return {"rules": len(ENGINE.rules), "techniques": techniques}


@app.get("/api/attack/{scenario}")
async def api_attack(scenario: str):
    import random

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)

    def log_event(event: dict):
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        event["source"] = "securepay-attack-simulator"
        for path in (LOG_DIR / f"events_{datetime.now().strftime('%Y%m%d')}.jsonl", EVENT_LOG):
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event) + "\n")
        ENGINE.evaluate_event(event)

    ip = f"203.0.113.{random.randint(1, 254)}"
    count = 0
    if scenario == "carding":
        for _ in range(25):
            log_event(
                {
                    "event_type": "payment_attempt",
                    "scenario": "card_testing",
                    "source_ip": ip,
                    "amount": round(random.uniform(5, 80), 2),
                    "status": "failed",
                    "merchant_id": "merchant-api",
                }
            )
            count += 1
    elif scenario == "credential_stuffing":
        for _ in range(25):
            log_event(
                {
                    "event_type": "authentication_attempt",
                    "scenario": "credential_stuffing",
                    "source_ip": ip,
                    "username": random.choice(["admin", "merchant1", "test"]),
                    "status": "failed",
                }
            )
            count += 1
    elif scenario == "bola":
        for _ in range(10):
            log_event(
                {
                    "event_type": "authorization_error",
                    "scenario": "bola",
                    "error_type": "object_level_authorization",
                    "source_ip": ip,
                    "merchant_id": "merchant-api",
                    "target_merchant_id": f"MERCH_{random.randint(100, 999)}",
                    "status_code": 403,
                }
            )
            count += 1
    elif scenario == "jwt_replay":
        log_event({"event_type": "jwt_replay", "status": "blocked", "source_ip": ip, "jti": "replayed"})
        count = 1
    elif scenario == "sqli":
        log_event(
            {
                "event_type": "injection_probe",
                "status": "blocked",
                "source_ip": ip,
                "payload": "' OR 1=1 --",
            }
        )
        count = 1
    elif scenario == "fraud_spike":
        for _ in range(15):
            log_event(
                {
                    "event_type": "fraud_score",
                    "scenario": "fraud_spike",
                    "source_ip": ip,
                    "risk_score": round(random.uniform(0.85, 0.99), 4),
                    "risk_level": "critical",
                    "amount": round(random.uniform(5000, 20000), 2),
                    "merchant_id": "merchant-api",
                }
            )
            count += 1
    else:
        return {"error": "unknown scenario"}
    return {"scenario": scenario, "events_created": count, "attacker_ip": ip}
