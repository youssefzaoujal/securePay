"""3DS 1.0 legacy — MPI + ACS redirect (PARes/PAReq XML signé).

Module historique minimal POUR ILLUSTRER pourquoi 3DS 2.0 existe :
  - UX dégradée (redirection iframe, pas mobile-friendly)
  - taux d'abandon élevé (parcours interrompu)
  - pas de données device dans la requête

Il ne sert qu'à la pédagogie / démo. Le trafic production de cette repo
passe par le flux EMV 3DS 2.x (three_ds/, directory_server/, acs_simulator/).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from xml.etree import ElementTree

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from shared.events import emit_event
from shared.http import mount_security

Legacy = None

app = FastAPI(
    title="SecurePay - Legacy 3DS 1.0 (MPI)",
    version="1.0.0",
    description="Legacy MPI + ACS redirect — pour comparaison avec EMV 3DS 2.x.",
)
mount_security(app)

_sessions: dict[str, dict] = {}


class PAReqBody(BaseModel):
    """PAReq — Payment Authentication Request (3DS 1.0)."""
    merchant_id: str
    purchase_id: str
    amount: float
    currency: str = "EUR"
    card_token: str
    cardholder_url: str = ""

    # Signature XML (lab) — en prod signée avec RSA PKCS#1 v1.5 du marchand (MPI).
    @property
    def pa_res_callback(self) -> str:
        return "/api/v1/pares"

    def to_xml(self, session_id: str) -> str:
        root = ElementTree.Element("PAResRequest")
        ElementTree.SubElement(root, "MERCHANT").text = self.merchant_id
        ElementTree.SubElement(root, "XPID").text = session_id
        ElementTree.SubElement(root, "PURCHAMT").text = f"{self.amount:.2f}"
        ElementTree.SubElement(root, "CURRENCY").text = self.currency
        ElementTree.SubElement(root, "CARDTOKEN").text = self.card_token
        return ElementTree.tostring(root, encoding="unicode")


class PAResBody(BaseModel):
    result: str = Field(..., pattern="^(Y|N|U)$")
    session_id: str
    eci: str = "07"


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "legacy-3ds1-mpi"}


@app.post("/api/v1/pareq", status_code=201)
async def create_pareq(body: PAReqBody):
    """Endpoint MPI : retourne la redirection ACS (iframe encastrable)."""
    session_id = f"3ds1_{uuid.uuid4().hex[:20]}"
    xml = body.to_xml(session_id)
    _sessions[session_id] = {
        "merchant_id": body.merchant_id,
        "purchase_id": body.purchase_id,
        "amount": body.amount,
        "currency": body.currency,
        "card_token": body.card_token,
        "xml_digest": hashlib.sha256(xml.encode()).hexdigest(),
        "status": "redirected",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    emit_event(
        {
            "event_type": "three_ds",
            "scenario": "3ds1_pareq",
            "session_id": session_id,
            "merchant_id": body.merchant_id,
            "amount": body.amount,
            "status": "redirected",
        }
    )

    # 3DS 1.0 : interruption du parcours → redirection iframe (ACSUrl).
    return {
        "session_id": session_id,
        "acs_url": f"/api/v1/acs-simulated/{session_id}",
        "pareq_xml": xml,
        "iframe_warning": "3DS 1.0 legacy: UX dégradée, pas mobile-friendly.",
    }


@app.post("/api/v1/pares")
async def receive_pares(body: PAResBody | None = None, session_id: str = "", result: str = "U", eci: str = "07"):
    """Réception du PARes (XML signé) depuis le simulateur ACS."""
    if body is None:
        body = PAResBody(result=result, session_id=session_id, eci=eci)
    session = _sessions.get(body.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session 3DS1 inconnue")
    session["status"] = "completed"
    session["pares_result"] = body.result
    session["eci"] = body.eci

    verified = body.result == "Y"
    emit_event(
        {
            "event_type": "three_ds",
            "scenario": "3ds1_pares",
            "session_id": body.session_id,
            "merchant_id": session.get("merchant_id"),
            "result": body.result,
            "eci": body.eci,
            "status": "ok",
        }
    )
    return {
        "session_id": body.session_id,
        "verified": verified,
        "eci": body.eci,
        "acs_rendered": session.get("status"),
    }


@app.get("/api/v1/acs-simulated/{session_id}")
async def acs_simulated(session_id: str, approve: int = 0):
    """Page HTML simulée de l'ACS legacy (parcours cassé par design)."""
    session = _sessions.get(session_id)
    brand = (session or {}).get("card_token", "").split("_")[-1][:4] or "****"
    approve_link = f"/api/v1/acs-simulated/{session_id}?approve=1"
    if approve:
        return _pares_close(session_id)
    return f"""
    <!doctype html><html><head><title>ACS 3DS 1.0 (legacy demo)</title></head>
    <body style="font-family:monospace;background:#f5f5f5;padding:2rem">
      <h1>Bank ACS — 3DS 1.0</h1>
      <p>Paiement de <b>{(session or {}).get('amount', 0.0):.2f} {(session or {}).get('currency', 'EUR')}</b>
      sur carte ****{brand}</p>
      <p>Ceci est la page <i>legacy</i> 3DS 1.0 : redirection iframe, pas de
      device fingerprinting, abandon ~60% en mobile. C'est pourquoi
      <strong>EMV 3DS 2.x</strong> existe.</p>
      <div>
        <form method="get" action="{approve_link}">
          <button style="background:#222;color:#fff;padding:1rem 2rem;border:0;cursor:pointer">
          Continuer (simulation)</button>
        </form>
      </div>
    </body></html>
    """


def _pares_close(session_id: str):
    """Clone le retour iframe → POST PARes au MPI (3DS 1.0)."""
    return """
    <!doctype html><html><body>
      <script>window.location = "/api/v1/pares?session_id=%s&result=Y&eci=05";</script>
    </body></html>
    """ % session_id