"""Payment routes — persistance, BOLA object-level, webhooks HMAC."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status

from payment.idempotency import IdempotencyConflict, STORE as IDEMPOTENCY
from payment.ledger import LEDGER
from payment.legacy_client import call_legacy_core
from payment.schemas import PaymentStatus, ProcessPaymentRequest, ProcessPaymentResponse
from shared.auth import TokenClaims, verify_token
from shared.bola import assert_object_owner, bind_merchant_id
from shared.events import emit_event
from shared.metrics import TRANSACTIONS
from shared.webhooks import sign_payload, signature_header

router = APIRouter()

_PAYMENTS: dict[str, dict] = {}


def _to_response(row: dict) -> ProcessPaymentResponse:
    return ProcessPaymentResponse(
        id=row["id"],
        status=PaymentStatus(row["status"]),
        amount=row["amount"],
        currency=row["currency"],
        card_last_four=row["card_last_four"],
        merchant_id=row["merchant_id"],
        authorization_code=row.get("authorization_code"),
        created_at=row["created_at"],
        fraud_score=row.get("fraud_score"),
        correlation_id=row.get("correlation_id"),
        idempotent_replay=bool(row.get("idempotent_replay")),
        three_ds_status=row.get("three_ds_status"),
        three_ds_eci=row.get("three_ds_eci"),
    )


@router.post("/process", response_model=ProcessPaymentResponse, status_code=status.HTTP_201_CREATED)
async def process_payment(
    data: ProcessPaymentRequest,
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    """Autorisation simulée — le PAN n'entre jamais dans ce service."""
    merchant_id = bind_merchant_id(claims, data.merchant_id)
    idem_key = (request.headers.get("idempotency-key") or data.idempotency_key or "").strip()
    fingerprint_payload = {
        "amount": data.amount,
        "currency": data.currency,
        "card_token": data.card_token,
        "merchant_id": merchant_id,
    }
    if idem_key:
        try:
            existing_id = IDEMPOTENCY.replay_or_conflict(merchant_id, idem_key, fingerprint_payload)
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        if existing_id and existing_id in _PAYMENTS:
            row = dict(_PAYMENTS[existing_id])
            row["idempotent_replay"] = True
            if row["status"] == PaymentStatus.FAILED.value:
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail="Paiement refusé par le core banking (COBOL) ou l'acquéreur simulé",
                )
            return _to_response(row)

    payment_id = f"pay_{uuid.uuid4().hex[:16]}"
    three_ds_ok = data.three_ds_status in (
        None,
        "verified",
        "frictionless",
        "3ds2_authenticated",
        "3ds2_frictionless",
        "3ds2_Y",
        "3ds2_A",
        "3ds2_U",
    )
    if data.three_ds_status in ("3ds2_N", "3ds2_R"):
        three_ds_ok = False
    core_decision = None
    if data.three_ds_status != "pending":
        core_decision = await call_legacy_core(merchant_id, data.amount)
    if core_decision is None:
        approved = data.amount <= 10000.00 and three_ds_ok
    else:
        approved = core_decision == "APPROVED" and three_ds_ok

    if data.three_ds_status == "pending":
        status_value = PaymentStatus.CHALLENGE_REQUIRED
        auth_code = None
    elif not approved:
        status_value = PaymentStatus.FAILED
        auth_code = None
    else:
        status_value = PaymentStatus.SUCCEEDED
        auth_code = f"AUTH_{uuid.uuid4().hex[:8].upper()}"

    row = {
        "id": payment_id,
        "status": status_value.value,
        "amount": data.amount,
        "currency": data.currency,
        "card_token": data.card_token,
        "card_last_four": data.card_last_four,
        "card_brand": data.card_brand,
        "merchant_id": merchant_id,
        "authorization_code": auth_code,
        "created_at": datetime.now(timezone.utc),
        "fraud_score": data.fraud_score,
        "fraud_flags": data.fraud_flags,
        "ip_address": data.ip_address or (request.client.host if request.client else ""),
        "correlation_id": data.correlation_id,
        "description": data.description,
        "idempotency_key": idem_key or None,
        "idempotent_replay": False,
        "three_ds_status": data.three_ds_status,
        "three_ds_eci": data.three_ds_eci,
        "three_ds_cavv": data.three_ds_cavv,
    }
    _PAYMENTS[payment_id] = row
    if idem_key:
        IDEMPOTENCY.remember(merchant_id, idem_key, fingerprint_payload, payment_id)

    emit_event(
        {
            "event_type": "payment_attempt",
            "payment_id": payment_id,
            "merchant_id": merchant_id,
            "amount": data.amount,
            "currency": data.currency,
            "status": "failed" if status_value == PaymentStatus.FAILED else status_value.value,
            "card_token": data.card_token,
            "card_last_four": data.card_last_four,
            "fraud_score": data.fraud_score,
            "source_ip": row["ip_address"],
            "correlation_id": data.correlation_id,
            "legacy_core": core_decision,
        }
    )
    TRANSACTIONS.labels(
        status=status_value.value,
        merchant_id=merchant_id,
        decision=status_value.value,
    ).inc()

    if status_value == PaymentStatus.SUCCEEDED:
        LEDGER.post_capture(payment_id, merchant_id, data.amount, data.currency)
        webhook_body = {
            "type": "payment.succeeded",
            "payment_id": payment_id,
            "merchant_id": merchant_id,
            "amount": data.amount,
            "currency": data.currency,
        }
        ts, sig = sign_payload(webhook_body)
        row["webhook"] = {"header": signature_header(ts, sig), "body": webhook_body}

    if status_value == PaymentStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Paiement refusé par le core banking (COBOL) ou l'acquéreur simulé",
        )

    return _to_response(row)


@router.get("/ledger/reconcile")
async def ledger_reconcile(claims: TokenClaims = Depends(verify_token)):
    """Réconciliation auto : débits = crédits."""
    return LEDGER.reconcile()


@router.get("/{payment_id}", response_model=ProcessPaymentResponse)
async def get_payment(
    payment_id: str,
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    row = _PAYMENTS.get(payment_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Paiement non trouvé")
    assert_object_owner(
        claims,
        row["merchant_id"],
        resource_type="transaction",
        resource_id=payment_id,
        source_ip=request.client.host if request.client else "",
    )
    return _to_response(row)


@router.get("", response_model=list[ProcessPaymentResponse])
async def list_payments(claims: TokenClaims = Depends(verify_token)):
    """Liste scoped au merchant JWT — pas d'énumération cross-tenant."""
    merchant_id = claims.merchant_id
    is_admin = "admin" in claims.roles
    rows = [
        row
        for row in _PAYMENTS.values()
        if is_admin or row["merchant_id"] == merchant_id
    ]
    return [_to_response(row) for row in rows]
