"""Gateway API Routes — orchestration tokenize → fraud → 3DS → payment."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from config import get_settings
from gateway.proxy import proxy_to_service
from gateway.schemas import (
    Currency,
    FraudCheckRequest,
    FraudCheckResponse,
    PaymentRequest,
    PaymentResponse,
    PaymentStatus,
    TokenizeRequest,
    TokenizeResponse,
)
from logging_config import correlation_id
from shared.auth import TokenClaims, verify_token
from shared.bola import bind_merchant_id
from shared.events import emit_event

router = APIRouter()
settings = get_settings()


class ChallengeVerifyBody(BaseModel):
    challenge_id: str
    otp_code: str = Field(..., min_length=6, max_length=6)


class ThreeDSInitBody(BaseModel):
    """Initialisation du flux EMV 3DS 2.x depuis le gateway."""
    payment_id: str
    amount: float = Field(..., gt=0)
    currency: str = "EUR"
    card_token: str
    card_last_four: str = "****"
    card_brand: str = "unknown"
    ip_address: str = ""
    device_channel: str = "BROWSER"
    device_info: dict = Field(default_factory=dict)


@router.get("/me")
async def get_current_user(claims: TokenClaims = Depends(verify_token)):
    return {
        "merchant_id": claims.merchant_id,
        "subject": claims.subject,
        "roles": claims.roles,
        "scope": claims.get("scope"),
    }


@router.post("/payments", status_code=status.HTTP_201_CREATED)
async def create_payment(
    payment: PaymentRequest,
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    """Flux PSP : tokenise (PAN hors payment) → score fraude → 3DS si besoin → capture."""
    merchant_id = bind_merchant_id(claims, payment.merchant_id)
    cid = correlation_id.get("")
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
        request.client.host if request.client else ""
    )
    token_header = request.headers.get("authorization", "").replace("Bearer ", "")

    token_result = await proxy_to_service(
        service_url=settings.TOKENIZATION_SERVICE_URL,
        path="/api/v1/tokenize",
        method="POST",
        data={
            "card_number": payment.card_number,
            "card_expiry": payment.card_expiry,
            "card_cvv": payment.card_cvv,
        },
        token=token_header,
    )

    fraud_result = await proxy_to_service(
        service_url=settings.FRAUD_SERVICE_URL,
        path="/api/v1/check",
        method="POST",
        data={
            "amount": payment.amount,
            "currency": payment.currency.value if hasattr(payment.currency, "value") else payment.currency,
            "card_token": token_result["token"],
            "merchant_id": merchant_id,
            "ip_address": client_ip,
        },
        token=token_header,
    )

    if fraud_result.get("recommendation") == "decline" or fraud_result.get("risk_score", 0) >= settings.FRAUD_THRESHOLD:
        emit_event(
            {
                "event_type": "payment_attempt",
                "status": "failed",
                "scenario": "fraud_decline",
                "merchant_id": merchant_id,
                "amount": payment.amount,
                "source_ip": client_ip,
                "fraud_score": fraud_result.get("risk_score"),
                "correlation_id": cid,
            }
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Transaction refusée par le moteur de fraude",
                "risk_score": fraud_result.get("risk_score"),
                "flags": fraud_result.get("flags"),
            },
        )

    three_ds_status = "frictionless"
    three_ds_result = None
    challenge = None
    if fraud_result.get("challenge_required") or fraud_result.get("recommendation") == "review":
        three_ds_result = await proxy_to_service(
            service_url=settings.THREEDS_SERVER_URL,
            path="/api/v1/authenticate",
            method="POST",
            data={
                "transaction_id": cid or "pending",
                "amount": payment.amount,
                "currency": payment.currency.value if hasattr(payment.currency, "value") else payment.currency,
                "merchant_id": merchant_id,
                "card_token": token_result["token"],
                "card_last_four": token_result.get("last_four", "****"),
                "card_brand": token_result.get("card_brand", "unknown"),
                "ip_address": client_ip,
                "device_channel": "BROWSER",
                "device_info": {"device_ip": client_ip},
                "merchant_category_code": "5999",
            },
            token=token_header,
        )
        if three_ds_result.get("challenge_required"):
            three_ds_status = "pending"
            challenge = {
                "challenge_id": three_ds_result.get("challenge_id"),
                "acs_url": three_ds_result.get("acs_url"),
                "require_challenge": True,
            }
        else:
            three_ds_status = "3ds2_authenticated" if three_ds_result.get("trans_status") == "Y" else "3ds2_" + str(three_ds_result.get("trans_status", "U"))
    else:
        three_ds_result = await proxy_to_service(
            service_url=settings.THREEDS_SERVER_URL,
            path="/api/v1/authenticate",
            method="POST",
            data={
                "transaction_id": cid or "pending",
                "amount": payment.amount,
                "currency": payment.currency.value if hasattr(payment.currency, "value") else payment.currency,
                "merchant_id": merchant_id,
                "card_token": token_result["token"],
                "card_last_four": token_result.get("last_four", "****"),
                "card_brand": token_result.get("card_brand", "unknown"),
                "ip_address": client_ip,
                "device_channel": "BROWSER",
                "device_info": {"device_ip": client_ip},
                "merchant_category_code": "5999",
            },
            token=token_header,
        )
        if three_ds_result.get("trans_status") in ("N", "R"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "Authentification 3DS refusée par l'émetteur",
                    "trans_status": three_ds_result.get("trans_status"),
                },
            )
        three_ds_status = "3ds2_authenticated" if three_ds_result.get("trans_status") == "Y" else "3ds2_frictionless"

    result = await proxy_to_service(
        service_url=settings.PAYMENT_SERVICE_URL,
        path="/api/v1/process",
        method="POST",
        data={
            "amount": payment.amount,
            "currency": payment.currency.value if hasattr(payment.currency, "value") else payment.currency,
            "card_token": token_result["token"],
            "merchant_id": merchant_id,
            "description": payment.description,
            "ip_address": client_ip,
            "fraud_score": fraud_result.get("risk_score"),
            "fraud_flags": fraud_result.get("flags", []),
            "card_last_four": token_result.get("last_four", "****"),
            "card_brand": token_result.get("card_brand", "unknown"),
            "correlation_id": cid,
            "three_ds_status": three_ds_status,
            "three_ds_eci": three_ds_result.get("eci") if three_ds_result else None,
            "three_ds_cavv": three_ds_result.get("cavv") if three_ds_result else None,
        },
        token=token_header,
        extra_headers={"Idempotency-Key": request.headers.get("idempotency-key", "")},
    )

    return {
        **result,
        "fraud": fraud_result,
        "tokenization": {
            "token": token_result["token"],
            "last_four": token_result.get("last_four"),
            "brand": token_result.get("card_brand"),
            "cvv_stored": False,
            "algorithm": token_result.get("algorithm"),
        },
        "three_ds": {
            "status": three_ds_status,
            "workflow": "EMV 3DS 2.x",
            **(three_ds_result or {}),
        },
        "three_ds_challenge": challenge,
        "correlation_id": cid,
    }


@router.post("/payments/{payment_id}/3ds/init", status_code=status.HTTP_200_OK)
async def init_three_ds(
    payment_id: str,
    body: ThreeDSInitBody,
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    """Lance le flux EMV 3DS 2.x : AReq → DS → ACS → ARes (frictionless ou challenge).

    C'est le point où un PSP réel décide d'appeler le 3DS Server :
      - 3DS Requestor (le PSP) → 3DS Server (three_ds)
      - 3DS Server → Directory Server (réseau Visa/MC simulé)
      - DS → ACS (banque émettrice) — décision frictionless/challenge
    """
    token_header = request.headers.get("authorization", "").replace("Bearer ", "")
    result = await proxy_to_service(
        service_url=settings.THREEDS_SERVER_URL,
        path="/api/v1/authenticate",
        method="POST",
        data={
            "transaction_id": payment_id,
            "amount": body.amount,
            "currency": body.currency,
            "merchant_id": claims.merchant_id,
            "card_token": body.card_token,
            "card_last_four": body.card_last_four,
            "card_brand": body.card_brand,
            "ip_address": body.ip_address,
            "device_channel": body.device_channel,
            "device_info": body.device_info,
            "merchant_category_code": "5999",
        },
        token=token_header,
    )
    return result


@router.post("/payments/{payment_id}/3ds/challenge", status_code=status.HTTP_200_OK)
async def complete_3ds_challenge(
    payment_id: str,
    body: ChallengeVerifyBody,
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    """Finalise le challenge 3DS 2.x : CReq → ACS → CRes → RReq → RRes."""
    token_header = request.headers.get("authorization", "").replace("Bearer ", "")
    return await proxy_to_service(
        service_url=settings.THREEDS_SERVER_URL,
        path="/api/v1/challenge/complete",
        method="POST",
        data={
            "three_ds_server_trans_id": body.challenge_id,
            "otp_code": body.otp_code,
        },
        token=token_header,
    )


@router.post("/payments/{payment_id}/3ds", status_code=status.HTTP_200_OK)
async def complete_3ds(
    payment_id: str,
    body: ChallengeVerifyBody,
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    token_header = request.headers.get("authorization", "").replace("Bearer ", "")
    return await proxy_to_service(
        service_url=settings.FRAUD_SERVICE_URL,
        path="/api/v1/verify-challenge",
        method="POST",
        data=body.model_dump(),
        token=token_header,
    )


@router.get("/payments/{payment_id}")
async def get_payment(
    payment_id: str,
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    token_header = request.headers.get("authorization", "").replace("Bearer ", "")
    return await proxy_to_service(
        service_url=settings.PAYMENT_SERVICE_URL,
        path=f"/api/v1/{payment_id}",
        method="GET",
        token=token_header,
    )


@router.get("/payments")
async def list_payments(
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    token_header = request.headers.get("authorization", "").replace("Bearer ", "")
    return await proxy_to_service(
        service_url=settings.PAYMENT_SERVICE_URL,
        path="/api/v1",
        method="GET",
        token=token_header,
    )


@router.post("/tokens", response_model=TokenizeResponse, status_code=status.HTTP_201_CREATED)
async def tokenize_card(
    card_data: TokenizeRequest,
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    token_header = request.headers.get("authorization", "").replace("Bearer ", "")
    return await proxy_to_service(
        service_url=settings.TOKENIZATION_SERVICE_URL,
        path="/api/v1/tokenize",
        method="POST",
        data=card_data.model_dump(),
        token=token_header,
    )


@router.post("/fraud/check", response_model=FraudCheckResponse)
async def check_fraud(
    fraud_data: FraudCheckRequest,
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    token_header = request.headers.get("authorization", "").replace("Bearer ", "")
    payload = fraud_data.model_dump()
    payload["merchant_id"] = bind_merchant_id(claims, fraud_data.merchant_id)
    payload["currency"] = (
        fraud_data.currency.value if hasattr(fraud_data.currency, "value") else fraud_data.currency
    )
    return await proxy_to_service(
        service_url=settings.FRAUD_SERVICE_URL,
        path="/api/v1/check",
        method="POST",
        data=payload,
        token=token_header,
    )
