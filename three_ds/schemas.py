"""EMV 3DS 2.x schemas — AReq/ARes/CRes/RReq/RRes selon EMVCo 3DS Core Spec v2.3."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────────────────────

class TransStatus(str, Enum):
    """transStatus — EMVCo 3DS Core Spec v2.3 §A.4."""
    Y = "Y"  # Authentication successful
    N = "N"  # Authentication failed
    U = "U"  # Authentication unavailable
    A = "A"  # Attempts processing performed
    C = "C"  # Challenge required; cardholder authentication required
    R = "R"  # Authentication rejected by issuer


class MessageCategory(str, Enum):
    """messageCategory — EMVCo §A.2."""
    A = "A"  # Authentication message
    D = "D"  # Device message
    G = "G"  # Non-payer authentication message


class DeviceRenderOptions(str, Enum):
    """deviceRenderOptions supported — EMVCo §A.2.8."""
    OTP_SMS = "otp-sms"
    OTP_EMAIL = "otp-email"
    OTP_APP = "otp-app"
    BIOMETRIC = "biometric"


class DecoupledProcessingRequest(str, Enum):
    """decoupledProcessingRequest — EMVCo §A.2."""
    Y = "Y"  # Decoupled authentication requested by 3DS Server
    N = "N"  # Decoupled not requested


class WhiteListStatus(str, Enum):
    """whitelistStatus — EMVCo §A.6."""
    Y = "Y"  # Cardholder is whitelisted
    N = "N"  # Cardholder is not whitelisted
    absent = "absent"


# ──────────────────────────────────────────────────────────────────────────────
# 3DS Server → DS / ACS  (AReq)
# ──────────────────────────────────────────────────────────────────────────────

class CardholderInfo(BaseModel):
    """cardholderBillingAddress — subset EMVCo §A.2.6."""
    addr_line1: str | None = None
    addr_line2: str | None = None
    addr_line3: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None


class MerchantInfo(BaseModel):
    """merchant and acquirer details — EMVCo §A.2.2."""
    merchant_id: str
    merchant_name: str = "SecurePay Lab Merchant"
    merchant_country_code: str = "FR"
    acquirer_merchant_id: str = "ACQ_SECUREPAY_LAB"
    acquirer_country_code: str = "FR"


class TransactionInfo(BaseModel):
    """transaction details — EMVCo §A.2.2."""
    amount: float = Field(..., gt=0)
    currency: str = "EUR"
    transaction_type: str = "01"  # 01 = goods/service
    date: str = ""  # yyyymmddhhmmss — filled at creation
    purchase_inst_ref: str = ""  # PAN reference number


class DeviceInfo(BaseModel):
    """device info (SDK channel) — EMVCo §A.2.8."""
    device_channel: str = "APP"  # APP, BROWSER, THREE_DS_REQUESTOR_SDK
    device_info: dict[str, Any] = Field(default_factory=dict)
    sdk_app_id: str | None = None
    sdk_transaction_id: str | None = None
    sdk_reference_number: str | None = None
    sdk_ephemeral_public_key: str | None = None
    sdk_max_timeout: int = 12  # seconds


class BrowserInfo(BaseModel):
    """browser info (BROWSER channel) — EMVCo §A.2.7."""
    browser_accept_header: str = "*/*"
    browser_ip: str = "127.0.0.1"
    browser_language: str = "fr-FR"
    browser_tz: int = 60  # UTC offset in minutes
    browser_user_agent: str = "SecurePayLab/1.0"
    browser_color_depth: int = 24
    browser_screen_height: int = 1080
    browser_screen_width: int = 1920
    browser_window_height: int = 960
    browser_window_width: int = 1920
    browser_java_enabled: bool = False
    browser_javascript_enabled: bool = True
    browser_plugins_enabled: bool = False
    browser_flash: str | None = None
    browser_package_name: str | None = None
    browser_operating_system: str | None = None


class AuthenticationRequest(BaseModel):
    """AReq — Authentication Request — EMVCo §A.2.
    Sent by 3DS Server to DS, then routed to ACS."""
    protocol_version: str = "2.3.0"
    message_type: str = "AReq"
    message_category: MessageCategory = MessageCategory.A
    three_ds_server_trans_id: str
    merchant: MerchantInfo
    transaction: TransactionInfo
    card: dict[str, str] = Field(default_factory=dict)
    device: DeviceInfo = Field(default_factory=DeviceInfo)
    browser: BrowserInfo | None = None
    cardholder: CardholderInfo | None = None
    requestor_challenge_ind: str = "04"  # 04 = both supported
    whatsapp_phone_number: str | None = None
    decoupled_processing_request: DecoupledProcessingRequest = DecoupledProcessingRequest.N
    messaging_extension: dict[str, Any] | None = None


# ──────────────────────────────────────────────────────────────────────────────
# ACS → 3DS Server  (ARes)
# ──────────────────────────────────────────────────────────────────────────────

class AuthenticationResponse(BaseModel):
    """ARes — Authentication Response — EMVCo §A.3."""
    protocol_version: str = "2.3.0"
    message_type: str = "ARes"
    three_ds_server_trans_id: str
    acs_trans_id: str | None = None
    ds_trans_id: str | None = None
    trans_status: TransStatus = TransStatus.U
    trans_status_reason: str | None = None
    eci: str | None = None
    cavv: str | None = None  # Cardholder Authentication Verification Value
    cavv_algorithm: str | None = None
    acs_challenge_mandated: str | None = None  # Y/N
    acs_url: str | None = None  # URL to call for challenge
    challenge_type: str | None = None
    three_ds_requestor_url: str | None = None
    whitelisting_status: WhiteListStatus = WhiteListStatus.absent
    acs_operator_id: str | None = None
    error_code: str | None = None
    error_component: str | None = None
    error_description: str | None = None
    message_version: str = "2.3.0"


# ──────────────────────────────────────────────────────────────────────────────
# Challenge flow — 3DS Server → ACS (CReq/CRes)
# ──────────────────────────────────────────────────────────────────────────────

class ChallengeRequest(BaseModel):
    """CReq — Challenge Request — EMVCo §A.4."""
    message_type: str = "CReq"
    three_ds_server_trans_id: str
    acs_trans_id: str
    challenge_window_size: str = "03"  # 01-09
    display_time_information: int = 0
    otp_code: str | None = None  # for lab simulation
    biometric_type: str | None = None


class ChallengeResponse(BaseModel):
    """CRes — Challenge Response — EMVCo §A.4."""
    message_type: str = "CRes"
    three_ds_server_trans_id: str
    acs_trans_id: str
    trans_status: TransStatus = TransStatus.Y
    acs_challenge_mandated: str | None = None


# ──────────────────────────────────────────────────────────────────────────────
# Result message — ACS → DS → 3DS Server (RReq / RRes)
# ──────────────────────────────────────────────────────────────────────────────

class ResultRequest(BaseModel):
    """RReq — Result Request — EMVCo §A.5."""
    message_type: str = "RReq"
    three_ds_server_trans_id: str
    acs_trans_id: str
    ds_trans_id: str | None = None
    trans_status: TransStatus = TransStatus.Y
    eci: str | None = None
    cavv: str | None = None
    cavv_algorithm: str | None = None
    authentication_value: str | None = None
    basket_id: str | None = None
    error_code: str | None = None
    error_component: str | None = None
    error_description: str | None = None
    message_version: str = "2.3.0"


class ResultResponse(BaseModel):
    """RRes — Result Response — EMVCo §A.5."""
    message_type: str = "RRes"
    three_ds_server_trans_id: str
    acs_trans_id: str
    acs_rendering_type: str | None = None


# ──────────────────────────────────────────────────────────────────────────────
# Internal — fraud engine input (reuses existing fraud scoring)
# ──────────────────────────────────────────────────────────────────────────────

class ThreeDSAuthInput(BaseModel):
    """Internal input from gateway for 3DS decision engine."""
    transaction_id: str
    amount: float
    currency: str = "EUR"
    merchant_id: str
    card_token: str
    card_last_four: str = "****"
    card_brand: str = "unknown"
    ip_address: str = ""
    device_channel: str = "BROWSER"
    device_info: dict[str, Any] = Field(default_factory=dict)
    merchant_category_code: str = "5999"
    risk_score: float | None = None  # from upstream fraud engine


class ThreeDSResult(BaseModel):
    """Result returned to gateway after 3DS processing."""
    trans_status: TransStatus
    eci: str | None = None
    cavv: str | None = None
    three_ds_server_trans_id: str
    acs_trans_id: str | None = None
    ds_trans_id: str | None = None
    challenge_required: bool = False
    challenge_id: str | None = None
    acs_url: str | None = None
    error_code: str | None = None
    error_description: str | None = None
