# Mapping SentinelPay `services/`

| Brief SentinelPay | Ce repo |
|-------------------|---------|
| `api-gateway/` | `gateway/` |
| `auth-service/` | Keycloak + `shared/auth.py` |
| `payment-service/` | `payment/` + `tokenization/` |
| `detection-service/` | `detection/engine/` + `fraud/` |
| `webhook-receiver/` | `services/webhook-receiver/` (Node.js HMAC) |
