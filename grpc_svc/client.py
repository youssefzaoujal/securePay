"""Client gRPC générique (via raw unary) + pont REST→gRPC.

Utilisé par gateway pour appeler payment/fraud par le backbone gRPC quand
`USE_GRPC=true`. Sans broker/process gRPC, le pont tombe sur le canal in-process
qui délègue aux mêmes moteurs — la logique métier est identique par construction.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import grpc

from config import get_settings

logger = logging.getLogger("securepay.grpc.client")
settings = get_settings()

from grpc_svc import raw_proto  # noqa: E402

PACKAGE = raw_proto.PACKAGE
SERVICE = raw_proto.SERVICE
METHOD = raw_proto.METHOD


class InternalClient:
    """Appelle `securepay.internal.v1.Unary/Invoke` via gRPC (ou in-process)."""

    def __init__(self, target: str, service=None):
        self._target = target
        self._service = service  # in-process InternalService (repli test/démo)

    def _invoke(self, method: str, request: dict) -> dict:
        if self._service is not None:
            import asyncio

            return asyncio.run(self._service.dispatch(method, request))

        channel = grpc.insecure_channel(self._target)
        try:
            payload = json.dumps(
                {"method": f"{PACKAGE}.{SERVICE}/{METHOD}#{method}", "request_json": request}
            ).encode("utf-8")
            response = channel.unary_unary(
                f"/{PACKAGE}.{SERVICE}/{METHOD}",
                request_serializer=lambda req: req,
                response_deserializer=lambda raw: raw,
            )(payload, timeout=10)
            data = json.loads(response.decode("utf-8"))
            if "error" in data:
                raise RuntimeError(data["error"])
            return data
        finally:
            channel.close()


def payment_client(service=None) -> InternalClient:
    return InternalClient(settings.GRPC_PAYMENT_TARGET, service=service)


def fraud_client(service=None) -> InternalClient:
    return InternalClient(settings.GRPC_FRAUD_TARGET, service=service)