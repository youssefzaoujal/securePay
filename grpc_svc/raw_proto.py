"""Serveur gRPC sans génération de stubs.

Un seul service unary : `securepay.internal.v1.Unary/Invoke` avec un message
{method: string, request_json: string}. Le handler route vers InternalService.
C'est une démonstration légère du backbone gRPC (latence faible, schéma fort)
sans build-time de stubs. En prod : remplacer par les stubs grpcio compilés
depuis protos/internal.proto (mêmes sémantiques).
"""

from __future__ import annotations

import json
import logging
from concurrent import futures

import grpc

logger = logging.getLogger("securepay.grpc.raw")

PACKAGE = "securepay.internal.v1"
SERVICE = "Unary"
METHOD = "Invoke"


class _UnaryServicer:
    def __init__(self, service):
        self._service = service

    def invoke(self, request_bytes: bytes) -> bytes:
        try:
            parsed = json.loads(request_bytes.decode("utf-8"))
            method = parsed.get("method", "")
            # la méthode est transportée après le '#'
            if "#" in method:
                method = method.split("#", 1)[1]
            payload = parsed.get("request_json") or parsed.get("request") or {}
            import asyncio

            result = asyncio.run(self._service.dispatch(method, payload))
            return json.dumps(result, default=str).encode("utf-8")
        except Exception as exc:  # noqa: BLE001
            logger.exception("erreur gRPC")
            return json.dumps({"error": str(exc)}).encode("utf-8")


def serve_raw(port: int, internal_service) -> None:
    """Démarre un thread gRPC servant le service unary générique (serveur simple)."""
    import threading

    from grpc._server import _add_generic_rpc_handlers, HandlerCallDetails, MethodHandler

    servicer = _UnaryServicer(internal_service)

    def dynamic_handler(details: HandlerCallDetails):
        if details.method.startswith(f"/{PACKAGE}."):
            return MethodHandler(
                request_streaming=False,
                response_streaming=False,
                request_deserializer=lambda b: b,
                response_serializer=lambda m: m,
                unary_unary=servicer.invoke,
                unary_stream=None,
                stream_unary=None,
                stream_stream=None,
            )
        return None

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    _add_generic_rpc_handlers(server, [dynamic_handler])
    server.add_insecure_port(f"0.0.0.0:{port}")
    server.start()
    logger.info("Serveur gRPC démarré sur :%s", port)
    threading.Event().wait()