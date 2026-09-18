"""Blocklist SOAR — fichier + Redis optionnel. Consommé par le gateway."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def _block_file() -> Path:
    return Path(os.getenv("SECUREPAY_BLOCKLIST", "logs/blocked-ips.jsonl"))


def _state_file() -> Path:
    return Path(os.getenv("SECUREPAY_BLOCKSTATE", "logs/blocked-ips-state.json"))


def _load_state() -> dict[str, dict[str, Any]]:
    path = _state_file()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _save_state(state: dict[str, dict[str, Any]]) -> None:
    path = _state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def block_ip(ip: str, reason: str, ttl_seconds: int = 3600, alert: dict | None = None) -> dict[str, Any]:
    if not ip:
        return {"blocked": False, "reason": "empty_ip"}
    now = time.time()
    state = _load_state()
    entry = {
        "ip": ip,
        "reason": reason,
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": now + ttl_seconds,
        "alert": alert or {},
        "source": "securepay-soar",
    }
    state[ip] = entry
    _save_state(state)
    _sync_gauge(state)
    path = _block_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, default=str) + "\n")
    return {"blocked": True, "ip": ip, "ttl": ttl_seconds, "reason": reason}


def unblock_ip(ip: str) -> bool:
    state = _load_state()
    if ip not in state:
        return False
    del state[ip]
    _save_state(state)
    _sync_gauge(state)
    return True


def is_blocked(ip: str) -> bool:
    if not ip:
        return False
    state = _load_state()
    entry = state.get(ip)
    if not entry:
        return False
    if time.time() > float(entry.get("expires_at", 0)):
        unblock_ip(ip)
        return False
    return True


def list_blocks() -> list[dict[str, Any]]:
    now = time.time()
    state = _load_state()
    live = []
    expired = []
    for ip, entry in state.items():
        if now > float(entry.get("expires_at", 0)):
            expired.append(ip)
        else:
            live.append(entry)
    for ip in expired:
        unblock_ip(ip)
    _sync_gauge(_load_state())
    return live


def _sync_gauge(state: dict[str, dict[str, Any]] | None = None) -> None:
    try:
        from shared.metrics import SOAR_BLOCKS

        SOAR_BLOCKS.set(len(state if state is not None else _load_state()))
    except Exception:
        return
