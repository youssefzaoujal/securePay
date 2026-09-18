import sys, os, json, random, uuid, asyncio
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path("./detection/simulator/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

def log_event(event):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    event["source"] = "securepay-attack-simulator"
    log_file = LOG_DIR / f"events_{datetime.now().strftime('%Y%m%d')}.jsonl"
    with open(log_file, "a") as f:
        f.write(json.dumps(event) + "\n")

def simulate_carding(n=25):
    ip = "10.0.0.66"
    print(f"\n  [CARDING] {n} tentatives depuis {ip}")
    for i in range(n):
        log_event({
            "event_type": "payment_attempt",
            "scenario": "card_testing",
            "source_ip": ip,
            "card_token": f"tok_{uuid.uuid4().hex[:16]}",
            "amount": round(random.uniform(5, 5000), 2),
            "status": "failed",
            "merchant_id": "MERCH_001",
        })
    log_event({
        "event_type": "carding_summary",
        "scenario": "card_testing",
        "source_ip": ip,
        "total_attempts": n,
        "failed_count": n,
        "detection_signal": "high_volume_failed_payments",
    })
    print(f"  OK - {n} evenements generes")

def simulate_credential_stuffing(n=25):
    ip = "10.0.0.77"
    usernames = ["admin", "merchant1", "test", "user", "root", "dev"]
    print(f"\n  [CREDENTIAL STUFFING] {n} tentatives depuis {ip}")
    for i in range(n):
        log_event({
            "event_type": "authentication_attempt",
            "scenario": "credential_stuffing",
            "source_ip": ip,
            "username": random.choice(usernames),
            "status": "failed",
        })
    log_event({
        "event_type": "credential_stuffing_summary",
        "scenario": "credential_stuffing",
        "source_ip": ip,
        "total_attempts": n,
        "detection_signal": "rapid_auth_failures",
    })
    print(f"  OK - {n} evenements generes")

def simulate_bola(n=10):
    ip = "10.0.0.88"
    print(f"\n  [BOLA] {n} tentatives cross-merchant depuis {ip}")
    for i in range(n):
        log_event({
            "event_type": "authorization_error",
            "scenario": "bola",
            "source_ip": ip,
            "merchant_id": "MERCH_001",
            "target_merchant_id": f"MERCH_{random.randint(100,999):03d}",
            "error_type": "object_level_authorization",
            "http_method": "GET",
            "http_path": f"/api/v1/merchants/MERCH_{random.randint(100,999):03d}/transactions/pay_{uuid.uuid4().hex[:8]}",
            "status_code": 403,
        })
    log_event({
        "event_type": "bola_summary",
        "scenario": "bola",
        "source_ip": ip,
        "total_attempts": n,
        "detection_signal": "cross_merchant_access_denied",
    })
    print(f"  OK - {n} evenements generes")

print("=" * 50)
print("  SECUREPAY - SIMULATEUR D'ATTAQUES")
print("=" * 50)

simulate_carding(25)
simulate_credential_stuffing(25)
simulate_bola(10)

print("\n" + "=" * 50)
print("  LOGS ECRITS DANS: detection/simulator/logs/")
print("=" * 50)

# Lire et afficher les stats
log_file = LOG_DIR / f"events_{datetime.now().strftime('%Y%m%d')}.jsonl"
with open(log_file) as f:
    lines = [json.loads(l) for l in f.readlines()]

scenarios = {}
for e in lines:
    s = e.get("scenario", "system")
    if s not in scenarios:
        scenarios[s] = {"count": 0, "ips": set()}
    scenarios[s]["count"] += 1
    if "source_ip" in e:
        scenarios[s]["ips"].add(e["source_ip"])

print(f"\nTotal evenements: {len(lines)}")
for s, data in scenarios.items():
    print(f"  {s}: {data['count']} evenements, {len(data['ips'])} IP(s)")

print("\nTOURNE OK !")
