"""Orchestrateur CSPM — fixture (démo), Terraform (shift-left), AWS (boto3)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cspm.checks.iam import check_iam
from cspm.checks.s3 import check_s3
from cspm.checks.sg import check_security_groups
from cspm.checks.storage import check_ebs_and_trail
from cspm.checks.terraform_static import check_terraform


def run_scan(
    mode: str,
    fixture_path: Path,
    terraform_dir: Path,
    region: str = "eu-west-1",
) -> list[dict[str, Any]]:
    if mode == "terraform":
        return check_terraform(terraform_dir)
    if mode == "aws":
        inventory = _live_inventory(region)
        return _from_inventory(inventory)
    inventory = _load_fixture(fixture_path)
    return _from_inventory(inventory)


def _load_fixture(path: Path) -> dict[str, Any]:
    import json

    return json.loads(path.read_text(encoding="utf-8"))


def _from_inventory(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings.extend(check_iam(inventory.get("iam", {})))
    findings.extend(check_s3(inventory.get("s3", [])))
    findings.extend(check_security_groups(inventory.get("security_groups", [])))
    findings.extend(check_ebs_and_trail(inventory.get("ebs", []), inventory.get("cloudtrail", {})))
    return findings


def _live_inventory(region: str) -> dict[str, Any]:
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("boto3 requis pour --mode aws (pip install boto3)") from exc

    iam = boto3.client("iam")
    s3 = boto3.client("s3")
    ec2 = boto3.client("ec2", region_name=region)
    ct = boto3.client("cloudtrail", region_name=region)

    users = iam.list_users().get("Users", [])
    policies = []
    for user in users:
        attached = iam.list_attached_user_policies(UserName=user["UserName"]).get("AttachedPolicies", [])
        policies.append({"user": user["UserName"], "attached": [p["PolicyName"] for p in attached]})

    buckets = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        public = False
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            public = any(
                grant.get("Grantee", {}).get("URI", "").endswith("AllUsers")
                for grant in acl.get("Grants", [])
            )
        except Exception:
            public = False
        buckets.append({"name": name, "public": public})

    sgs = []
    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        sgs.append(
            {
                "id": sg["GroupId"],
                "name": sg.get("GroupName"),
                "ingress": sg.get("IpPermissions", []),
            }
        )

    volumes = [
        {"id": vol["VolumeId"], "encrypted": vol.get("Encrypted", False)}
        for vol in ec2.describe_volumes().get("Volumes", [])
    ]
    trails = ct.describe_trails().get("trailList", [])
    return {
        "iam": {
            "root_access_keys": False,
            "users": [{"name": u["UserName"]} for u in users],
            "admin_users": [p["user"] for p in policies if "AdministratorAccess" in p["attached"]],
        },
        "s3": buckets,
        "security_groups": sgs,
        "ebs": volumes,
        "cloudtrail": {"enabled": bool(trails), "trails": [t.get("Name") for t in trails]},
    }
