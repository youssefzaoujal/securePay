"""CSPM — CIS AWS Foundations Benchmark (lab + scan Terraform + fixtures).

Sans credentials AWS : `python -m cspm --mode fixture` ou `--mode terraform`.
Avec credentials : `--mode aws`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cspm.report import write_reports
from cspm.scanner import run_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecurePay CSPM — CIS AWS Foundations")
    parser.add_argument("--mode", choices=["fixture", "terraform", "aws"], default="fixture")
    parser.add_argument("--fixture", default="cspm/fixtures/aws_inventory.json")
    parser.add_argument("--terraform", default="infra/terraform")
    parser.add_argument("--region", default="eu-west-1")
    parser.add_argument("--out", default="cspm/reports")
    args = parser.parse_args(argv)

    findings = run_scan(
        mode=args.mode,
        fixture_path=Path(args.fixture),
        terraform_dir=Path(args.terraform),
        region=args.region,
    )
    paths = write_reports(findings, Path(args.out))
    critical = sum(1 for item in findings if item["severity"] == "CRITICAL")
    high = sum(1 for item in findings if item["severity"] == "HIGH")
    print(json.dumps({"findings": len(findings), "critical": critical, "high": high, "reports": paths}, indent=2))
    return 1 if critical else 0


if __name__ == "__main__":
    sys.exit(main())
