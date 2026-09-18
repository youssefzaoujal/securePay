# Contributing to SecurePay

SecurePay favors small, demonstrable changes: every feature should have a clear owner, a testable behavior, and an observable result.

## Local Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest tests/unit tests/security -q
```

For the full lab, copy `.env.example` to `.env` and follow the Docker profiles in the README.

## Before Opening a PR

```powershell
python -m py_compile dashboard.py
ruff check shared gateway payment tokenization fraud detection cspm legacy_core atm tests
pytest tests/unit tests/security -q
python scripts/pci_audit.py
```

For infrastructure changes, run Checkov or the relevant Terraform validation. For detection changes, include a fixture event and the expected Sigma result.

## Pull Requests

Use the PR template and describe the user or security behavior changed. Include test evidence, screenshots for UI changes, migration notes, and any new environment variables. Keep secrets, real payment data, and generated logs out of commits.

## Commit Style

Use a short imperative prefix such as `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, or `chore:`. Keep unrelated refactors out of feature commits.
