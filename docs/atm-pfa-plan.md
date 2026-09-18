# Plan d’implémentation PFE — canal DAB + outils PFA

Livrable **déjà dans le repo** (lab). Ce tableau sert au rapport de stage.

| Phase | Action | Statut | Livrable |
|-------|--------|--------|----------|
| 1 | Translateur ISO 8583 0200/0210 | Fait | `atm/iso8583.py`, `atm/engine.py`, `atm/adapter.py` |
| 2 | Profils constructeurs NCR / Diebold / WNX / DN | Fait | `atm/profiles/*.yaml` |
| 3 | KaNest-lite (recettes DDT) | Fait | `atm/kanest/scenarios.yaml`, `runner.py` |
| 4 | Recettes retrait / dépôt V / NV / LSB | Fait | 5 scénarios + `tests/unit/test_atm_kanest.py` |
| 5 | PV de recette HTML | Fait | `atm/alm.py` → `logs/pv-recette-dab.html` |
| 6 | ALM-lite (NEW→CLOSED) | Fait | `/alm/defects` + Command Center onglet DAB |
| 7 | ARGAUS + APTRA Vision lite | Fait | `atm/argaus.py`, `atm/aptra.py` |
| 8 | Journaux MXA / VTE | Fait | `atm/journals.py` |
| 9 | Routage `dab-net` | Fait | profile compose `atm` |
| 10 | Specs fonctionnelles | Fait | `docs/functional-specs/dab.md` |

## Hors scope (volontaire)

- Licence KaNest, HP ALM, APTRA Vision, ARGAUS, firmware NCR/Diebold.
- Switch ISO 8583 certifié CB / Visa.
- Hardware GAB.

## Commandes

```powershell
python -m pytest tests/unit/test_atm_kanest.py -q
# optionnel :
docker compose --profile atm up -d --build
curl -X POST http://localhost:8016/kanest/run
```

Command Center : http://localhost:9000 → onglet **DAB / PFA**.
