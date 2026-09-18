# Spécifications fonctionnelles — canal DAB (lab)

> Simulation. Aucun automate physique. KaNest / HP ALM / ARGAUS / APTRA Vision / MXA / VTE sont **émulés**.

## Périmètre

SecurePay reste le **cœur** (tokenisation, fraude, COBOL, ledger). Le DAB est un **canal** de plus, comme l’e-commerce.

```
Simulateur KaNest-lite --ISO 8583 (0200)--> atm-adapter --décision--> 0210
                                              |              |
                                           MXA technique   VTE avis financier
                                              |              |
                                           ARGAUS parc     APTRA reporting
                                              └────── ALM + PV de recette ──┘
```

## Recettes

| ID | Type | Attendu |
|----|------|---------|
| ATM-RET-001 | Retrait 50 € | RC `00` |
| ATM-RET-002 | Retrait 600 000 € | RC `51` (insuffisant / COBOL) |
| ATM-DEP-V-001 | Dépôt **valorisé** | RC `00` + écriture ledger |
| ATM-DEP-NV-001 | Dépôt **non valorisé** | RC `00` + VTE `pending` + log MXA cassette |
| ATM-LSB-001 | **LSB** (Liste de Surveillance Bancaire) | RC `62` |

LSB ici = carte en watchlist lab (`4000000000000002`), pas un logiciel propriétaire.

## Constructeurs

Profils YAML : `ncr`, `diebold`, `wnx` (Wincor Nixdorf), `dn` (Diebold Nixdorf). Ils changent préfixe terminal, timeout, code MXA — pas le firmware.

## Routage lab

Réseau Docker `dab-net` (10.8.0.0/24). Seul `atm-adapter` est joignable depuis ce réseau. Timeout DAB plus strict que l’API web (profil `timeout_ms`).

## Journaux

- **MXA** : technique automate (`logs/mxa-technical.jsonl`)
- **VTE** : avis financiers (`logs/vte-financial.jsonl`)
- PAN masqué (PCI Req 3.3)

## Outils PFA (ce qui est simulé / ce qui ne l’est pas)

| Outil réel | Dans SecurePay |
|------------|----------------|
| KaNest (Galitt) | `atm/kanest/` recettes YAML |
| HP ALM | `atm/alm.py` + PV HTML |
| ARGAUS | `atm/argaus.py` parc 4 DAB |
| APTRA Vision (NCR) | `atm/aptra.py` |
| MXA / VTE | `atm/journals.py` |

Aucune licence constructeur n’est requise.
