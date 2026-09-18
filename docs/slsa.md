# SLSA / Sigstore (lab)

SecurePay vise une **forme SLSA niveau 2–3** sur les tags, pas une certification builder hébergé.

| Contrôle SLSA | Dans ce repo |
|---------------|--------------|
| Build scripté, versionné | GitHub Actions `ci.yml` / `cd.yml` |
| Provenance signée | `.github/workflows/slsa.yml` (générateur officiel SLSA 3, tags `v*`) |
| SBOM | Syft + Trivy CycloneDX dans CI |
| Signature d'image | Cosign keyless (OIDC GitHub) dans `cd.yml` |
| Attestation SBOM | `cosign attest --type cyclonedx` + Kyverno `verify-cosign.yml` |
| Vérification admission | Kyverno `verify-cosign.yml` (Audit en lab) |

Ce n'est **pas** un SLSA Build L3 isolé (pas de hosted builder hermétique sur chaque PR). En entretien : expliquer l'écart lab vs production (Rekor public, identity GitHub, Kyverno Enforce une fois les images signées).

Détail Cosign : [`supply-chain/cosign/README.md`](../supply-chain/cosign/README.md).
