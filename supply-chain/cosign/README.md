# Signature Cosign / Sigstore (lab)

La **clé privée n'est jamais commitée**. Cette `cosign.pub` est une clé lab de démonstration (Audit Kyverno).

En CI (`cd.yml`) : signature **keyless** + **attestation SBOM CycloneDX** (`cosign attest --type cyclonedx`).

Kyverno :

- Lab : `verify-cosign.yml` (**Audit**, n'empêche pas k3s local)
- Prod : `verify-cosign-enforce.yml` (**Enforce** signature + SBOM)

Générer votre paire (hors repo) :

```bash
cosign generate-key-pair
# coller cosign.pub dans k8s-security/kyverno/verify-cosign.yml
# passer validationFailureAction: Enforce une fois les images signées
```

Vérifier une image GHCR :

```bash
cosign verify ghcr.io/<org>/securepay/gateway:<sha> \
  --certificate-identity-regexp='https://github.com/.+' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```
