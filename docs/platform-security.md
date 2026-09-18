# Platform security (Kubernetes)

## Admission

- Kyverno : `k8s-security/kyverno/` (no-root, no-privileged, limits, registries, labels, **image-scan gate**, no `:latest`)
- OPA Gatekeeper : `k8s-security/opa/constraints.yaml` (même posture Rego)

## Runtime

Falco : `k8s-security/falco/rules.yml` (shell, egress, secrets files, binaries, miner, Keycloak).

## Réseau / secrets / IaC

- Default-deny : `k8s-security/network-policies/default-deny.yml`
- Vault : `k8s-security/vault/`
- Lab k3s : `infra/k3s`
- Cloud : `infra/terraform`
- Helm : `infra/helm/securepay`

Quickstart k3d : commentaires en tête de `infra/k3s/kustomization.yaml`.
