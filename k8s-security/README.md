# Kubernetes security pack (Module C)

Appliquer **après** Kyverno / Gatekeeper / Falco / Vault :

```bash
kubectl apply -f k8s-security/kyverno/
kubectl apply -f k8s-security/opa/
kubectl apply -f k8s-security/network-policies/
kubectl apply -f k8s-security/namespaces/tenants.yml
kubectl apply -f k8s-security/vault/injector-example.yml
```

- Cosign (Audit lab) : `kyverno/verify-cosign.yml`
- Multi-tenant : namespaces `tenant-acme` / `tenant-globex` + NetworkPolicy isolation
- Core COBOL : `network-policies/legacy-core.yml` (ingress **payment only**)
- Cosign + SBOM Enforce (prod) : `kyverno/verify-cosign-enforce.yml`

Falco custom rules : `falco/rules.yml` (helm `--set-file customRules=`).

Voir `docs/platform-security.md` et le quickstart dans `infra/k3s/kustomization.yaml`.
