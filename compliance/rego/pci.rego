# Règles OPA (Open Policy Agent) — politique PCI-DSS v4.0.1 (phase 3).
# Standard minimale : tout déploiement dans 'prod' doit satisfaire ces règles.
# (Le lab n'exécute pas OPA : compliance/assess.py réplique ces règles en Python.)

package securepay.pci

import rego.v1

default allow = false

# Tout Pod doit porter les labels attendus (PCI-DSS 1.4 – segmentation)
required_labels := {"app", "tier", "namespace.securepay.dev"}

missing_label(pod) := label {
    label := required_labels[_]
    not pod.metadata.labels[label]
}

pod_label_violation[pod] {
    pod := input.review.object
    missing_label(pod)
} else {
    pod := input.review.object
    pod.spec.containers[_].image
}

# Deny by default : toute violation de label est un deny
deny contains {"msg": sprintf("pod absent des labels attendus: %v", [missing_label(input.review.object)])} {
    pod_label_violation[input.review.object]
}

# Pas de privilège root (PCI-DSS 8.4.2 / défense en profondeur)
deny contains {"msg": "conteneur en root: runAsNonRoot requis"} {
    some container
    input.review.object.spec.containers[container].securityContext.runAsNonRoot != true
}

# Images non signées (SLSA v1.0 / cosign)
deny contains {"msg": "image non signée (cosign requis)"} {
    some container
    not input.review.object.metadata.annotations["cosign.dsse.dev/verified"]
    input.review.object.spec.containers[container]
}

# Pas de secret en dur dans une env var (PCI-DSS 8.5)
deny contains {"msg": "secret en clair interdit : utiliser secretKeyRef"} {
    some container
    env := input.review.object.spec.containers[container].env[i]
    env.value != ""
}