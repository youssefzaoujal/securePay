# =============================================================================
# HashiCorp Vault Configuration for SecurePay
# Secrets Management (PCI-DSS Req 2.1, 3.5)
# =============================================================================

# Vault Policy: securepay-service
# Accès restreint aux secrets nécessaires au service
path "secret/data/securepay/*" {
  capabilities = ["read"]
}

path "secret/data/securepay/database" {
  capabilities = ["read"]
}

path "secret/data/securepay/encryption" {
  capabilities = ["read"]
}

path "secret/data/securepay/keycloak" {
  capabilities = ["read"]
}

# Pas d'écriture depuis les services (seul l'admin peut modifier)
path "secret/data/securepay/*" {
  capabilities = ["read", "list"]
}

# =============================================================================
# Vault Setup Script
# Exécuter une fois pour initialiser Vault avec les secrets SecurePay
# =============================================================================

# Initialiser Vault (une seule fois)
# vault operator init -key-shares=5 -key-threshold=3

# Créer un mount pour les secrets SecurePay
# vault secrets enable -path=secret kv-v2

# Insérer les secrets de la base de données
# vault kv put secret/securepay/database \
#   host="postgres.securepay.svc.cluster.local" \
#   port="5432" \
#   username="securepay" \
#   password="CHANGE_ME" \
#   database="securepay"

# Insérer les clés de chiffrement (tokenisation)
# vault kv put secret/securepay/encryption \
#   fernet_key="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
#   algorithm="AES-256-GCM"

# Insérer les credentials Keycloak
# vault kv put secret/securepay/keycloak \
#   admin_password="admin" \
#   client_secret="CHANGE_ME" \
#   realm="securepay"

# =============================================================================
# Vault Kubernetes Auth Method
# Permet aux pods Kubernetes d'authentifier via leur ServiceAccount
# =============================================================================

# Activer l'auth method Kubernetes
# vault auth enable kubernetes

# Configurer l'auth method
# vault write auth/kubernetes/config \
#   kubernetes_host="https://kubernetes.default.svc" \
#   kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Créer un rôle pour le gateway
# vault write auth/kubernetes/role/securepay-gateway \
#   bound_service_account_names=securepay-gateway \
#   bound_service_account_namespaces=securepay \
#   policies=securepay-service \
#   ttl=1h

# Créer un rôle pour le service payment
# vault write auth/kubernetes/role/securepay-payment \
#   bound_service_account_names=securepay-payment \
#   bound_service_account_namespaces=securepay \
#   policies=securepay-service \
#   ttl=1h
