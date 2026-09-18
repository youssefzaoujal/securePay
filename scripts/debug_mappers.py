import httpx
import json

KEYCLOAK_URL = "http://localhost:8081"

# Login as admin
resp = httpx.post(
    f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
    data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"},
)
admin_token = resp.json()["access_token"]
headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}

# Get merchant-api client UUID
clients = httpx.get(f"{KEYCLOAK_URL}/admin/realms/securepay/clients?clientId=merchant-api", headers=headers).json()
client_id = clients[0]["id"]
print(f"Client UUID: {client_id}")

# Check if service account is enabled
client_detail = httpx.get(f"{KEYCLOAK_URL}/admin/realms/securepay/clients/{client_id}", headers=headers).json()
print(f"Service accounts enabled: {client_detail.get('serviceAccountsEnabled')}")
print(f"Direct access grants: {client_detail.get('directAccessGrantsEnabled')}")

# Get the service account user for merchant-api
sa_resp = httpx.get(f"{KEYCLOAK_URL}/admin/realms/securepay/clients/{client_id}/service-account-user", headers=headers)
print(f"\nService account user status: {sa_resp.status_code}")
if sa_resp.status_code == 200:
    sa_user = sa_resp.json()
    print(f"Service account username: {sa_user.get('username')}")
    print(f"Service account ID: {sa_user.get('id')}")
    sa_id = sa_user.get('id')

    # Get realm roles available for this service account
    roles_resp = httpx.get(f"{KEYCLOAK_URL}/admin/realms/securepay/users/{sa_id}/role-mappings/realm", headers=headers)
    print(f"\nCurrent realm roles: {json.dumps(roles_resp.json(), indent=2)}")

    # Get all realm roles
    all_roles = httpx.get(f"{KEYCLOAK_URL}/admin/realms/securepay/roles", headers=headers).json()
    print(f"\nAll realm roles: {[r['name'] for r in all_roles]}")

    # Assign merchant role to service account
    merchant_role = [r for r in all_roles if r['name'] == 'merchant']
    if merchant_role:
        r = httpx.post(
            f"{KEYCLOAK_URL}/admin/realms/securepay/users/{sa_id}/role-mappings/realm",
            headers=headers,
            json=[{"id": merchant_role[0]['id'], "name": merchant_role[0]['name']}],
        )
        print(f"\nAssigned 'merchant' role: {r.status_code}")

# Now try the mapper again - but for service accounts we need hardcoded-role-mapper
# or user-attribute-mapper that doesn't depend on user model

# First, let's check available protocol mappers types
print("\n--- Trying to add mappers ---")

# For client_credentials, we should use hardcoded role mapper
# or just check what the existing JWT claims are

# Actually, the simplest approach: configure the client to include roles via client scopes
# Let's check the default client scopes
scopes = httpx.get(f"{KEYCLOAK_URL}/admin/realms/securepay/clients/{client_id}/default-client-scopes", headers=headers).json()
print(f"\nDefault client scopes: {[s.get('name') for s in scopes]}")

# Add a role list mapper that works with service accounts
mapper = {
    "name": "realm-roles-mapper",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-realm-role-list-mapper",
    "config": {
        "multivalued": ["true"],
        "claim.name": ["realm_access.roles"],
        "id.token.claim": ["true"],
        "access.token.claim": ["true"],
        "userinfo.token.claim": ["true"],
    },
}

r = httpx.post(
    f"{KEYCLOAK_URL}/admin/realms/securepay/clients/{client_id}/protocol-mappers/models",
    headers=headers,
    json=mapper,
)
print(f"\nrealm-roles-mapper (list): {r.status_code} {r.text[:200]}")
