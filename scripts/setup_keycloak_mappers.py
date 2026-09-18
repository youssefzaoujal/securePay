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

# Check existing mappers
existing = httpx.get(f"{KEYCLOAK_URL}/admin/realms/securepay/clients/{client_id}/protocol-mappers/models", headers=headers).json()
if isinstance(existing, dict):
    mapper_list = existing.get("mappers", [])
else:
    mapper_list = existing
print(f"Existing mappers: {[(m.get('name','?'), m.get('id','?')) for m in mapper_list]}")

# Delete all existing mappers
for m in mapper_list:
    mid = m.get("id")
    name = m.get("name", "?")
    if mid:
        r = httpx.delete(f"{KEYCLOAK_URL}/admin/realms/securepay/clients/{client_id}/protocol-mappers/models/{mid}", headers=headers)
        print(f"  Deleted '{name}': {r.status_code}")

# Add mapper 1: realm_access.roles
mapper1 = {
    "name": "realm-roles-mapper",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-realm-role-mapper",
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
    json=mapper1,
)
print(f"\nroles-mapper: {r.status_code} {r.text[:200]}")

# Add mapper 2: merchant_id from user attribute
mapper2 = {
    "name": "merchant-id-mapper",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "config": {
        "user.attribute": ["merchant_id"],
        "claim.name": ["merchant_id"],
        "id.token.claim": ["true"],
        "access.token.claim": ["true"],
        "userinfo.token.claim": ["true"],
    },
}
r = httpx.post(
    f"{KEYCLOAK_URL}/admin/realms/securepay/clients/{client_id}/protocol-mappers/models",
    headers=headers,
    json=mapper2,
)
print(f"merchant-id-mapper: {r.status_code} {r.text[:200]}")

# Verify
existing = httpx.get(f"{KEYCLOAK_URL}/admin/realms/securepay/clients/{client_id}/protocol-mappers/models", headers=headers).json()
if isinstance(existing, dict):
    final_list = existing.get("mappers", [])
else:
    final_list = existing
print(f"\nFinal mappers: {[m.get('name','?') for m in final_list]}")
