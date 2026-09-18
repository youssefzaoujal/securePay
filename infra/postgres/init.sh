#!/bin/bash
set -e

# Créer la base et l'utilisateur pour Keycloak
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER keycloak WITH PASSWORD 'keycloak_dev';
    CREATE DATABASE keycloak OWNER keycloak;
    GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
EOSQL

# Créer la base de données pour les tests
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE securepay_test OWNER securepay;
EOSQL

echo "Databases initialized successfully"
