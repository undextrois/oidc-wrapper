#!/usr/bin/env bash
set -euo pipefail

# Standalone Keycloak (no Docker) — same JVM you're already using for
# everything else. ~140MB download, ~300MB on disk extracted.

KC_VERSION="25.0.6"
KC_DIR="keycloak-${KC_VERSION}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"

if [ ! -d "$KC_DIR" ]; then
  echo "Downloading Keycloak ${KC_VERSION}..."
  curl -L -o keycloak.zip \
    "https://github.com/keycloak/keycloak/releases/download/${KC_VERSION}/keycloak-${KC_VERSION}.zip"
  unzip -q keycloak.zip
  rm keycloak.zip
fi

mkdir -p "${KC_DIR}/data/import"
cp realm-export.json "${KC_DIR}/data/import/kdy-demo-realm.json"

export KEYCLOAK_ADMIN=admin
export KEYCLOAK_ADMIN_PASSWORD=admin

echo "Starting Keycloak on http://localhost:8081 ..."
"${KC_DIR}/bin/kc.sh" start-dev --http-port=8081 --import-realm
