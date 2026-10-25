#!/bin/sh
# One-time Vault setup for the docker-compose.yml reference stack: enable
# the Transit engine and create the session-root signing key
# (internal/capability/vault.go's NewVaultSeedMinter needs it to exist
# before the proxy can mint its first root capability). A plain
# `vault server -dev` container does NOT do this on its own - dev mode only
# auto-unseals and enables the KV v2 engine at `secret/` by default.
#
# Runs to completion and exits; docker-compose.yml gates the proxy service
# on this script's success (service_completed_successfully), the same way
# the manual setup in docs/REFERENCE.md runs these two `vault` commands before starting
# the proxy by hand.
set -eu

export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"

echo "vault-init: waiting for vault to become reachable..."
until vault status >/dev/null 2>&1; do
  sleep 1
done
echo "vault-init: vault is up."

# Tolerant of "already enabled" so a restart against a Vault that somehow
# kept its state doesn't fail the whole stack - dev mode's storage is
# in-memory, so this is normally moot, but there's no reason for this
# script to be fragile about it.
vault secrets enable transit 2>&1 | grep -qi "already in use" \
  && echo "vault-init: transit engine already enabled" \
  || echo "vault-init: transit engine enabled"

vault write -f transit/keys/jit-session-root >/dev/null
echo "vault-init: jit-session-root transit key ready."
echo "vault-init: done."
