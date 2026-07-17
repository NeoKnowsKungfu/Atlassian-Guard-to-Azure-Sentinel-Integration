#!/bin/bash

set -e

source ./guard-sentinel.env

echo "Starting full deployment..."

echo "Ensuring Key Vault exists..."
az keyvault create \
  --name "$KV" \
  --resource-group "$LOGIC_APP_RG" \
  --location "$LOCATION" \
  --enable-rbac-authorization true \
  --enable-purge-protection true || true

echo "Ensuring webhook secret exists..."
if ! az keyvault secret show \
  --vault-name "$KV" \
  --name "$WEBHOOK_SECRET_NAME" >/dev/null 2>&1; then

  WEBHOOK_TOKEN=$(openssl rand -base64 32)

  az keyvault secret set \
    --vault-name "$KV" \
    --name "$WEBHOOK_SECRET_NAME" \
    --value "$WEBHOOK_TOKEN"

  echo "Created webhook token"
fi

echo "Deploying Logic App..."
az logic workflow create \
  --resource-group "$LOGIC_APP_RG" \
  --location "$LOCATION" \
  --name "$LOGIC_APP" \
  --definition ./logic-app-definition.json \
  --state Enabled

echo "Ensuring Managed Identity..."
az logic workflow identity assign \
  --resource-group "$LOGIC_APP_RG" \
  --name "$LOGIC_APP" \
  --system-assigned

echo "Deployment complete."
