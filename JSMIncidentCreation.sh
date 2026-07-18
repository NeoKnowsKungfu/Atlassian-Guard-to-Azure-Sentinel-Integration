#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Microsoft Sentinel -> Jira Service Management Incident Ticket Creation
# Atlassian Guard Detect final-stage automation
###############################################################################

echo "=== 0. Variables ==="

export SUBSCRIPTION_ID="d37bb853-36e2-46de-83a0-ed7161c8eb12"

# Resource groups
export SENTINEL_RG="RG_MCS_Sentinel"
export INTEGRATION_RG="atlassianguard2sentinel"

# Sentinel / Log Analytics
export WORKSPACE_NAME="MCS-343-SentinelWorkspace"
export CUSTOM_TABLE="atlassian_guard_detect_CL"

# Existing ingestion Logic App
export INGESTION_LOGIC_APP="AtlassianGuard2Sentinel"

# New playbook Logic App
export PLAYBOOK_NAME="SentinelIncident-To-JSM-Incident"
export LOCATION="eastus"

# Existing Key Vault
export KV_NAME="kv-atlguard-hs-prod"

# Jira / JSM
export JIRA_SITE="https://343industries.atlassian.net"
export JIRA_PROJECT_KEY="DCCSUP"
export JIRA_ISSUE_TYPE="Incident"
export JIRA_API_EMAIL="cybersquad@halostudios.com"

# Key Vault secret names
export JIRA_EMAIL_SECRET_NAME="jira-api-email"
export JIRA_TOKEN_SECRET_NAME="jira-api-token"

# Sentinel rule names
export ANALYTICS_RULE_NAME="Atlassian Guard Detect - Create JSM Incident"
export AUTOMATION_RULE_NAME="Run JSM Incident Playbook for Atlassian Guard Detect"

az account set --subscription "$SUBSCRIPTION_ID"

export TENANT_ID=$(az account show --query tenantId -o tsv)

echo "Subscription: $SUBSCRIPTION_ID"
echo "Tenant:       $TENANT_ID"
echo "Workspace:   $WORKSPACE_NAME"
echo "Playbook:    $PLAYBOOK_NAME"
echo "Jira site:   $JIRA_SITE"
echo "JSM project: $JIRA_PROJECT_KEY"

###############################################################################
# 1. Confirm base resources
###############################################################################

echo "=== 1. Confirming workspace and Key Vault ==="

export WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group "$SENTINEL_RG" \
  --workspace-name "$WORKSPACE_NAME" \
  --query customerId \
  -o tsv)

export WORKSPACE_ARM_ID=$(az monitor log-analytics workspace show \
  --resource-group "$SENTINEL_RG" \
  --workspace-name "$WORKSPACE_NAME" \
  --query id \
  -o tsv)

export KV_ID=$(az keyvault show \
  --name "$KV_NAME" \
  --resource-group "$INTEGRATION_RG" \
  --query id \
  -o tsv)

echo "WORKSPACE_ID=$WORKSPACE_ID"
echo "WORKSPACE_ARM_ID=$WORKSPACE_ARM_ID"
echo "KV_ID=$KV_ID"

###############################################################################
# 2. Store Jira credentials in Key Vault
###############################################################################

echo "=== 2. Storing Jira API credentials in Key Vault ==="

export CURRENT_USER_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)

echo "Ensuring current user can write Key Vault secrets..."
az role assignment create \
  --assignee "$CURRENT_USER_OBJECT_ID" \
  --role "Key Vault Secrets Officer" \
  --scope "$KV_ID" >/dev/null 2>&1 || true

echo "Storing Jira API email..."
az keyvault secret set \
  --vault-name "$KV_NAME" \
  --name "$JIRA_EMAIL_SECRET_NAME" \
  --value "$JIRA_API_EMAIL" \
  --output none

echo
read -s -p "Paste Jira API token for $JIRA_API_EMAIL: " JIRA_API_TOKEN
echo

if [ -z "$JIRA_API_TOKEN" ]; then
  echo "ERROR: Jira API token cannot be empty."
  exit 1
fi

echo "Storing Jira API token..."
az keyvault secret set \
  --vault-name "$KV_NAME" \
  --name "$JIRA_TOKEN_SECRET_NAME" \
  --value "$JIRA_API_TOKEN" \
  --output none

unset JIRA_API_TOKEN

###############################################################################
# 3. Create Microsoft Sentinel API connection + Logic App playbook
###############################################################################

echo "=== 3. Creating Logic App playbook ARM template ==="

cat > sentinel-jsm-playbook-template.json <<'EOF'
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "playbookName": { "type": "string" },
    "location": { "type": "string" },
    "jiraSite": { "type": "string" },
    "jiraProjectKey": { "type": "string" },
    "jiraIssueType": { "type": "string" },
    "keyVaultName": { "type": "string" },
    "jiraEmailSecretName": { "type": "string" },
    "jiraTokenSecretName": { "type": "string" }
  },
  "variables": {
    "sentinelConnectionName": "[concat(parameters('playbookName'), '-azuresentinel')]"
  },
  "resources": [
    {
      "type": "Microsoft.Web/connections",
      "apiVersion": "2016-06-01",
      "name": "[variables('sentinelConnectionName')]",
      "location": "[parameters('location')]",
      "properties": {
        "displayName": "[variables('sentinelConnectionName')]",
        "api": {
          "id": "[subscriptionResourceId('Microsoft.Web/locations/managedApis', parameters('location'), 'azuresentinel')]"
        }
      }
    },
    {
      "type": "Microsoft.Logic/workflows",
      "apiVersion": "2019-05-01",
      "name": "[parameters('playbookName')]",
      "location": "[parameters('location')]",
      "identity": {
        "type": "SystemAssigned"
      },
      "dependsOn": [
        "[resourceId('Microsoft.Web/connections', variables('sentinelConnectionName'))]"
      ],
      "properties": {
        "state": "Enabled",
        "definition": {
          "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
          "contentVersion": "1.0.0.0",
          "parameters": {
            "$connections": { "type": "Object" },
            "jiraSite": { "type": "String" },
            "jiraProjectKey": { "type": "String" },
            "jiraIssueType": { "type": "String" },
            "keyVaultName": { "type": "String" },
            "jiraEmailSecretName": { "type": "String" },
            "jiraTokenSecretName": { "type": "String" }
          },
          "triggers": {
            "Microsoft_Sentinel_incident": {
              "type": "ApiConnectionWebhook",
              "inputs": {
                "host": {
                  "connection": {
                    "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                  }
                },
                "body": {
                  "callback_url": "@{listCallbackUrl()}"
                },
                "path": "/incident-creation"
              }
            }
          },
          "actions": {
            "Compose_Custom_Details": {
              "type": "Compose",
              "inputs": "@json(coalesce(first(coalesce(triggerBody()?['object']?['properties']?['Alerts'], triggerBody()?['incidentUpdates']?['alerts'], createArray(json('{}'))))?['properties']?['additionalData']?['Custom Details'], '{}'))",
              "runAfter": {}
            },
            "Compose_Jira_Priority": {
              "type": "Compose",
              "inputs": "@if(equals(triggerBody()?['object']?['properties']?['severity'], 'High'), 'High', if(equals(triggerBody()?['object']?['properties']?['severity'], 'Medium'), 'Medium', 'Low'))",
              "runAfter": {
                "Compose_Custom_Details": [ "Succeeded" ]
              }
            },
            "Get_Jira_API_Email": {
              "type": "Http",
              "inputs": {
                "method": "GET",
                "uri": "@{concat('https://', parameters('keyVaultName'), '.vault.azure.net/secrets/', parameters('jiraEmailSecretName'), '?api-version=7.4')}",
                "authentication": {
                  "type": "ManagedServiceIdentity",
                  "audience": "https://vault.azure.net"
                }
              },
              "runAfter": {
                "Compose_Jira_Priority": [ "Succeeded" ]
              },
              "runtimeConfiguration": {
                "secureData": {
                  "properties": [ "inputs", "outputs" ]
                }
              }
            },
            "Get_Jira_API_Token": {
              "type": "Http",
              "inputs": {
                "method": "GET",
                "uri": "@{concat('https://', parameters('keyVaultName'), '.vault.azure.net/secrets/', parameters('jiraTokenSecretName'), '?api-version=7.4')}",
                "authentication": {
                  "type": "ManagedServiceIdentity",
                  "audience": "https://vault.azure.net"
                }
              },
              "runAfter": {
                "Get_Jira_API_Email": [ "Succeeded" ]
              },
              "runtimeConfiguration": {
                "secureData": {
                  "properties": [ "inputs", "outputs" ]
                }
              }
            },
            "Compose_Basic_Auth_Header": {
              "type": "Compose",
              "inputs": "@concat('Basic ', base64(concat(body('Get_Jira_API_Email')?['value'], ':', body('Get_Jira_API_Token')?['value'])))",
              "runAfter": {
                "Get_Jira_API_Token": [ "Succeeded" ]
              },
              "runtimeConfiguration": {
                "secureData": {
                  "properties": [ "inputs", "outputs" ]
                }
              }
            },
            "Create_JSM_Incident": {
              "type": "Http",
              "inputs": {
                "method": "POST",
                "uri": "@{concat(parameters('jiraSite'), '/rest/api/3/issue')}",
                "headers": {
                  "Accept": "application/json",
                  "Content-Type": "application/json",
                  "Authorization": "@{outputs('Compose_Basic_Auth_Header')}"
                },
                "body": {
                  "fields": {
                    "project": {
                      "key": "@{parameters('jiraProjectKey')}"
                    },
                    "issuetype": {
                      "name": "@{parameters('jiraIssueType')}"
                    },
                    "summary": "@{concat('Atlassian Guard Detect: ', coalesce(outputs('Compose_Custom_Details')?['GuardAlertTitle'], triggerBody()?['object']?['properties']?['title'], 'Sentinel Incident'))}",
                    "priority": {
                      "name": "@{outputs('Compose_Jira_Priority')}"
                    },
                    "description": {
                      "type": "doc",
                      "version": 1,
                      "content": [
                        {
                          "type": "heading",
                          "attrs": { "level": 2 },
                          "content": [
                            {
                              "type": "text",
                              "text": "Atlassian Guard Detect alert from Microsoft Sentinel"
                            }
                          ]
                        },
                        {
                          "type": "paragraph",
                          "content": [
                            {
                              "type": "text",
                              "text": "@{concat('Sentinel incident severity: ', triggerBody()?['object']?['properties']?['severity'])}"
                            }
                          ]
                        },
                        {
                          "type": "paragraph",
                          "content": [
                            {
                              "type": "text",
                              "text": "@{concat('Activity/action: ', coalesce(outputs('Compose_Custom_Details')?['GuardActivityAction'], 'N/A'))}"
                            }
                          ]
                        },
                        {
                          "type": "paragraph",
                          "content": [
                            {
                              "type": "text",
                              "text": "@{concat('Actor: ', coalesce(outputs('Compose_Custom_Details')?['GuardActorName'], 'N/A'), ' / ', coalesce(outputs('Compose_Custom_Details')?['GuardActorAccountId'], 'N/A'))}"
                            }
                          ]
                        },
                        {
                          "type": "paragraph",
                          "content": [
                            {
                              "type": "text",
                              "text": "@{concat('Event type: ', coalesce(outputs('Compose_Custom_Details')?['GuardEventType'], 'N/A'))}"
                            }
                          ]
                        },
                        {
                          "type": "paragraph",
                          "content": [
                            {
                              "type": "text",
                              "text": "Sentinel incident: "
                            },
                            {
                              "type": "text",
                              "text": "@{triggerBody()?['object']?['properties']?['incidentUrl']}",
                              "marks": [
                                {
                                  "type": "link",
                                  "attrs": {
                                    "href": "@{triggerBody()?['object']?['properties']?['incidentUrl']}"
                                  }
                                }
                              ]
                            }
                          ]
                        },
                        {
                          "type": "paragraph",
                          "content": [
                            {
                              "type": "text",
                              "text": "Atlassian Guard alert: "
                            },
                            {
                              "type": "text",
                              "text": "@{coalesce(outputs('Compose_Custom_Details')?['GuardAlertUrl'], outputs('Compose_Custom_Details')?['GuardAlertDetailUrl'], 'N/A')}",
                              "marks": [
                                {
                                  "type": "link",
                                  "attrs": {
                                    "href": "@{coalesce(outputs('Compose_Custom_Details')?['GuardAlertUrl'], outputs('Compose_Custom_Details')?['GuardAlertDetailUrl'], parameters('jiraSite'))}"
                                  }
                                }
                              ]
                            }
                          ]
                        }
                      ]
                    }
                  }
                }
              },
              "runAfter": {
                "Compose_Basic_Auth_Header": [ "Succeeded" ]
              },
              "runtimeConfiguration": {
                "secureData": {
                  "properties": [ "inputs" ]
                }
              }
            }
          },
          "outputs": {}
        },
        "parameters": {
          "jiraSite": { "value": "[parameters('jiraSite')]" },
          "jiraProjectKey": { "value": "[parameters('jiraProjectKey')]" },
          "jiraIssueType": { "value": "[parameters('jiraIssueType')]" },
          "keyVaultName": { "value": "[parameters('keyVaultName')]" },
          "jiraEmailSecretName": { "value": "[parameters('jiraEmailSecretName')]" },
          "jiraTokenSecretName": { "value": "[parameters('jiraTokenSecretName')]" },
          "$connections": {
            "value": {
              "azuresentinel": {
                "connectionId": "[resourceId('Microsoft.Web/connections', variables('sentinelConnectionName'))]",
                "connectionName": "[variables('sentinelConnectionName')]",
                "id": "[subscriptionResourceId('Microsoft.Web/locations/managedApis', parameters('location'), 'azuresentinel')]",
                "connectionProperties": {
                  "authentication": {
                    "type": "ManagedServiceIdentity"
                  }
                }
              }
            }
          }
        }
      }
    }
  ],
  "outputs": {
    "logicAppResourceId": {
      "type": "string",
      "value": "[resourceId('Microsoft.Logic/workflows', parameters('playbookName'))]"
    }
  }
}
EOF

echo "Deploying playbook..."
az deployment group create \
  --resource-group "$INTEGRATION_RG" \
  --template-file sentinel-jsm-playbook-template.json \
  --parameters \
    playbookName="$PLAYBOOK_NAME" \
    location="$LOCATION" \
    jiraSite="$JIRA_SITE" \
    jiraProjectKey="$JIRA_PROJECT_KEY" \
    jiraIssueType="$JIRA_ISSUE_TYPE" \
    keyVaultName="$KV_NAME" \
    jiraEmailSecretName="$JIRA_EMAIL_SECRET_NAME" \
    jiraTokenSecretName="$JIRA_TOKEN_SECRET_NAME" \
  -o table

export PLAYBOOK_ID=$(az resource show \
  --name "$PLAYBOOK_NAME" \
  --resource-group "$INTEGRATION_RG" \
  --resource-type "Microsoft.Logic/workflows" \
  --query id \
  -o tsv)

export PLAYBOOK_PRINCIPAL_ID=$(az resource show \
  --ids "$PLAYBOOK_ID" \
  --query identity.principalId \
  -o tsv)

echo "PLAYBOOK_ID=$PLAYBOOK_ID"
echo "PLAYBOOK_PRINCIPAL_ID=$PLAYBOOK_PRINCIPAL_ID"

###############################################################################
# 4. RBAC for playbook identity
###############################################################################

echo "=== 4. Assigning RBAC to playbook identity ==="

echo "Granting Key Vault Secrets User..."
az role assignment create \
  --assignee "$PLAYBOOK_PRINCIPAL_ID" \
  --role "Key Vault Secrets User" \
  --scope "$KV_ID" >/dev/null 2>&1 || true

echo "Granting Microsoft Sentinel Responder on workspace..."
az role assignment create \
  --assignee "$PLAYBOOK_PRINCIPAL_ID" \
  --role "Microsoft Sentinel Responder" \
  --scope "$WORKSPACE_ARM_ID" >/dev/null 2>&1 || true

echo "Granting Sentinel automation service permission to run playbooks..."
export SENTINEL_AUTOMATION_SP_ID=$(az ad sp list \
  --display-name "Azure Security Insights" \
  --query "[0].id" \
  -o tsv)

if [ -n "$SENTINEL_AUTOMATION_SP_ID" ]; then
  az role assignment create \
    --assignee "$SENTINEL_AUTOMATION_SP_ID" \
    --role "Microsoft Sentinel Automation Contributor" \
    --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$INTEGRATION_RG" >/dev/null 2>&1 || true
else
  echo "WARNING: Could not find Azure Security Insights service principal by display name."
  echo "If automation rule cannot run the playbook, grant Microsoft Sentinel Automation Contributor to the Sentinel service account on $INTEGRATION_RG from the portal."
fi

###############################################################################
# 5. Create Sentinel analytics rule
###############################################################################

echo "=== 5. Creating Microsoft Sentinel analytics rule ==="

export ANALYTICS_RULE_ID=$(uuidgen)

cat > atlassian-guard-jsm-analytics-rule.json <<EOF
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "$ANALYTICS_RULE_NAME",
    "description": "Creates a Sentinel alert and incident for Atlassian Guard Detect records ingested into atlassian_guard_detect_CL.",
    "severity": "Medium",
    "enabled": true,
    "query": "let Lookback = 10m;\\natlassian_guard_detect_CL\\n| where TimeGenerated >= ago(Lookback)\\n| extend GuardAlertId = tostring(AlertId), GuardAlertTitle = tostring(AlertTitle), GuardAlertUrl = tostring(AlertUrl), GuardAlertDetailUrl = tostring(AlertDetailURL), GuardActivityAction = tostring(ActivityAction), GuardActorName = tostring(ActorName), GuardActorAccountId = tostring(ActorAccountId), GuardEventType = tostring(EventType), GuardSite = tostring(AlertSite), GuardProduct = tostring(AlertProduct), GuardWorkspaceId = tostring(WorkspaceId)\\n| extend NormalizedSeverity = case(GuardActivityAction has_any (\\\"admin\\\", \\\"permission\\\", \\\"privilege\\\", \\\"policy\\\", \\\"token\\\", \\\"export\\\", \\\"download\\\", \\\"exfil\\\", \\\"external\\\", \\\"public\\\", \\\"sharing\\\", \\\"suspicious\\\"), \\\"High\\\", GuardActivityAction has_any (\\\"login\\\", \\\"failed\\\", \\\"created\\\", \\\"updated\\\", \\\"changed\\\", \\\"access\\\", \\\"session\\\"), \\\"Medium\\\", \\\"Low\\\")\\n| extend AlertDisplayName = strcat(\\\"Atlassian Guard Detect: \\\", coalesce(GuardAlertTitle, GuardActivityAction, GuardEventType, GuardAlertId)), AlertDescription = strcat(\\\"Atlassian Guard Detect alert from \\\", GuardSite, \\\"\\\\nActivityAction: \\\", GuardActivityAction, \\\"\\\\nActor: \\\", GuardActorName, \\\"\\\\nGuard Alert URL: \\\", GuardAlertUrl)\\n| project TimeGenerated, AlertDisplayName, AlertDescription, NormalizedSeverity, GuardAlertId, GuardAlertTitle, GuardAlertUrl, GuardAlertDetailUrl, GuardActivityAction, GuardActorName, GuardActorAccountId, GuardEventType, GuardSite, GuardProduct, GuardWorkspaceId",
    "queryFrequency": "PT5M",
    "queryPeriod": "PT10M",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "eventGroupingSettings": {
      "aggregationKind": "AlertPerResult"
    },
    "incidentConfiguration": {
      "createIncident": true,
      "groupingConfiguration": {
        "enabled": false,
        "reopenClosedIncident": false,
        "lookbackDuration": "PT5H",
        "matchingMethod": "AllEntities",
        "groupByEntities": [],
        "groupByAlertDetails": [],
        "groupByCustomDetails": []
      }
    },
    "customDetails": {
      "GuardAlertId": "GuardAlertId",
      "GuardAlertTitle": "GuardAlertTitle",
      "GuardAlertUrl": "GuardAlertUrl",
      "GuardAlertDetailUrl": "GuardAlertDetailUrl",
      "GuardActivityAction": "GuardActivityAction",
      "GuardActorName": "GuardActorName",
      "GuardActorAccountId": "GuardActorAccountId",
      "GuardEventType": "GuardEventType",
      "GuardSite": "GuardSite",
      "GuardProduct": "GuardProduct",
      "NormalizedSeverity": "NormalizedSeverity"
    },
    "alertDetailsOverride": {
      "alertDisplayNameFormat": "{{AlertDisplayName}}",
      "alertDescriptionFormat": "{{AlertDescription}}",
      "alertSeverityColumnName": "NormalizedSeverity"
    },
    "tactics": [
      "Collection",
      "Exfiltration"
    ]
  }
}
EOF

az rest \
  --method put \
  --url "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE_NAME/providers/Microsoft.SecurityInsights/alertRules/$ANALYTICS_RULE_ID?api-version=2024-03-01" \
  --body @atlassian-guard-jsm-analytics-rule.json \
  -o jsonc

export ANALYTICS_RULE_ARM_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE_NAME/providers/Microsoft.SecurityInsights/alertRules/$ANALYTICS_RULE_ID"

echo "ANALYTICS_RULE_ID=$ANALYTICS_RULE_ID"
echo "ANALYTICS_RULE_ARM_ID=$ANALYTICS_RULE_ARM_ID"

###############################################################################
# 6. Create Sentinel automation rule to run playbook
###############################################################################

echo "=== 6. Creating Sentinel automation rule ==="

export AUTOMATION_RULE_ID=$(uuidgen)

cat > sentinel-jsm-automation-rule.json <<EOF
{
  "properties": {
    "displayName": "$AUTOMATION_RULE_NAME",
    "order": 1,
    "triggeringLogic": {
      "isEnabled": true,
      "triggersOn": "Incidents",
      "triggersWhen": "Created",
      "conditions": [
        {
          "conditionType": "Property",
          "conditionProperties": {
            "propertyName": "IncidentRelatedAnalyticRuleIds",
            "operator": "Contains",
            "propertyValues": [
              "$ANALYTICS_RULE_ARM_ID"
            ]
          }
        }
      ]
    },
    "actions": [
      {
        "order": 1,
        "actionType": "RunPlaybook",
        "actionConfiguration": {
          "logicAppResourceId": "$PLAYBOOK_ID"
        }
      }
    ]
  }
}
EOF

az rest \
  --method put \
  --url "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE_NAME/providers/Microsoft.SecurityInsights/automationRules/$AUTOMATION_RULE_ID?api-version=2024-03-01" \
  --body @sentinel-jsm-automation-rule.json \
  -o jsonc

echo "AUTOMATION_RULE_ID=$AUTOMATION_RULE_ID"

###############################################################################
# 7. Validation output
###############################################################################

echo "=== 7. Deployment summary ==="

echo "Playbook Logic App:"
echo "$PLAYBOOK_ID"

echo
echo "Analytics Rule:"
echo "$ANALYTICS_RULE_ARM_ID"

echo
echo "Automation Rule ID:"
echo "$AUTOMATION_RULE_ID"

echo
echo "Key Vault secrets created:"
az keyvault secret list \
  --vault-name "$KV_NAME" \
  --query "[?name=='$JIRA_EMAIL_SECRET_NAME' || name=='$JIRA_TOKEN_SECRET_NAME'].{name:name,enabled:attributes.enabled}" \
  -o table

echo
echo "RBAC assigned to playbook identity:"
az role assignment list \
  --assignee "$PLAYBOOK_PRINCIPAL_ID" \
  --query "[].{role:roleDefinitionName,scope:scope}" \
  -o table

echo
echo "DONE."
echo "Next: trigger a new Atlassian Guard Detect sample alert, wait for Sentinel incident creation, then confirm a DCCSUP Incident was created in Jira Service Management."
