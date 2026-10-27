# SecureShare Infrastructure as Code (Bicep)

**Author:** Member 4 — Azure Solutions Architect & Cloud Security Engineer  
**IaC Language:** Microsoft Bicep v0.25+  
**Architecture Standard:** Azure Well-Architected Framework (Reliability, Security, Performance)  

---

## 1. Overview & Cloud Architecture

SecureShare provides fully modularized Infrastructure-as-Code (IaC) written in **Microsoft Bicep**. The templates describe the desired state of Azure cloud resources using native ARM constructs without requiring imperative scripts.

```mermaid
graph TD
    Main["main.bicep (Root Orchestrator)"] --> StorageMod["modules/storage.bicep"]
    Main --> KeyVaultMod["modules/keyvault.bicep"]
    Main --> PostgresMod["modules/postgres.bicep"]
    Main --> AppServiceMod["modules/appservice.bicep"]
    
    AppServiceMod -.->|Managed Identity RBAC| KeyVaultMod
    AppServiceMod -.->|Key Vault Secrets User (4633458b)| RoleAssign["RBAC Role Assignment"]
```

---

## 2. Module Specifications

### 2.1 Storage Account (`modules/storage.bicep`)
- **SKU:** `Standard_GRS` (Geo-redundant storage with read failover capability).
- **Security Hardening:**
  - `supportsHttpsTrafficOnly: true` — Blocks unencrypted plain HTTP transport.
  - `minimumTlsVersion: 'TLS1_2'` — Prevents deprecated TLS 1.0/1.1 protocol negotiation.
  - `allowBlobPublicAccess: false` — Enforces private blobs; prevents accidental public data exposure.
  - `deleteRetentionPolicy`: 7-day soft delete retention on blobs and containers for ransomware recovery.
- **Private Container:** Automatically creates private container `secure-files` (`publicAccess: 'None'`).

---

### 2.2 Azure Key Vault (`modules/keyvault.bicep`)
- **SKU:** `Standard`.
- **Zero-Trust RBAC:** `enableRbacAuthorization: true`. Replaces legacy, error-prone access policies with fine-grained Azure Role-Based Access Control.
- **Data Protection:**
  - `enableSoftDelete: true` with 90-day retention.
  - `enablePurgeProtection: true` — Guarantees secrets cannot be permanently destroyed during incident investigations or ransomware attacks.
  - `networkAcls.bypass: 'AzureServices'` — Allows authorized Microsoft Azure resources to interact while blocking public scanning.

---

### 2.3 Azure Database for PostgreSQL Flexible Server (`modules/postgres.bicep`)
- **Engine Version:** PostgreSQL 16.
- **Compute:** Burstable `Standard_B1ms` with automated storage auto-grow enabled.
- **Security Controls:**
  - `require_secure_transport: 'ON'` — Server-enforced SSL/TLS requirement for all client database connections.
  - Automated daily backups with 7-day retention period.
  - Firewall configuration allowing secure traffic originating from within Azure data centers.

---

### 2.4 Azure App Service (`modules/appservice.bicep`)
- **Runtime Stack:** Linux container running Python 3.12.
- **Identity:** `SystemAssigned` Managed Identity. Eliminates static service principal secrets; Azure automatically handles credential rotation.
- **Security Controls:**
  - `httpsOnly: true` — Automatically redirects HTTP requests to HTTPS.
  - `minTlsVersion: '1.2'`.
  - `ftpsState: 'Disabled'` — Blocks insecure FTP access to code directories.
  - Production WSGI/ASGI web server command: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8000`.

---

## 3. RBAC Least-Privilege Identity Binding

In `main.bicep`, the App Service System-Assigned Managed Identity is automatically granted the **Key Vault Secrets User** built-in role (`4633458b-17de-408a-b874-0445c86b69e6`) on the Key Vault scope:

```bicep
resource keyVaultSecretsUserRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVaultModule.outputs.keyVaultId, appServiceModule.outputs.principalId, '4633458b-17de-408a-b874-0445c86b69e6')
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: appServiceModule.outputs.principalId
    principalType: 'ServicePrincipal'
  }
}
```

This ensures the web application can read secrets at runtime via `DefaultAzureCredential()` without possessing permissions to modify, list, or delete secrets.

---

## 4. Deployment Instructions

```bash
# 1. Login to Azure CLI
az login

# 2. Set target subscription
az account set --subscription "<SUBSCRIPTION_ID>"

# 3. Create Resource Group (if not already existing)
az group create --name "rg-secureshare-prod" --location "eastus2"

# 4. Validate Bicep Template Pre-flight
az deployment group validate \
  --resource-group "rg-secureshare-prod" \
  --template-file infra/main.bicep \
  --parameters dbAdminPassword="<SUPER_SECURE_PASSWORD_123!>"

# 5. Execute Infrastructure Deployment
az deployment group create \
  --resource-group "rg-secureshare-prod" \
  --template-file infra/main.bicep \
  --parameters dbAdminPassword="<SUPER_SECURE_PASSWORD_123!>"
```
