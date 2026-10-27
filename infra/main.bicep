@description('Environment Name (e.g. prod, dev, staging)')
@allowed([
  'prod'
  'dev'
  'staging'
])
param environmentName string = 'prod'

@description('Azure Region / Location for all resources')
param location string = resourceGroup().location

@description('Unique Suffix for globally unique names')
param uniqueSuffix string = uniqueString(resourceGroup().id)

@description('Database Administrator Login')
param dbAdminLogin string = 'secureshare_admin'

@description('Database Administrator Password')
@secure()
param dbAdminPassword string

// Base Resource Naming Conventions
var storageAccountName = 'stsecureshare${environmentName}${take(uniqueSuffix, 8)}'
var keyVaultName = 'kv-secureshare-${environmentName}-${take(uniqueSuffix, 6)}'
var postgresServerName = 'psql-secureshare-${environmentName}-${take(uniqueSuffix, 6)}'
var appServiceName = 'app-secureshare-${environmentName}-${take(uniqueSuffix, 6)}'

var commonTags = {
  Project: 'SecureShare'
  Environment: environmentName
  ManagedBy: 'Bicep'
}

// 1. Storage Account Module (Private blob container, TLS 1.2 minimum, soft delete)
module storageModule 'modules/storage.bicep' = {
  name: 'storageModuleDeployment'
  params: {
    storageAccountName: storageAccountName
    location: location
    skuName: 'Standard_GRS'
    containerName: 'secure-files'
    tags: commonTags
  }
}

// 2. Azure Key Vault Module (RBAC authorization, purge protection, soft delete)
module keyVaultModule 'modules/keyvault.bicep' = {
  name: 'keyVaultModuleDeployment'
  params: {
    keyVaultName: keyVaultName
    location: location
    enableRbacAuthorization: true
    tags: commonTags
  }
}

// 3. PostgreSQL Flexible Server Module (SSL Enforced, Backup Retention, Secure Firewall)
module postgresModule 'modules/postgres.bicep' = {
  name: 'postgresModuleDeployment'
  params: {
    serverName: postgresServerName
    location: location
    administratorLogin: dbAdminLogin
    administratorLoginPassword: dbAdminPassword
    databaseName: 'secureshare_db'
    skuName: 'Standard_B1ms'
    tier: 'Burstable'
    tags: commonTags
  }
}

// 4. Azure App Service Module (Linux, Python 3.12, System-Assigned Managed Identity)
module appServiceModule 'modules/appservice.bicep' = {
  name: 'appServiceModuleDeployment'
  params: {
    appName: appServiceName
    location: location
    appServicePlanSku: 'B1'
    keyVaultUri: keyVaultModule.outputs.keyVaultUri
    storageAccountName: storageModule.outputs.storageAccountName
    databaseHost: postgresModule.outputs.serverFqdn
    databaseUser: postgresModule.outputs.administratorLogin
    databaseName: postgresModule.outputs.databaseName
    databasePassword: dbAdminPassword
    tags: commonTags
  }
}

// 5. Zero-Trust RBAC: Grant App Service Managed Identity 'Key Vault Secrets User' role
// Key Vault Secrets User built-in role definition ID: 4633458b-17de-408a-b874-0445c86b69e6
resource keyVaultSecretsUserRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVaultModule.outputs.keyVaultId, appServiceModule.outputs.principalId, '4633458b-17de-408a-b874-0445c86b69e6')
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: appServiceModule.outputs.principalId
    principalType: 'ServicePrincipal'
  }
}

// Deployment Outputs
output storageAccountId string = storageModule.outputs.storageAccountId
output storageAccountName string = storageModule.outputs.storageAccountName
output blobEndpoint string = storageModule.outputs.primaryBlobEndpoint
output keyVaultUri string = keyVaultModule.outputs.keyVaultUri
output postgresFqdn string = postgresModule.outputs.serverFqdn
output appServiceHostName string = appServiceModule.outputs.appDefaultHostName
output appServicePrincipalId string = appServiceModule.outputs.principalId
