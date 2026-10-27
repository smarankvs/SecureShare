@description('App Service Web App Name')
param appName string

@description('Azure Region / Location')
param location string = resourceGroup().location

@description('App Service Plan Pricing Tier')
param appServicePlanSku string = 'B1'

@description('Azure Key Vault URI for Managed Identity Secret Resolution')
param keyVaultUri string

@description('Azure Storage Account Name')
param storageAccountName string

@description('PostgreSQL Server Fully Qualified Domain Name')
param databaseHost string

@description('PostgreSQL Database User')
param databaseUser string

@description('PostgreSQL Database Name')
param databaseName string

@description('PostgreSQL Database Password')
@secure()
param databasePassword string

@description('Tags to apply to resources')
param tags object = {
  Project: 'SecureShare'
  Environment: 'Production'
  ManagedBy: 'Bicep'
}

resource appServicePlan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: '${appName}-plan'
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: appServicePlanSku
    tier: 'Basic'
  }
  properties: {
    reserved: true // Required for Linux
  }
}

resource webApp 'Microsoft.Web/sites@2022-09-01' = {
  name: appName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned' // Managed Identity for Key Vault & Storage access
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      alwaysOn: false
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
      appCommandLine: 'gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8000'
      appSettings: [
        {
          name: 'APP_NAME'
          value: 'SecureShare'
        }
        {
          name: 'ENVIRONMENT'
          value: 'production'
        }
        {
          name: 'DEBUG'
          value: 'false'
        }
        {
          name: 'AZURE_KEYVAULT_ENABLED'
          value: 'true'
        }
        {
          name: 'AZURE_KEYVAULT_URL'
          value: keyVaultUri
        }
        {
          name: 'AZURE_STORAGE_CONTAINER_NAME'
          value: 'secure-files'
        }
        {
          name: 'AZURE_STORAGE_ACCOUNT_NAME'
          value: storageAccountName
        }
        {
          name: 'POSTGRES_SERVER'
          value: databaseHost
        }
        {
          name: 'POSTGRES_USER'
          value: databaseUser
        }
        {
          name: 'POSTGRES_DB'
          value: databaseName
        }
        {
          name: 'POSTGRES_PASSWORD'
          value: databasePassword
        }
        {
          name: 'POSTGRES_SSLMODE'
          value: 'require'
        }
        {
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'true'
        }
      ]
    }
  }
}

output appId string = webApp.id
output appDefaultHostName string = webApp.properties.defaultHostName
output principalId string = webApp.identity.principalId
