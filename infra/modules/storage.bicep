@description('Azure Storage Account Name (3-24 alphanumeric lowercase characters)')
@minLength(3)
@maxLength(24)
param storageAccountName string

@description('Azure Region / Location')
param location string = resourceGroup().location

@description('Storage Account SKU')
@allowed([
  'Standard_LRS'
  'Standard_GRS'
  'Standard_ZRS'
])
param skuName string = 'Standard_GRS'

@description('Secure Private Blob Container Name')
param containerName string = 'secure-files'

@description('Tags to apply to resources')
param tags object = {
  Project: 'SecureShare'
  Environment: 'Production'
  ManagedBy: 'Bicep'
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: skuName
  }
  properties: {
    // Enterprise Security Baseline: Enforce TLS 1.2+ and HTTPS only
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true
    defaultToOAuthAuthentication: true
    publicNetworkAccess: 'Enabled'
    encryption: {
      services: {
        blob: {
          enabled: true
          keyType: 'Account'
        }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    // Data protection: 7-day soft delete retention
    deleteRetentionPolicy: {
      enabled: true
      days: 7
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

resource blobContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: containerName
  properties: {
    publicAccess: 'None'
  }
}

output storageAccountId string = storageAccount.id
output storageAccountName string = storageAccount.name
output primaryBlobEndpoint string = storageAccount.properties.primaryEndpoints.blob
output containerName string = blobContainer.name
