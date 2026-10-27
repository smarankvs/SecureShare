@description('Azure Key Vault Name (3-24 alphanumeric characters)')
@minLength(3)
@maxLength(24)
param keyVaultName string

@description('Azure Region / Location')
param location string = resourceGroup().location

@description('Enable Azure RBAC Authorization instead of legacy access policies')
param enableRbacAuthorization bool = true

@description('Tags to apply to resources')
param tags object = {
  Project: 'SecureShare'
  Environment: 'Production'
  ManagedBy: 'Bicep'
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    // Zero-Trust security properties
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    enableRbacAuthorization: enableRbacAuthorization
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

output keyVaultId string = keyVault.id
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
