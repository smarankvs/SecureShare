@description('PostgreSQL Flexible Server Name')
param serverName string

@description('Azure Region / Location')
param location string = resourceGroup().location

@description('Database Administrator Login Name')
param administratorLogin string = 'secureshare_admin'

@description('Database Administrator Password')
@secure()
param administratorLoginPassword string

@description('Database Name')
param databaseName string = 'secureshare_db'

@description('PostgreSQL Version')
@allowed([
  '14'
  '15'
  '16'
])
param pgVersion string = '16'

@description('Compute SKU Name')
param skuName string = 'Standard_B1ms'

@description('Compute Tier')
@allowed([
  'Burstable'
  'GeneralPurpose'
  'MemoryOptimized'
])
param tier string = 'Burstable'

@description('Storage size in GB')
param storageSizeGB int = 32

@description('Tags to apply to resources')
param tags object = {
  Project: 'SecureShare'
  Environment: 'Production'
  ManagedBy: 'Bicep'
}

resource postgresServer 'Microsoft.DBforPostgreSQL/flexibleServers@2023-03-01-preview' = {
  name: serverName
  location: location
  tags: tags
  sku: {
    name: skuName
    tier: tier
  }
  properties: {
    version: pgVersion
    administratorLogin: administratorLogin
    administratorLoginPassword: administratorLoginPassword
    storage: {
      storageSizeGB: storageSizeGB
      autoGrow: 'Enabled'
    }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
    // Network and TLS security
    network: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// PostgreSQL Server Configuration - Enforce SSL
resource sslEnforcement 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2023-03-01-preview' = {
  parent: postgresServer
  name: 'require_secure_transport'
  properties: {
    value: 'ON'
    source: 'user-override'
  }
}

// Database creation
resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-03-01-preview' = {
  parent: postgresServer
  name: databaseName
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

// Firewall rule allowing Azure Services
resource allowAzureServices 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-03-01-preview' = {
  parent: postgresServer
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

output serverId string = postgresServer.id
output serverFqdn string = postgresServer.properties.fullyQualifiedDomainName
output databaseName string = database.name
output administratorLogin string = administratorLogin
