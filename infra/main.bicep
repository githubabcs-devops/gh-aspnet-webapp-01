// Bicep file to deploy a containerized web app to Azure

@description('The name of the Azure Container Registry')
param acrName string

@description('The SKU of the Azure Container Registry')
param acrSku string = 'Basic'

@description('The name of the App Service Plan')
param appServicePlanName string

@description('The name of the Web App')
param webAppName string

@description('The location for all resources')
param location string

@description('The container image to deploy')
param containerImage string

@description('The name of the Resource Group')
param resourceGroupName string = 'rg-webapp01-dev'

// Create the resource group at the subscription level
targetScope = 'subscription'

resource resourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: resourceGroupName
  location: location
}

// Deploy resources within the resource group
module resourcesInRG './resources.bicep' = {
  name: 'deployResourcesInRG'
  scope: resourceGroup
  params: {
    acrName: acrName
    acrSku: acrSku
    appServicePlanName: appServicePlanName
    webAppName: webAppName
    location: location
    containerImage: containerImage
  }
}
