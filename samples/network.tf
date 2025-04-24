#
# Creates a network, subnets and network security rules before building an Application Gateway
# that we can use to front the services in the Kubernetes Cluster.
#

resource "azurerm_network_security_group" "app_gateway" {
  name                = "${var.cluster_name}-app-gateway"
  location            = var.region
  resource_group_name = azurerm_resource_group.aks_cluster_resource_group.name
}


resource "azurerm_network_security_rule" "gateway_manager" {
  name      = "${var.cluster_name}-app-gateway-gateway-mananger"
  priority  = 200
  direction = "Inbound"
  access    = "Allow"
  protocol  = "Tcp"

  source_address_prefix = "GatewayManager"
  source_port_range     = "*"

  destination_address_prefix = "*"
  destination_port_range     = "65200-65535"

  resource_group_name         = azurerm_resource_group.aks_cluster_resource_group.name
  network_security_group_name = azurerm_network_security_group.app_gateway.name
}


resource "azurerm_network_security_rule" "gateway_cidr" {
  name      = "${var.cluster_name}-app-gateway-gateway-cidr"
  priority  = 201
  direction = "Inbound"
  access    = "Allow"
  protocol  = "Tcp"

  source_address_prefix = var.app_gateway_gateway_subnet_address_prefix
  source_port_range     = "*"

  destination_address_prefix = "*"
  destination_port_range     = "65200-65535"

  resource_group_name         = azurerm_resource_group.aks_cluster_resource_group.name
  network_security_group_name = azurerm_network_security_group.app_gateway.name
}

resource "azurerm_network_security_rule" "azure_loadbalancer" {
  name      = "${var.cluster_name}-app-gateway-loadbalancer"
  priority  = 210
  direction = "Inbound"
  access    = "Allow"
  protocol  = "*"

  source_address_prefix = "AzureLoadBalancer"
  source_port_range     = "*"

  destination_address_prefix = "*"
  destination_port_range     = "*"

  resource_group_name         = azurerm_resource_group.aks_cluster_resource_group.name
  network_security_group_name = azurerm_network_security_group.app_gateway.name
}


resource "azurerm_public_ip" "gateway" {
  name                = "gateway-pip"
  location            = azurerm_resource_group.aks_cluster_resource_group.location
  resource_group_name = azurerm_resource_group.aks_cluster_resource_group.name
  allocation_method   = "Static"

  sku = var.app_gateway_static_ip_sku

  tags = merge(
    local.default_tags,
    var.resource_tags,
  )
}


resource "azurerm_virtual_network" "application_gateway" {
  name                = "k8s-app-gateway-network"
  location            = azurerm_resource_group.aks_cluster_resource_group.location
  resource_group_name = azurerm_resource_group.aks_cluster_resource_group.name
  address_space       = [var.app_gateway_vnet_address_prefix]

  tags = merge(
    local.default_tags,
    var.resource_tags,
  )
}


resource "azurerm_subnet" "aks_cluster" {
  name                 = "akscluster"
  resource_group_name  = azurerm_resource_group.aks_cluster_resource_group.name
  virtual_network_name = azurerm_virtual_network.application_gateway.name
  address_prefixes     = [var.app_gateway_aks_subnet_address_prefix]
}


resource "azurerm_subnet" "app_gateway" {
  name                 = "appgw"
  resource_group_name  = azurerm_resource_group.aks_cluster_resource_group.name
  virtual_network_name = azurerm_virtual_network.application_gateway.name
  address_prefixes     = [var.app_gateway_gateway_subnet_address_prefix]
}


resource "azurerm_subnet_network_security_group_association" "app_gateway" {
  subnet_id                 = azurerm_subnet.app_gateway.id
  network_security_group_id = azurerm_network_security_group.app_gateway.id
}


resource "azurerm_application_gateway" "network" {
  name                = "k8s-app-gateway"
  location            = azurerm_resource_group.aks_cluster_resource_group.location
  resource_group_name = azurerm_resource_group.aks_cluster_resource_group.name

  sku {
    name     = var.app_gateway_sku
    tier     = var.app_gateway_sku_tier
    capacity = 2
  }

  gateway_ip_configuration {
    name      = "appGatewayIpConfiguration"
    subnet_id = azurerm_subnet.app_gateway.id
  }

  frontend_port {
    name = local.frontend_port_name
    port = 80
  }

  frontend_port {
    name = "httpsPort"
    port = 443
  }

  frontend_ip_configuration {
    name                 = local.frontend_ip_configuration_name
    public_ip_address_id = azurerm_public_ip.gateway.id
  }

  backend_address_pool {
    name = local.backend_address_pool_name
  }

  backend_http_settings {
    name                  = local.http_setting_name
    cookie_based_affinity = "Disabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 1
  }

  http_listener {
    name                           = local.listener_name
    frontend_ip_configuration_name = local.frontend_ip_configuration_name
    frontend_port_name             = local.frontend_port_name
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = local.request_routing_rule_name
    rule_type                  = "Basic"
    http_listener_name         = local.listener_name
    backend_address_pool_name  = local.backend_address_pool_name
    backend_http_settings_name = local.http_setting_name
  }

  tags = merge(
    local.default_tags,
    var.resource_tags,
  )

  depends_on = [
    azurerm_virtual_network.application_gateway,
    azurerm_public_ip.gateway
  ]
}
