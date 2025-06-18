# User Assigned Identity for Chatbot
resource azurerm_user_assigned_identity chatbot {
  name                = "chatbot"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
}

resource "azurerm_user_assigned_identity" "vault" {
  name                = "vault-identity"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
}

# Assign the "Cognitive Services User" to the chatbot User Assigned identity
resource "azurerm_role_assignment" "chatbot_role_assignment" {
  scope                = azurerm_resource_group.this.id
  role_definition_name = "Cognitive Services User"
  principal_id         = azurerm_user_assigned_identity.chatbot.principal_id
}

# Federated Identity Credential
resource "azurerm_federated_identity_credential" "chatbot_federated_identity" {
  name                = "chatbot-federated-identity"
  resource_group_name = azurerm_resource_group.this.name
  audience            = ["api://AzureADTokenExchange"]
  issuer              = module.aks.oidc_issuer_url 
  parent_id           = azurerm_user_assigned_identity.chatbot.id
  subject             = "system:serviceaccount:${kubernetes_namespace.chatbot.metadata[0].name}:${kubernetes_service_account.chatbot.metadata[0].name}"
}

# Federated Identity Credential for Vault App
resource "azurerm_federated_identity_credential" "vault_app_cred" {
  name                = "vault-app-fic"
  resource_group_name = azurerm_resource_group.this.name
  audience            = ["api://AzureADTokenExchange"]
  issuer              = module.aks.oidc_issuer_url 
  parent_id           = azurerm_user_assigned_identity.vault.id
  subject             = "system:serviceaccount:${kubernetes_namespace.chatbot.metadata[0].name}:${kubernetes_service_account.vault.metadata[0].name}"
}
