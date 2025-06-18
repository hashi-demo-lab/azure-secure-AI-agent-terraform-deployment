//output for resource group name
output "resource_group_name" {
  value = azurerm_resource_group.this.name
}

//Open AI key
output "open_ai_key" {
  value = module.openai.openai_endpoint
} 

//Azure manged identity
output "managed_identity" {
  value = azurerm_user_assigned_identity.chatbot.client_id
}

//Azure OIDC_URL
output "oidc_url" {
  value = module.aks.oidc_issuer_url
}

# -------------------------
# Outputs for Vault debugging
# -------------------------
output "vault_azure_auth_path" {
  description = "Path of the Azure auth backend"
  value       = vault_auth_backend.azure.path
}

output "vault_azure_role_name" {
  description = "Name of the Azure auth role"
  value       = vault_azure_auth_backend_role.aks_workload_role.role
}

output "vault_database_role_name" {
  description = "Name of the database role"
  value       = vault_database_secret_backend_role.chatbot_role.name
}

output "vault_database_path" {
  description = "Path to read database credentials"
  value       = "${vault_database_secrets_mount.mysql.path}/creds/${vault_database_secret_backend_role.chatbot_role.name}"
}
//kubernetes load balancer status
output "kubernetes_service_mysql_lb_status" {
  description = "Status of the MySQL LoadBalancer service"
  value       = kubernetes_service.mysql_lb.status[0].load_balancer[0].ingress[0].ip
}
//kubernetes chatbot public ip
output "kubernetes_service_chatbot_public_ip" {
  description = "Public IP of the Chatbot service"
  value       = kubernetes_service.chatbot.status[0].load_balancer[0].ingress[0].ip
}

output "identity_comparison" {
  value = {
    chatbot_principal_id = azurerm_user_assigned_identity.chatbot.principal_id
    chatbot_client_id    = azurerm_user_assigned_identity.chatbot.client_id
    vault_principal_id   = azurerm_user_assigned_identity.vault.principal_id
    vault_client_id      = azurerm_user_assigned_identity.vault.client_id
  }
}