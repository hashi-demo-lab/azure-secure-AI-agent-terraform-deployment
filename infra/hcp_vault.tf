
# -------------------------
# Vault Azure Auth Setup
# -------------------------
resource "vault_auth_backend" "azure" {
  type = "azure"
  path = "azure"
}

resource "vault_azure_auth_backend_config" "azure_config" {
  backend                 = vault_auth_backend.azure.path
  tenant_id               = data.azurerm_client_config.current.tenant_id
  resource                = "api://AzureADTokenExchange" 
  client_id               = azurerm_user_assigned_identity.chatbot.client_id
  environment             = "AzurePublicCloud"
  identity_token_audience = "api://AzureADTokenExchange"
  }

#role name to match Python app expectation
resource "vault_azure_auth_backend_role" "aks_workload_role" {
  backend                     = vault_auth_backend.azure.path
  role                        = "aks-workload-role"
  bound_subscription_ids      = [data.azurerm_client_config.current.subscription_id]
  bound_resource_groups       = [azurerm_resource_group.this.name]
  bound_service_principal_ids = [
    azurerm_user_assigned_identity.chatbot.principal_id,   # Object ID
    azurerm_user_assigned_identity.vault.principal_id,     # Object ID 
  ]
  token_ttl                   = 1800
  token_max_ttl               = 3600
  token_policies              = ["db-access", "default"]
}
 
# JWT configuration for Vault App
resource "vault_jwt_auth_backend" "jwt_config" {
  path               = "jwt"
  type              = "jwt"
  bound_issuer       = module.aks.oidc_issuer_url
  oidc_discovery_url  = module.aks.oidc_issuer_url
  # jwks_url          = "${module.aks.oidc_issuer_url}openid/v1/jwks"
}

resource "vault_jwt_auth_backend_role" "aks_workload_role" {
  backend        = vault_jwt_auth_backend.jwt_config.path
  role_name      = "aks-workload-role"
  token_policies = ["db-access", "default"]
  token_ttl      = 1800
  token_max_ttl  = 3600
  
  # Use the Kubernetes service account token audience
  bound_audiences = ["api://AzureADTokenExchange"]
  # Bind to the Kubernetes service account subject
  bound_subject = "system:serviceaccount:chatbot:chatbot"

  user_claim = "sub"
  role_type  = "jwt"
}

# -------------------------
# Database Secrets Engine
# -------------------------
resource "vault_database_secrets_mount" "mysql" {
  path = "database"

  mysql {
    name           = "chatbot-mysql"
    username       = "root"
    password       = var.mysql_root_password
    
    # Using LoadBalancer IP - wait for IP assignment
    connection_url = "{{username}}:{{password}}@tcp(${kubernetes_service.mysql_lb.status[0].load_balancer[0].ingress[0].ip}:3306)/"

    # Allowed roles for dynamic credential generation
    allowed_roles = ["my-role"]
    
    # Connection verification - enable once LoadBalancer is ready
    verify_connection = false
    
    # Maximum number of open connections to the database
    max_open_connections = 4
    
    # Maximum number of idle connections to the database
    max_idle_connections = 2
    
    # Maximum amount of time a connection may be reused
    max_connection_lifetime = "1"
  }
  
  # Ensure LoadBalancer IP is available before configuring Vault
  depends_on = [
    kubernetes_service.mysql_lb,
    vault_azure_auth_backend_role.aks_workload_role ]
}

# Database role for dynamic credential generation
resource "vault_database_secret_backend_role" "chatbot_role" {
  backend             = vault_database_secrets_mount.mysql.path
  name                = "my-role"  # Matches the path expected by Python app
  db_name             = vault_database_secrets_mount.mysql.mysql[0].name
  default_ttl         = 1800   #30 minutes
  max_ttl             = 3600  # 1 hour
  
  creation_statements = [
    "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';",
    "GRANT ALL PRIVILEGES ON chatbotdb.* TO '{{name}}'@'%';",
    "FLUSH PRIVILEGES;"
  ]
  
  revocation_statements = [
    "DROP USER IF EXISTS '{{name}}'@'%';"
  ]
}

resource "vault_policy" "db_access" {
  name   = "db-access"
  policy = <<EOT
# Allow reading database credentials for the chatbot role
path "database/creds/my-role" {
  capabilities = ["read"]
}

# Allow listing database roles (helpful for debugging)
path "database/roles" {
  capabilities = ["list"]
}

# Allow reading database configuration (helpful for debugging)
path "database/config/*" {
  capabilities = ["read"]
}

# Allow reading database connections (helpful for debugging)
path "database/config/chatbot-mysql" {
  capabilities = ["read"]
}

# Allow token self-renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow token self-lookup
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow accessing sys/health for health checks
path "sys/health" {
  capabilities = ["read", "sudo"]
}

# Allow accessing auth/token/lookup-self for token info
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Entity metadata access
path "identity/entity/id/*" {
  capabilities = ["read", "update"]
}

# Alternative templated policy
path "identity/entity/id/{{identity.entity.id}}" {
  capabilities = ["read", "update"]
}

# JWT authentication
path "auth/jwt/login" {
  capabilities = ["create", "update"]
}
EOT
}

resource "vault_policy" "debug_access" {
  name   = "debug-access"
  policy = <<EOT
# Additional permissions for debugging
path "sys/auth" {
  capabilities = ["read"]
}

path "sys/auth/azure" {
  capabilities = ["read"]
}

path "auth/azure/role/aks-workload-role" {
  capabilities = ["read"]
}

path "database/roles/my-role" {
  capabilities = ["read"]
}
EOT
}
