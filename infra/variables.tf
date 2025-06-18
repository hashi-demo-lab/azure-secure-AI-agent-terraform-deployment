variable "region" {
  type    = string
  default = "eastus"
}

//vault address
variable "vault_addr" {
  type    = string
  default = "https://vault-public-vault-MY_VAULT.hashicorp.cloud:8200" # Replace with your actual Vault address
}
//vault token
variable "vault_token" {
  type      = string
  sensitive = true
  default   = "token_value"  # Replace with your actual Vault token
}
//vault namespace
variable "vault_namespace" {
  type    = string
  default = "admin"
}


//OPENAI_API_VERSION
variable "openai_api_version" {
  type    = string
  default = "2024-02-01"
}
//OPENAI_API_TYPE
variable "openai_api_type" {
  type    = string
  default = "azuread"
}


variable "mysql_root_password" {
  type      = string
  sensitive = true
  default   = "rootpassword"
}

variable "mysql_password" {
  type      = string
  sensitive = true
  default =  "ChangeThisRootPassword123!"
}
variable "service_account_name" { 
  default = "vault-app-sa"
   }

variable "allowed_source_ranges" {
  description = "CIDR blocks allowed to access MySQL LoadBalancer"
  default     = ["20.190.41.181/32"]  # Only allow specific Vault IP
}

variable "AZURE_OPENAI_DEPLOYMENT_NAME" {
  description = "Deployment name for Azure OpenAI"
  type        = string
  default     = "gpt-35-turbo"
}
variable "AZURE_OPENAI_MODEL_NAME" {
  description = "Model name for Azure OpenAI"
  type        = string
  default     = "gpt-35-turbo"
}
variable "AZURE_OPENAI_EMBEDDING_DEPLOYMENT_NAME" {
  description = "Deployment name for Azure OpenAI embedding model"
  type        = string
  default     = "text-embedding-ada-002"
}
