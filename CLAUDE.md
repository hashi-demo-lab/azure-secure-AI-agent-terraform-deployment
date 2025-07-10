# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a secure AI agent deployment on Azure using Terraform. The project deploys an AI-powered chatbot with HashiCorp Vault integration for dynamic credential management, Azure OpenAI Service, Azure Kubernetes Service (AKS), and a MySQL database. The application provides a Streamlit web interface for querying databases and performing calculations.

## Key Commands

### Terraform Operations
Navigate to the `infra/` directory for all Terraform operations:

```bash
cd infra
terraform init
terraform plan
terraform apply
terraform destroy
```

### Python Application
The sample application is located in `sample-application/`:

```bash
cd sample-application
pip install -r requirements.txt
streamlit run chatbot.py
```

For API mode:
```bash
python chatbot.py api
```

## Architecture

### Infrastructure Components
- **Azure Resource Group**: Contains all resources
- **Azure Kubernetes Service (AKS)**: Hosts the containerized application
- **Azure OpenAI Service**: Provides LLM capabilities with GPT-3.5-turbo model
- **Azure Virtual Network**: Secure network isolation
- **HashiCorp Vault**: Dynamic credential management for database access
- **MySQL Database**: Stores population data for countries and cities

### Application Architecture
- **Streamlit Interface**: Web-based chat interface
- **LangChain Agent**: Orchestrates tool usage and conversation flow
- **Tools Available**:
  - `ask_mysql`: Database queries with dynamic Vault authentication
  - `calculator`: Mathematical calculations
  - `web_search`: DuckDuckGo web search (optional)

### Security Features
- Workload Identity for Azure authentication
- HashiCorp Vault for dynamic database credentials
- Azure Managed Identity integration
- Network policies and security groups
- Encrypted secrets management

## Configuration

### Required Environment Variables
Set these in `infra/variables.tf`:
- `vault_addr`: HashiCorp Vault URL
- `vault_token`: Vault authentication token
- `mysql_root_password`: MySQL root password
- `mysql_password`: Application database password

### Azure OpenAI Configuration
- Default model: `gpt-35-turbo`
- API version: `2024-02-01`
- Embedding model: `text-embedding-ada-002`

### Database Schema
The application includes seeded data:
- `countries` table: id, country, population, created_at
- `cities` table: id, city, country, population, created_at

## Development Notes

### Terraform Modules
- `modules/aks/`: AKS cluster configuration
- `modules/openai/`: Azure OpenAI service setup

### Key Files
- `infra/providers.tf`: Provider configurations including Vault
- `infra/aks.tf`: AKS cluster with workload identity
- `infra/hcp_vault.tf`: Vault integration
- `sample-application/chatbot.py`: Main application with Streamlit and FastAPI interfaces

### Python Dependencies
Key packages:
- `streamlit`: Web interface
- `langchain`: AI agent framework
- `azure-identity`: Azure authentication
- `hvac`: HashiCorp Vault client
- `llama-index`: Document processing
- `sqlalchemy`: Database connectivity

## Testing

To test the deployment:
1. Deploy infrastructure: `terraform apply`
2. Get the external IP from Terraform output
3. Access the Streamlit interface in browser
4. Test database connectivity with "Test Vault" button
5. Try example queries like "What is the population of China?"

## Troubleshooting

### Common Issues
- Vault authentication failures: Check vault_addr and vault_token in variables.tf
- Database connection errors: Verify MySQL credentials and network connectivity
- Azure OpenAI errors: Ensure proper service deployment and API key configuration
- AKS deployment issues: Check Azure subscription permissions and resource quotas