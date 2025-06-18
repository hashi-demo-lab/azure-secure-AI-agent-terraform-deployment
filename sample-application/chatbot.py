# Complete AI Agent with Azure Authentication for HCP Vault - FIXED VERSION
import streamlit as st
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.tools import tool
from langchain_community.utilities.sql_database import SQLDatabase
from langchain_community.agent_toolkits.sql.toolkit import SQLDatabaseToolkit
from langchain.tools import Tool
from langchain_openai import AzureChatOpenAI, AzureOpenAIEmbeddings
from langchain.memory import ConversationBufferMemory
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from azure.identity import ManagedIdentityCredential, DefaultAzureCredential
from dotenv import load_dotenv
import sys
import re
import base64
import os
import requests
import hvac
import logging
import uuid
import json
import functools
import time
from typing import Dict, Any, Optional, Callable, Tuple
from datetime import datetime, timezone

# Web search import - optional
try:
    from langchain_community.utilities import DuckDuckGoSearchAPIWrapper
except ImportError:
    print("Warning: DuckDuckGo search not available. Web search tool will be disabled.")
    DuckDuckGoSearchAPIWrapper = None

# Load environment variables
load_dotenv()

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# FastAPI imports - optional
try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
    import uvicorn
    FASTAPI_AVAILABLE = True
    logger.info("FastAPI dependencies available")
except ImportError:
    logger.info("FastAPI not available. API endpoints will be disabled.")
    FASTAPI_AVAILABLE = False
    FastAPI = None
    HTTPException = None
    BaseModel = None
    uvicorn = None

# =============================================================================
# CONFIGURATION
# =============================================================================

# Azure OpenAI Configuration
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
AZURE_OPENAI_DEPLOYMENT_NAME = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "gpt-4")
AZURE_OPENAI_EMBEDDING_DEPLOYMENT = os.getenv("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "text-embedding-ada-002")

# Vault Configuration
VAULT_URL = os.getenv("VAULT_ADDR", "https://your-hcp-vault-url")
VAULT_ROLE = os.getenv("VAULT_ROLE", "aks-workload-role")
VAULT_SECRET_PATH = os.getenv("VAULT_SECRET_PATH", "database/creds/my-role")
VAULT_AUTH_PATH = os.getenv("VAULT_AUTH_PATH", "jwt")
VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE")

# Database Configuration
DB_HOST = os.getenv("DB_HOST", "<your-db-host>")
DB_NAME = os.getenv("DB_NAME", "<your-db-name>")

# Token file path
TOKEN_FILE = os.getenv("AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/azure/tokens/azure-identity-token")

# =============================================================================
# VAULT METADATA MANAGER
# =============================================================================

class HvacMetadataManager:
    """Manager class for handling HVAC clients and metadata operations"""
    
    def __init__(self):
        self.client_instances = {}
        self.metadata_cache = {}
        self.last_auth_time = None

    def add_client(self, name: str, client: hvac.Client):
        """Add a client instance to the manager"""
        self.client_instances[name] = client
        logger.info(f"Added HVAC client: {name}")

    def get_client(self, name: str) -> Optional[hvac.Client]:
        """Get a client instance by name"""
        return self.client_instances.get(name)

    def get_primary_client(self) -> Optional[hvac.Client]:
        """Get the primary client (first available)"""
        if 'primary' in self.client_instances:
            return self.client_instances['primary']
        elif self.client_instances:
            return next(iter(self.client_instances.values()))
        return None

    def remove_client(self, name: str):
        """Remove a client instance"""
        if name in self.client_instances:
            del self.client_instances[name]
            logger.info(f"Removed HVAC client: {name}")

    def clear_all_clients(self):
        """Clear all client instances"""
        self.client_instances.clear()
        logger.info("Cleared all HVAC clients")

# Initialize the global manager
hvac_metadata_manager = HvacMetadataManager()

# =============================================================================
# VAULT AUTHENTICATION AND ENTITY METADATA
# =============================================================================

def get_jwt_token() -> str:
    """Get JWT token from file system"""
    token_locations = [
        TOKEN_FILE,
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/tokens/vault-token",
        "/tmp/vault-token"
    ]
    
    for token_file in token_locations:
        if os.path.exists(token_file):
            try:
                with open(token_file, "r") as f:
                    jwt_token = f.read().strip()
                    if jwt_token:
                        logger.info(f"Successfully read JWT token from {token_file}")
                        return jwt_token
            except Exception as e:
                logger.warning(f"Failed to read token from {token_file}: {e}")
                continue
    
    raise Exception(f"No valid JWT token found. Tried: {', '.join(token_locations)}")

def create_vault_client(vault_addr: str, vault_namespace: str = None, custom_headers: Dict[str, str] = None) -> hvac.Client:
    """Create HVAC client with optional custom headers"""
    try:
        client = hvac.Client(url=vault_addr, namespace=vault_namespace)
        
        if custom_headers and hasattr(client, 'session'):
            logger.info(f"Adding custom headers: {list(custom_headers.keys())}")
            client.session.headers.update(custom_headers)
        
        logger.info(f"Created HVAC client for {vault_addr}")
        return client
        
    except Exception as e:
        raise Exception(f"Failed to create HVAC client: {e}")

def authenticate_with_vault(agent_uuid: str = None, custom_headers: Dict[str, str] = None) -> hvac.Client:
    """Authenticate to Vault using JWT token"""
    
    # Validate configuration
    if not VAULT_URL or VAULT_URL == "https://your-hcp-vault-url":
        raise Exception("VAULT_ADDR environment variable must be set to a valid URL")
    if not VAULT_ROLE:
        raise Exception("VAULT_ROLE environment variable must be set")

    # Get JWT token
    jwt_token = get_jwt_token()
    
    # Generate agent UUID if not provided
    if not agent_uuid:
        agent_uuid = str(uuid.uuid4())
        logger.info(f"Generated agent UUID: {agent_uuid}")

    # Prepare custom headers
    headers_to_add = {
        'X-Agent-UUID': agent_uuid,
        'X-Environment': os.getenv("ENVIRONMENT", "production"),
        'X-App-Version': os.getenv("APP_VERSION", "1.0.0"),
        'X-Timestamp': datetime.now(timezone.utc).isoformat(),
        'X-Request-Source': 'ai-agent-auth'
    }
    
    if custom_headers:
        headers_to_add.update(custom_headers)

    # Create client
    client = create_vault_client(VAULT_URL, VAULT_NAMESPACE, headers_to_add)

    # Authenticate using JWT
    try:
        logger.info(f"Attempting JWT authentication with role: {VAULT_ROLE}")
        logger.info(f"Using auth path: {VAULT_AUTH_PATH}")
        
        auth_response = client.auth.jwt.jwt_login(
            role=VAULT_ROLE,
            jwt=jwt_token,
            path=VAULT_AUTH_PATH
        )
        
        logger.info("✅ JWT authentication successful")
        logger.info(f"Token policies: {auth_response.get('auth', {}).get('policies', [])}")
        logger.info(f"Token TTL: {auth_response.get('auth', {}).get('lease_duration', 'unknown')} seconds")
        
        # Verify token
        token_info = client.auth.token.lookup_self()
        entity_id = token_info.get('data', {}).get('entity_id')
        logger.info(f"Token verification successful - entity_id: {entity_id or 'none'}")
        
        return client
        
    except Exception as e:
        error_msg = f"Vault JWT authentication failed: {e}"
        
        if "permission denied" in str(e).lower():
            error_msg += f"\n\nTroubleshooting:"
            error_msg += f"\n1. Check if role '{VAULT_ROLE}' exists in Vault"
            error_msg += f"\n2. Verify JWT auth method is enabled at 'auth/{VAULT_AUTH_PATH}'"
            error_msg += f"\n3. Ensure the JWT token has the correct claims"
        elif "invalid role name" in str(e).lower():
            error_msg += f"\n\nRole '{VAULT_ROLE}' does not exist in Vault"
        elif "mount not found" in str(e).lower():
            error_msg += f"\n\nJWT auth method not enabled at 'auth/{VAULT_AUTH_PATH}'"
            
        raise Exception(error_msg)

def set_entity_metadata(client: hvac.Client, metadata: Dict[str, str], agent_uuid: str = None) -> bool:
    """Set custom metadata on the current entity after authentication"""
    try:
        # Get current token info to find entity ID
        token_info = client.auth.token.lookup_self()
        entity_id = token_info.get('data', {}).get('entity_id')
        
        if not entity_id:
            logger.warning("No entity_id found in token info - cannot set entity metadata")
            logger.warning("This might be because the token is not associated with an entity")
            return False
            
        logger.info(f"Setting metadata for entity: {entity_id}")
        
        # Prepare metadata to set
        metadata_to_set = metadata.copy() if metadata else {}
        
        # Add standard metadata
        if agent_uuid:
            metadata_to_set['agent_uuid'] = agent_uuid
        metadata_to_set['last_updated'] = datetime.now(timezone.utc).isoformat()
        metadata_to_set['app_name'] = 'ai-agent'
        metadata_to_set['app_version'] = os.getenv("APP_VERSION", "1.0.0")
        metadata_to_set['environment'] = os.getenv("ENVIRONMENT", "production")
        
        # Try different methods to set entity metadata
        success = False
        
        # Method 1: Standard identity API
        try:
            client.write(f"identity/entity/id/{entity_id}", metadata=metadata_to_set)
            logger.info("✅ Successfully set entity metadata using identity API")
            success = True
            
        except Exception as api_error:
            logger.warning(f"Standard identity API failed: {api_error}")
            
            # Method 2: Direct PATCH request
            try:
                url = f"{client.url}/v1/identity/entity/id/{entity_id}"
                headers = {"X-Vault-Token": client.token}
                if hasattr(client, '_namespace') and client._namespace:
                    headers["X-Vault-Namespace"] = client._namespace
                
                patch_data = {"metadata": metadata_to_set}
                response = client.session.patch(url, json=patch_data, headers=headers)
                
                if response.status_code in [200, 204]:
                    logger.info("✅ Successfully set entity metadata using PATCH")
                    success = True
                else:
                    logger.error(f"PATCH failed with status {response.status_code}: {response.text}")
                    
            except Exception as patch_error:
                logger.error(f"PATCH method also failed: {patch_error}")
        
        if success:
            # Cache the metadata
            hvac_metadata_manager.metadata_cache[entity_id] = metadata_to_set
            logger.info(f"Metadata keys set: {list(metadata_to_set.keys())}")
        
        return success
        
    except Exception as e:
        logger.error(f"Failed to set entity metadata: {e}")
        
        if "permission denied" in str(e).lower():
            logger.error("PERMISSION DENIED - Required Vault policy:")
            logger.error('path "identity/entity/id/*" {')
            logger.error('  capabilities = ["read", "update"]')
            logger.error('}')
            
        return False

def verify_entity_metadata(client: hvac.Client) -> Optional[Dict[str, Any]]:
    """Verify that entity metadata was set correctly"""
    try:
        token_info = client.auth.token.lookup_self()
        entity_id = token_info.get('data', {}).get('entity_id')
        
        if not entity_id:
            logger.warning("No entity_id found in token info")
            return None
            
        # Try to read entity metadata
        try:
            entity_info = client.read(f"identity/entity/id/{entity_id}")
        except Exception:
            # Try direct GET request
            url = f"{client.url}/v1/identity/entity/id/{entity_id}"
            headers = {"X-Vault-Token": client.token}
            if hasattr(client, '_namespace') and client._namespace:
                headers["X-Vault-Namespace"] = client._namespace
            
            response = client.session.get(url, headers=headers)
            if response.status_code == 200:
                entity_info = response.json()
            else:
                logger.error(f"Failed to read entity info: {response.status_code}")
                return None
        
        if entity_info and 'data' in entity_info:
            metadata = entity_info['data'].get('metadata', {})
            logger.info(f"Current entity metadata: {metadata}")
            return metadata
        
        return None
        
    except Exception as e:
        logger.error(f"Failed to verify entity metadata: {e}")
        return None

def authenticate_with_vault_and_set_metadata(
    agent_uuid: str = None,
    custom_headers: Dict[str, str] = None,
    entity_metadata: Dict[str, str] = None
) -> hvac.Client:
    """Complete authentication and metadata setting workflow"""
    try:
        # Generate UUID if not provided
        if not agent_uuid:
            agent_uuid = str(uuid.uuid4())
            logger.info(f"Generated new agent UUID: {agent_uuid}")
        
        # Authenticate with Vault
        client = authenticate_with_vault(agent_uuid=agent_uuid, custom_headers=custom_headers)
        
        # Add to manager
        hvac_metadata_manager.add_client('primary', client)
        hvac_metadata_manager.last_auth_time = datetime.now(timezone.utc)
        
        # Set entity metadata if provided
        if entity_metadata or agent_uuid:
            metadata_to_set = entity_metadata.copy() if entity_metadata else {}
            
            if agent_uuid:
                metadata_to_set['agent_uuid'] = agent_uuid
            metadata_to_set['session_start'] = datetime.now(timezone.utc).isoformat()
                
            success = set_entity_metadata(client, metadata_to_set, agent_uuid)
            
            if success:
                logger.info("✅ Entity metadata set successfully")
                # Verify metadata
                verification_metadata = verify_entity_metadata(client)
                if verification_metadata:
                    logger.info("✅ Entity metadata verified successfully")
            else:
                logger.warning("⚠️ Authentication successful but entity metadata setting failed")
        
        return client
        
    except Exception as e:
        logger.error(f"Failed to authenticate and set metadata: {e}")
        raise

# =============================================================================
# DATABASE CREDENTIALS FROM VAULT
# =============================================================================

def get_db_credentials_from_vault_with_metadata(
    agent_uuid: str = None,
    custom_headers: Dict[str, str] = None,
    entity_metadata: Dict[str, str] = None
) -> Tuple[str, str]:
    """Get database credentials from Vault with metadata tracking"""
    try:
        # Get or create authenticated client
        client = hvac_metadata_manager.get_primary_client()
        
        if not client or not client.is_authenticated():
            logger.info("No authenticated client found, creating new one...")
            client = authenticate_with_vault_and_set_metadata(
                agent_uuid=agent_uuid,
                custom_headers=custom_headers,
                entity_metadata=entity_metadata
            )
        
        # Get database credentials
        logger.info(f"Requesting database credentials from: {VAULT_SECRET_PATH}")
        response = client.read(VAULT_SECRET_PATH)
        
        if not response or 'data' not in response:
            raise Exception(f"No data returned from Vault path: {VAULT_SECRET_PATH}")
        
        data = response['data']
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            raise Exception("Username or password not found in Vault response")
        
        logger.info(f"✅ Successfully retrieved database credentials for user: {username}")
        
        # Update entity metadata with database access info
        if client:
            try:
                db_metadata = {
                    'last_db_access': datetime.now(timezone.utc).isoformat(),
                    'db_user': username,
                    'db_operation': 'credential_retrieval'
                }
                set_entity_metadata(client, db_metadata, agent_uuid)
            except Exception as meta_error:
                logger.warning(f"Failed to update entity metadata: {meta_error}")
        
        return username, password
        
    except Exception as e:
        logger.error(f"Failed to get database credentials: {e}")
        
        if "permission denied" in str(e).lower():
            logger.error("PERMISSION DENIED - Required Vault policy:")
            logger.error(f'path "{VAULT_SECRET_PATH}" {{')
            logger.error('  capabilities = ["read"]')
            logger.error('}')
        elif "mount not found" in str(e).lower():
            logger.error(f"Database secrets engine not found or path incorrect: {VAULT_SECRET_PATH}")
            
        raise

# =============================================================================
# AZURE OPENAI INITIALIZATION
# =============================================================================

def initialize_azure_llm():
    """Initialize Azure OpenAI LLM with proper configuration"""
    try:
        if not AZURE_OPENAI_ENDPOINT:
            raise Exception("AZURE_OPENAI_ENDPOINT not configured")
            
        if not AZURE_OPENAI_API_KEY:
            logger.info("No API key found, attempting managed identity authentication...")
            try:
                credential = DefaultAzureCredential()
                token = credential.get_token("https://cognitiveservices.azure.com/.default")
                api_key = token.token
            except Exception as e:
                raise Exception(f"Failed to get token from managed identity: {e}")
        else:
            api_key = AZURE_OPENAI_API_KEY
            
        llm = AzureChatOpenAI(
            api_key=api_key,
            azure_endpoint=AZURE_OPENAI_ENDPOINT,
            api_version=AZURE_OPENAI_API_VERSION,
            azure_deployment=AZURE_OPENAI_DEPLOYMENT_NAME,
            temperature=0
        )
        
        logger.info(f"✅ Azure OpenAI initialized with deployment: {AZURE_OPENAI_DEPLOYMENT_NAME}")
        return llm
        
    except Exception as e:
        logger.error(f"Failed to initialize Azure OpenAI: {e}")
        return None

# =============================================================================
# TOOLS DEFINITION
# =============================================================================
@tool
def calculator(expression: str) -> str:
    """Evaluates a math expression safely."""
    try:
        # Basic safety check - only allow mathematical operations
        allowed_chars = set('0123456789+-*/.() ')
        if not all(c in allowed_chars for c in expression):
            return "Error: Only basic mathematical operations are allowed"
        
        result = eval(expression)
        return str(result)
    except Exception as e:
        return f"Error: {e}"
    
@tool
def ask_mysql(query: str) -> str:
    """Executes a SQL query on the MySQL DB and returns results.
    
    Available tables and columns:
    - countries: id, country (full country name like 'China', 'India'), population, created_at
    - cities: id, city, country (full country name), population, created_at
    
    Important: 
    - Use 'country' column with full country names (e.g., 'China', not 'CHN')
    - Only valid SQL SELECT statements are allowed
    - Use single quotes for string values in WHERE clauses
    
    Example queries:
    - SELECT population FROM countries WHERE country='China'
    - SELECT city, population FROM cities WHERE country='India' ORDER BY population DESC
    - SELECT country, population FROM countries ORDER BY population DESC LIMIT 5
    """
    try:
        # Validate that this looks like a SQL query
        query_stripped = query.strip()
        if not query_stripped:
            return "Error: Empty query provided"
        
        # Basic SQL validation - must start with SELECT
        if not query_stripped.upper().startswith('SELECT'):
            # If it's not a SELECT statement, try to help construct one
            return f"""Error: Invalid SQL query. The query must start with SELECT.
            
Did you mean to ask about '{query}'? Here are some example queries:
- SELECT population FROM countries WHERE country='{query}'
- SELECT city, population FROM cities WHERE country='{query}' ORDER BY population DESC
- SELECT * FROM countries WHERE country LIKE '%{query}%'

Available tables:
- countries: id, country, population, created_at
- cities: id, city, country, population, created_at"""
        
        # Additional validation checks
        dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'ALTER', 'CREATE', 'TRUNCATE']
        query_upper = query_stripped.upper()
        for keyword in dangerous_keywords:
            if keyword in query_upper:
                return f"Error: {keyword} operations are not allowed. Only SELECT queries are permitted."
        
        logger.info(f"Executing MySQL query: {query_stripped}")
        
        # Generate unique agent UUID for this session
        agent_uuid = str(uuid.uuid4())
        
        # Prepare metadata for this database operation
        custom_headers = {
            'X-Agent-UUID': agent_uuid,
            'X-Request-Source': 'ai-agent-mysql-query',
            'X-Query-Type': 'database',
            'X-Timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        entity_metadata = {
            'agent_uuid': agent_uuid,
            'operation': 'mysql_query',
            'request_source': 'ai-agent',
            'query_preview': query_stripped[:50] + '...' if len(query_stripped) > 50 else query_stripped,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Get fresh credentials with metadata tracking
        username, password = get_db_credentials_from_vault_with_metadata(
            agent_uuid=agent_uuid,
            custom_headers=custom_headers,
            entity_metadata=entity_metadata
        )
        
        # Validate database configuration
        if DB_HOST == "<your-db-host>" or DB_NAME == "<your-db-name>":
            return "Error: Database not configured. Please set DB_HOST and DB_NAME environment variables."
        
        # Create database connection
        db_uri = f"mysql+pymysql://{username}:{password}@{DB_HOST}:3306/{DB_NAME}"
        db = SQLDatabase.from_uri(db_uri)
        
        # Execute query
        result = db.run(query_stripped)
        logger.info("✅ Query executed successfully")
        
        # Update entity metadata with successful query
        client = hvac_metadata_manager.get_primary_client()
        if client:
            try:
                success_metadata = {
                    'last_successful_query': datetime.now(timezone.utc).isoformat(),
                    'query_status': 'success'
                }
                set_entity_metadata(client, success_metadata, agent_uuid)
            except Exception:
                pass  # Don't fail the query if metadata update fails
        
        return result
        
    except Exception as e:
        error_msg = f"Database query failed: {str(e)}"
        logger.error(error_msg)
        
        # Provide helpful error messages
        if "Unknown column" in str(e):
            error_msg += "\n\nHint: Check column names. Available columns:"
            error_msg += "\n- countries table: id, country, population, created_at"
            error_msg += "\n- cities table: id, city, country, population, created_at"
            error_msg += "\nUse 'country' with full names like 'China', not 'CHN'"
        elif "You have an error in your SQL syntax" in str(e):
            error_msg += "\n\nHint: Check your SQL syntax. Examples:"
            error_msg += "\n- SELECT population FROM countries WHERE country='China'"
            error_msg += "\n- SELECT city, population FROM cities WHERE country='India'"
            error_msg += "\n- SELECT * FROM countries ORDER BY population DESC LIMIT 5"
        elif "permission denied" in str(e).lower():
            error_msg += "\nHint: Check Vault authentication and database policies"
        elif "connection" in str(e).lower():
            error_msg += "\nHint: Check database connection settings"
        elif "access denied" in str(e).lower():
            error_msg += "\nHint: Check database user permissions"
            
        return error_msg


def create_agent_prompt():
    """Create a prompt template for the agent with better SQL guidance"""
    try:
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a helpful AI assistant with access to various tools. 

You can:
1. Query a MySQL database with information about countries and cities
2. Perform mathematical calculations
3. Search the web for current information (if available)

When using the database:
- Available tables: 
  * countries (id, country, population, created_at)
  * cities (id, city, country, population, created_at)
- Use full country names (e.g., 'China', 'India') not country codes
- Always construct proper SQL SELECT statements
- Use single quotes for string values in WHERE clauses

Examples of good database queries:
- "What is the population of China?" → SELECT population FROM countries WHERE country='China'
- "List cities in India" → SELECT city, population FROM cities WHERE country='India'
- "Top 5 populous countries" → SELECT country, population FROM countries ORDER BY population DESC LIMIT 5

If a user asks about database information, always use the ask_mysql tool with a proper SQL SELECT statement.
Never pass just a country name or city name - always construct a complete SQL query.

Always be helpful and provide clear, accurate responses."""),
            MessagesPlaceholder("chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder("agent_scratchpad")
        ])
        return prompt
    except Exception as e:
        logger.error(f"Failed to create prompt: {e}")
        return None


# Also update the Tool description to be more explicit
def initialize_agent_system():
    """Initialize the complete agent system with improved SQL tool"""
    try:
        logger.info("Initializing agent system...")
        
        # Initialize LLM
        llm = initialize_azure_llm()
        if not llm:
            raise Exception("LLM initialization failed")
        
        # Initialize tools with better descriptions
        tools = [
            Tool(
                name="ask_mysql",
                func=ask_mysql,
                description="""Query the MySQL database using proper SQL SELECT statements.
                
Available tables:
- countries: id, country (full name like 'China'), population, created_at  
- cities: id, city, country (full name), population, created_at

IMPORTANT: Always pass complete SQL SELECT statements, not just country/city names.

Examples:
- To get China's population: SELECT population FROM countries WHERE country='China'
- To list Indian cities: SELECT city, population FROM cities WHERE country='India' ORDER BY population DESC
- Top countries by population: SELECT country, population FROM countries ORDER BY population DESC LIMIT 5

Use single quotes for string values in WHERE clauses."""
            ),
            Tool(
                name="calculator",
                func=calculator,
                description="Perform mathematical calculations using Python expressions"
            )
        ]
        
        # Add web search if available
        if DuckDuckGoSearchAPIWrapper:
            try:
                search = DuckDuckGoSearchAPIWrapper()
                tools.append(Tool(
                    name="web_search",
                    func=search.run,
                    description="Search the web for current information"
                ))
                logger.info("✅ Web search tool added")
            except Exception as e:
                logger.warning(f"Web search tool not available: {e}")
        
        # Create memory
        memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)
        
        # Create prompt
        prompt = create_agent_prompt()
        if not prompt:
            raise Exception("Prompt creation failed")
        
        # Create agent
        agent = create_tool_calling_agent(llm, tools, prompt)
        
        # Create agent executor
        agent_executor = AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=True,
            return_intermediate_steps=True,
            memory=memory,
            handle_parsing_errors=True,
            max_iterations=10
        )
        
        logger.info("✅ Agent system initialized successfully")
        return agent_executor, llm, tools
        
    except Exception as e:
        logger.error(f"Failed to initialize agent system: {e}")
        return None, None, None
    
# =============================================================================
# QUERY FUNCTIONS
# =============================================================================

def query_agent_direct(agent_executor, question: str):
    """Direct function to query the agent"""
    if not agent_executor:
        return {"error": "Agent not properly initialized"}

    correlation_id = str(uuid.uuid4())
    logger.info(f"[{correlation_id}] Processing question: {question}")

    try:
        response = agent_executor.invoke({"input": question})
        final_answer = response.get("output", "")
        steps = response.get("intermediate_steps", [])

        formatted_steps = []
        for i, step in enumerate(steps):
            try:
                if not isinstance(step, (list, tuple)) or len(step) < 2:
                    continue
                
                agent_action, result = step[0], step[1]
                
                step_info = {
                    "step": i + 1,
                    "action": getattr(agent_action, 'tool', 'unknown'),
                    "input": str(getattr(agent_action, 'tool_input', '')),
                    "result": str(result) if result is not None else ""
                }
                
                formatted_steps.append(step_info)
                
            except Exception as step_error:
                logger.error(f"Error processing step {i}: {step_error}")
                formatted_steps.append({
                    "step": i + 1,
                    "action": "error",
                    "input": "",
                    "result": f"Error processing step: {step_error}"
                })

        return {
            "correlation_id": correlation_id,
            "question": question,
            "agent_steps": formatted_steps,
            "final_answer": final_answer
        }

    except Exception as e:
        logger.error(f"[{correlation_id}] Agent error: {e}")
        return {
            "correlation_id": correlation_id,
            "error": str(e),
            "question": question,
            "agent_steps": [],
            "final_answer": ""
        }

# =============================================================================
# STREAMLIT INTERFACE
# =============================================================================

def main():
    """Main Streamlit interface"""
    st.set_page_config(
        page_title="AI Agent with Vault Integration",
        page_icon="🤖",
        layout="wide"
    )

    st.title("🤖 AI Agent with HashiCorp Vault Integration")
    st.markdown("Ask questions, query databases with dynamic credentials, and more!")

    # Initialize agent system
    if 'agent_executor' not in st.session_state:
        with st.spinner("Initializing AI Agent..."):
            agent_executor, llm, tools = initialize_agent_system()
            st.session_state.agent_executor = agent_executor
            st.session_state.llm = llm
            st.session_state.tools = tools

    agent_executor = st.session_state.agent_executor
    llm = st.session_state.llm
    tools = st.session_state.tools

    # Create layout
    col1, col2 = st.columns([2, 1])
    
    with col2:
        st.markdown("### 🔧 System Status")
        
        # Status indicators
        status_checks = [
            ("🔐 HashiCorp Vault", VAULT_URL != "https://your-hcp-vault-url", 
             "Connected" if VAULT_URL != "https://your-hcp-vault-url" else "Not Configured"),
            ("🔑 Azure OpenAI", AZURE_OPENAI_API_KEY is not None or AZURE_OPENAI_ENDPOINT is not None,
             "Configured" if AZURE_OPENAI_API_KEY or AZURE_OPENAI_ENDPOINT else "Not Configured"),
            ("🗄️ Database Connection", DB_HOST != "<your-db-host>" and DB_NAME != "<your-db-name>",
             "Configured" if DB_HOST != "<your-db-host>" and DB_NAME != "<your-db-name>" else "Not Configured"),
            ("🤖 AI Agent", agent_executor is not None, 
             "Ready" if agent_executor else "Failed to Initialize"),
            ("🔧 Available Tools", len(tools) if tools else 0, 
             f"{len(tools)} tools" if tools else "No tools")
        ]
        
        for name, status, description in status_checks:
            if status:
                st.success(f"{name}: {description}")
            else:
                st.error(f"{name}: {description}")
        
        # Vault connection test
        st.markdown("---")
        if st.button("🔐 Test Vault Connection"):
            with st.spinner("Testing Vault connection..."):
                try:
                    # Generate test UUID
                    test_uuid = str(uuid.uuid4())
                    test_metadata = {
                        'test_connection': 'true',
                        'test_timestamp': datetime.now(timezone.utc).isoformat()
                    }
                    
                    # Test authentication
                    client = authenticate_with_vault_and_set_metadata(
                        agent_uuid=test_uuid,
                        custom_headers={'X-Test': 'connection'},
                        entity_metadata=test_metadata
                    )
                    
                    if client and client.is_authenticated():
                        st.success("✅ Vault connection successful!")
                        st.info(f"Test UUID: {test_uuid}")
                    else:
                        st.error("❌ Vault connection failed")
                        
                except Exception as e:
                    st.error(f"❌ Vault connection error: {str(e)}")
        
        # Display current metadata
        st.markdown("---")
        st.markdown("### 📊 Session Info")
        
        # Get current client info
        client = hvac_metadata_manager.get_primary_client()
        if client and client.is_authenticated():
            try:
                token_info = client.auth.token.lookup_self()
                entity_id = token_info.get('data', {}).get('entity_id')
                policies = token_info.get('data', {}).get('policies', [])
                ttl = token_info.get('data', {}).get('ttl', 'Unknown')
                
                st.info(f"**Entity ID:** {entity_id or 'None'}")
                st.info(f"**Policies:** {', '.join(policies) if policies else 'None'}")
                st.info(f"**Token TTL:** {ttl} seconds")
                
                # Show cached metadata
                if entity_id in hvac_metadata_manager.metadata_cache:
                    metadata = hvac_metadata_manager.metadata_cache[entity_id]
                    st.json(metadata)
                    
            except Exception as e:
                st.warning(f"Could not retrieve session info: {e}")
        else:
            st.warning("No active Vault session")

    with col1:
        st.markdown("### 💬 Chat Interface")
        
        # Initialize chat history
        if 'messages' not in st.session_state:
            st.session_state.messages = []
        
        # Display chat history
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
                
                # Show intermediate steps if available
                if message.get("steps"):
                    with st.expander("View execution steps"):
                        for step in message["steps"]:
                            st.markdown(f"**Step {step['step']}:** {step['action']}")
                            st.code(step['input'], language='sql' if 'sql' in step['action'].lower() else 'text')
                            st.text(step['result'][:500] + "..." if len(step['result']) > 500 else step['result'])
        
        # Chat input
        if prompt := st.chat_input("Ask me anything about the database, calculations, or general questions..."):
            # Add user message to chat history
            st.session_state.messages.append({"role": "user", "content": prompt})
            
            # Display user message
            with st.chat_message("user"):
                st.markdown(prompt)
            
            # Get assistant response
            with st.chat_message("assistant"):
                if agent_executor:
                    with st.spinner("Thinking..."):
                        response = query_agent_direct(agent_executor, prompt)
                        
                        if "error" in response:
                            st.error(f"Error: {response['error']}")
                            assistant_response = f"I encountered an error: {response['error']}"
                            steps = []
                        else:
                            assistant_response = response.get('final_answer', 'No response generated')
                            steps = response.get('agent_steps', [])
                            
                            st.markdown(assistant_response)
                            
                            # Show execution steps
                            if steps:
                                with st.expander("View execution steps"):
                                    for step in steps:
                                        st.markdown(f"**Step {step['step']}:** {step['action']}")
                                        if step['input']:
                                            st.code(step['input'], language='sql' if 'sql' in step['action'].lower() else 'text')
                                        if step['result']:
                                            st.text(step['result'][:500] + "..." if len(step['result']) > 500 else step['result'])
                        
                        # Add assistant response to chat history
                        st.session_state.messages.append({
                            "role": "assistant", 
                            "content": assistant_response,
                            "steps": steps
                        })
                else:
                    st.error("Agent not properly initialized. Please check the system status.")

        # Clear chat button
        if st.button("🗑️ Clear Chat History"):
            st.session_state.messages = []
            st.rerun()

    # Example queries section
    st.markdown("---")
    st.markdown("### 💡 Example Queries")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**Database Queries:**")
        example_queries = [
            "What is the population of China?",
            "List all cities in India with their populations",
            "Which country has the highest population?",
            "Show me the top 5 most populous cities",
            "What is the total population of all countries?"
        ]
        for query in example_queries:
            if st.button(query, key=f"db_{query}"):
                st.session_state.messages.append({"role": "user", "content": query})
                st.rerun()
    
    with col2:
        st.markdown("**Calculations:**")
        calc_queries = [
            "Calculate 15% of 1000",
            "What is 2^10?",
            "Convert 100 kilometers to miles",
            "Calculate compound interest: 1000 at 5% for 3 years",
            "What is the square root of 144?"
        ]
        for query in calc_queries:
            if st.button(query, key=f"calc_{query}"):
                st.session_state.messages.append({"role": "user", "content": query})
                st.rerun()
    
    with col3:
        st.markdown("**General Questions:**")
        general_queries = [
            "What tools do you have available?",
            "How do you connect to the database?",
            "Explain how Vault authentication works",
            "What is the current system status?",
            "Help me understand your capabilities"
        ]
        for query in general_queries:
            if st.button(query, key=f"gen_{query}"):
                st.session_state.messages.append({"role": "user", "content": query})
                st.rerun()

# =============================================================================
# FASTAPI INTERFACE (OPTIONAL) 
# =============================================================================

if FASTAPI_AVAILABLE:
    from contextlib import asynccontextmanager
    
    # FastAPI models
    class QueryRequest(BaseModel):
        question: str
        agent_uuid: str = None
        custom_headers: dict = None
        entity_metadata: dict = None

    class QueryResponse(BaseModel):
        correlation_id: str
        question: str
        agent_steps: list
        final_answer: str
        error: str = None

    # Global agent executor
    _agent_executor = None
    _llm = None
    _tools = None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Initialize agent system on startup and cleanup on shutdown"""
        global _agent_executor, _llm, _tools
        
        # Startup
        logger.info("Initializing FastAPI agent system...")
        _agent_executor, _llm, _tools = initialize_agent_system()
        logger.info("FastAPI agent system initialized")
        
        yield  # Application runs here
        
        # Shutdown
        logger.info("Shutting down FastAPI agent system...")
        # Add any cleanup logic here if needed
        # For example: close database connections, cleanup vault clients, etc.
        hvac_metadata_manager.clear_all_clients()
        logger.info("FastAPI agent system shutdown complete")

    # Initialize FastAPI app with lifespan
    app = FastAPI(
        title="AI Agent API", 
        version="1.0.0",
        lifespan=lifespan
    )

    @app.post("/query", response_model=QueryResponse)
    async def query_endpoint(request: QueryRequest):
        """Query the AI agent via API"""
        if not _agent_executor:
            raise HTTPException(status_code=500, detail="Agent not properly initialized")
        
        try:
            # Set up custom headers and metadata if provided
            if request.custom_headers or request.entity_metadata:
                # Ensure fresh authentication with custom data
                client = authenticate_with_vault_and_set_metadata(
                    agent_uuid=request.agent_uuid,
                    custom_headers=request.custom_headers,
                    entity_metadata=request.entity_metadata
                )
            
            response = query_agent_direct(_agent_executor, request.question)
            
            return QueryResponse(
                correlation_id=response.get('correlation_id', ''),
                question=response.get('question', ''),
                agent_steps=response.get('agent_steps', []),
                final_answer=response.get('final_answer', ''),
                error=response.get('error')
            )
            
        except Exception as e:
            logger.error(f"API query error: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {
            "status": "healthy",
            "agent_ready": _agent_executor is not None,
            "tools_count": len(_tools) if _tools else 0,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    @app.get("/status")
    async def system_status():
        """Get detailed system status"""
        vault_status = "configured" if VAULT_URL != "https://your-hcp-vault-url" else "not_configured"
        azure_status = "configured" if AZURE_OPENAI_API_KEY or AZURE_OPENAI_ENDPOINT else "not_configured"
        db_status = "configured" if DB_HOST != "<your-db-host>" and DB_NAME != "<your-db-name>" else "not_configured"
        
        return {
            "vault": vault_status,
            "azure_openai": azure_status,
            "database": db_status,
            "agent_ready": _agent_executor is not None,
            "tools": [tool.name for tool in _tools] if _tools else [],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":
    import sys
    
    # Check command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == "api":
        if FASTAPI_AVAILABLE:
            logger.info("Starting FastAPI server...")
            uvicorn.run(app, host="0.0.0.0", port=8000)
        else:
            logger.error("FastAPI not available. Install with: pip install fastapi uvicorn")
    else:
        # Run Streamlit interface
        logger.info("Starting Streamlit interface...")
        main()