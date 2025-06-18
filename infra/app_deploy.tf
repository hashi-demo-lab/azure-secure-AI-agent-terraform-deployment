# --- Chatbot Namespace ---
resource "kubernetes_namespace" "chatbot" {
  metadata {
    name = "chatbot"
  }
}

# --- MySQL Namespace ---
resource "kubernetes_namespace" "mysql" {
  metadata {
    name = "mysql"
  }
}

# --- Vault Namespace ---
resource "kubernetes_namespace" "vault" {
  metadata {
    name = "vault"
  }
}

# --- Chatbot ServiceAccount ---
resource "kubernetes_service_account" "chatbot" {
  metadata {
    name      = "chatbot"
    namespace = kubernetes_namespace.chatbot.metadata[0].name
    annotations = {
      "azure.workload.identity/client-id" = azurerm_user_assigned_identity.chatbot.client_id
    }
    labels = {
      "azure.workload.identity/use" = "true"
    }
  }
}

# --- Chatbot ConfigMap with app code ---
resource "kubernetes_config_map" "app_code" {
  metadata {
    name      = "app-code"
    namespace = kubernetes_namespace.chatbot.metadata[0].name
  }

  data = {
    "app.py"           = file("../sample-application/chatbot.py")
    "requirements.txt" = file("../sample-application/requirements.txt")
  }
}

# # # # --- Chatbot Deployment ---
resource "kubernetes_deployment" "chatbot" {
  metadata {
    name      = "chatbot"
    namespace = kubernetes_namespace.chatbot.metadata[0].name
    labels = {
      app = "chatbot"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "chatbot"
      }
    }

    template {
      metadata {
        labels = {
          app = "chatbot"
          "azure.workload.identity/use" = "true"
        }
      }

      spec {
        service_account_name = kubernetes_service_account.chatbot.metadata[0].name

        container {
          name  = "chatbot"
          image = "python:3.11-bullseye"
          env {
            name  = "VAULT_ADDR"
            value = var.vault_addr
          }
          env {
            name  = "VAULT_NAMESPACE"
            value = "admin"
          }
          env {
            name  = "VAULT_ROLE"
            value = "aks-workload-role"  # Match the role from Python code
          }
          env {
            name  = "VAULT_SECRET_PATH"
            value = "database/creds/my-role"  # Match the path from Python code
          }
          env {
            name  = "AZURE_REGION"
            value = var.region
          }
          env {
            name  = "AZURE_CLIENT_ID"
            value = azurerm_user_assigned_identity.chatbot.client_id
          }
          env {
            name  = "AZURE_TENANT_ID"
            value = data.azurerm_client_config.current.tenant_id
          }
          env {
            name  = "AZURE_SUBSCRIPTION_ID"
            value = data.azurerm_client_config.current.subscription_id
          }
          env {
            name = "AZURE_RESOURCE_GROUP"
            value = azurerm_resource_group.this.name
            
          }
          env {
            name  = "OPENAI_API_TYPE"
            value = var.openai_api_type
          }
          env {
            name  = "AZURE_OPENAI_API_VERSION"
            value = var.openai_api_version
          }
          env {
            name  = "AZURE_OPENAI_ENDPOINT"
            value = module.openai.openai_endpoint
          }
          env {
            name  = "AZURE_OPENAI_DEPLOYMENT_NAME"
            value = var.AZURE_OPENAI_DEPLOYMENT_NAME
          }
          env {
            name  = "AZURE_OPENAI_EMBEDDING_DEPLOYMENT"
            value = var.AZURE_OPENAI_EMBEDDING_DEPLOYMENT_NAME  
          }
          env {
            name  = "DB_HOST"
            value = "mysql-lb.mysql.svc.cluster.local"
          }
          env {
            name  = "DB_NAME"
            value = "chatbotdb"
          }
          command = [
              "sh", "-c", <<-EOF
                echo "Installing system dependencies..." && \
                apt-get update && \
                apt-get install -y build-essential libffi-dev libssl-dev pkg-config default-libmysqlclient-dev && \
                echo "Upgrading pip and installing wheel..." && \
                pip install --no-cache-dir --upgrade pip wheel setuptools && \
                echo "Installing Python packages..." && \
                pip install --no-cache-dir --prefer-binary -r /app/requirements.txt && \
                echo "Installing additional packages..." && \
                pip install --no-cache-dir --prefer-binary \
                  pymysql \
                  cryptography \
                  azure-identity \
                  hvac \
                  requests \
                  fastapi \
                  uvicorn \
                  streamlit \
                  duckduckgo-search \
                  langchain \
                  langchain-community \
                  langchain-openai \
                  llama-index \
                  python-dotenv && \
                echo "Starting Streamlit application..." && \
                cd /app && \
                streamlit run app.py --server.port=8501 --server.address=0.0.0.0 --server.headless=true
              EOF
            ]

          port {
            container_port = 8501
            protocol       = "TCP"
          }

          volume_mount {
            name       = "app-code"
            mount_path = "/app"
          }

          # Add resource limits and requests
          resources {
            requests = {
              memory = "1Gi"
              cpu    = "500m"
            }
            limits = {
              memory = "5Gi"
              cpu    = "2000m"
            }
          }

        #   # Add health checks
        #   liveness_probe {
        #     http_get {
        #       path = "/"
        #       port = 8501
        #     }
        #     initial_delay_seconds = 180
        #     period_seconds        = 30
        #     timeout_seconds       = 10
        #     failure_threshold     = 5
        #   }

        #   readiness_probe {
        #     http_get {
        #       path = "/"
        #       port = 8501
        #     }
        #     initial_delay_seconds = 120
        #     period_seconds        = 15
        #     timeout_seconds       = 10
        #     failure_threshold     = 5
        #   }
        }

        volume {
          name = "app-code"
          config_map {
            name = kubernetes_config_map.app_code.metadata[0].name
          }
        }
      }
    }
  }
}

# --- Chatbot Service ---
resource "kubernetes_service" "chatbot" {
  metadata {
    name      = "chatbot"
    namespace = kubernetes_namespace.chatbot.metadata[0].name
  }

  spec {
    selector = {
      app = "chatbot"
    }

    port {
      port        = 80
      target_port = 8501
      protocol    = "TCP"
    }

    type = "LoadBalancer"
  }
}

# --- MySQL ServiceAccount ---
resource "kubernetes_service_account" "mysql" {
  metadata {
    name      = "mysql"
    namespace = kubernetes_namespace.mysql.metadata[0].name
    annotations = {
      "azure.workload.identity/client-id" = azurerm_user_assigned_identity.chatbot.client_id
    }
    labels = {
      "azure.workload.identity/use" = "true"
    }
  }
}

# --- ConfigMap with MySQL init SQL script ---
resource "kubernetes_config_map" "mysql_init_sql" {
  metadata {
    name      = "mysql-init"
    namespace = kubernetes_namespace.mysql.metadata[0].name
  }

  data = {
    "init.sql" = <<-EOT
      CREATE DATABASE IF NOT EXISTS chatbotdb;
      USE chatbotdb;
      
      -- Create the chatbot user that Vault will manage
      CREATE USER IF NOT EXISTS 'chatbot'@'%' IDENTIFIED BY 'temporary_password';
      GRANT ALL PRIVILEGES ON chatbotdb.* TO 'chatbot'@'%';
      FLUSH PRIVILEGES;
      
      -- Create sample tables
      CREATE TABLE IF NOT EXISTS countries (
          id INT AUTO_INCREMENT PRIMARY KEY,
          country VARCHAR(100) NOT NULL,
          population BIGINT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      INSERT INTO countries (country, population) VALUES
        ('China', 1344216107),
        ('India', 1293409038),
        ('United States', 321893745),
        ('Indonesia', 263523621),
        ('Pakistan', 210892331),
        ('Brazil', 202821986),
        ('Nigeria', 205139587),
        ('Bangladesh', 154689383),
        ('Russia', 135912025),
        ('Mexico', 118932753);
        
      -- Create additional sample tables for more interesting queries
      CREATE TABLE IF NOT EXISTS cities (
          id INT AUTO_INCREMENT PRIMARY KEY,
          city VARCHAR(100) NOT NULL,
          country VARCHAR(100) NOT NULL,
          population INT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      INSERT INTO cities (city, country, population) VALUES
        ('Tokyo', 'Japan', 37400068),
        ('Delhi', 'India', 31181376),
        ('Shanghai', 'China', 27795702),
        ('São Paulo', 'Brazil', 22430744),
        ('Mexico City', 'Mexico', 21804515),
        ('Cairo', 'Egypt', 21322750),
        ('Dhaka', 'Bangladesh', 21006000),
        ('Mumbai', 'India', 20411274),
        ('Beijing', 'China', 20035455),
        ('Osaka', 'Japan', 18967459);
    EOT
  }
}

# --- MySQL ClusterIP Service (for internal cluster access) ---
resource "kubernetes_service" "mysql" {
  metadata {
    name      = "mysql"
    namespace = kubernetes_namespace.mysql.metadata[0].name
  }

  spec {
    selector = {
      app = "mysql"
    }

    port {
      port        = 3306
      target_port = 3306
    }

    type = "ClusterIP"
  }
}


# --- MySQL LoadBalancer Service ---
resource "kubernetes_service" "mysql_lb" {
  metadata {
    name      = "mysql-lb"
    namespace = kubernetes_namespace.mysql.metadata[0].name
  }

  spec {
    selector = {
      app = "mysql"
    }

    port {
      port        = 3306
      target_port = 3306
      protocol    = "TCP"
    }

    type = "LoadBalancer"

  }

  # Ensure the LoadBalancer is created after the MySQL ClusterIP service
  depends_on = [kubernetes_service.mysql]
}

# --- MySQL StatefulSet ---
resource "kubernetes_stateful_set" "mysql" {
  metadata {
    name      = "mysql"
    namespace = kubernetes_namespace.mysql.metadata[0].name
    labels = {
      app = "mysql"
    }
  }

  spec {
    service_name = kubernetes_service.mysql.metadata[0].name
    replicas     = 1

    selector {
      match_labels = {
        app = "mysql"
      }
    }

    template {
      metadata {
        labels = {
          app = "mysql"
        }
      }

      spec {
        service_account_name = kubernetes_service_account.mysql.metadata[0].name

        container {
          name  = "mysql"
          image = "mysql:8.0"

          env {
            name  = "MYSQL_ROOT_PASSWORD"
            value = var.mysql_root_password  # Should be from variables
          }
          env {
            name  = "MYSQL_DATABASE"
            value = "chatbotdb"
          }

          port {
            container_port = 3306
          }

          volume_mount {
            name       = "mysql-data"
            mount_path = "/var/lib/mysql"
          }

          volume_mount {
            name       = "init-sql"
            mount_path = "/docker-entrypoint-initdb.d"
            read_only  = true
          }

          # Add resource limits
          resources {
            requests = {
              memory = "512Mi"
              cpu    = "250m"
            }
            limits = {
              memory = "1Gi"
              cpu    = "500m"
            }
          }

          # Add health checks
          liveness_probe {
            exec {
              command = ["mysqladmin", "ping", "-h", "localhost"]
            }
            initial_delay_seconds = 30
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          readiness_probe {
            exec {
              command = ["mysqladmin", "ping", "-h", "localhost"]
            }
            initial_delay_seconds = 10
            period_seconds        = 5
            timeout_seconds       = 2
            failure_threshold     = 3
          }
        }

        volume {
          name = "init-sql"
          config_map {
            name = kubernetes_config_map.mysql_init_sql.metadata[0].name
          }
        }

        volume {
          name      = "mysql-data"
          empty_dir {}  # For production, use persistent volume
        }
      }
    }
  }
}

# --- Vault ServiceAccount ---
resource "kubernetes_service_account" "vault" {
  metadata {
    name      = "vault-service-account"
    namespace = kubernetes_namespace.vault.metadata[0].name
    annotations = {
      "azure.workload.identity/client-id" = azurerm_user_assigned_identity.chatbot.client_id
    }
    labels = {
      "azure.workload.identity/use" = "true"
    }
  }
}

