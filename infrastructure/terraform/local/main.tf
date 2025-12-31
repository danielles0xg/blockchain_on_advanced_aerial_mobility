# =============================================================================
# AAM Security Experiment Infrastructure - Local Docker Deployment
# Provisions: PostgreSQL, Solana validator, Hyperledger Fabric (3 Raft orderers
# + 2 peers, LevelDB), and Prometheus/Grafana.
#
# NOTE: This is the Infrastructure-as-Code *alternative* to the primary, tested
# path (blockchain/hyperledger/network/network.sh + docker compose).
#
# Fabric prerequisites before `terraform apply`:
#   cd blockchain/hyperledger/network
#   ./network.sh install        # fetch Fabric 2.5.10 binaries + images
#   ./network.sh generate       # cryptogen -> organizations/ (mounted below)
# After apply, create the channel and deploy chaincode with:
#   ./network.sh createChannel deployCC
# =============================================================================

terraform {
  required_version = ">= 1.0"

  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0.1"
    }
  }
}

provider "docker" {}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "fabric_version" {
  description = "Hyperledger Fabric version"
  type        = string
  default     = "2.5.10"
}

variable "solana_version" {
  description = "Solana version"
  type        = string
  default     = "1.18.22"
}

variable "postgres_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "16"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "aam-security-experiment"
}

# Path to the Fabric network dir holding cryptogen output + peer config.
locals {
  fabric_net  = abspath("${path.module}/../../../blockchain/hyperledger/network")
  orderer_dir = "${local.fabric_net}/organizations/ordererOrganizations/example.com/orderers"
  org1_peer   = "${local.fabric_net}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com"
  org2_peer   = "${local.fabric_net}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com"
  peercfg     = "${local.fabric_net}/compose/docker/peercfg"
}

# -----------------------------------------------------------------------------
# Docker network (named "fabric_test" to match the peers' chaincode builder
# network mode and the compose file).
# -----------------------------------------------------------------------------

resource "docker_network" "experiment_network" {
  name   = "fabric_test"
  driver = "bridge"
}

# =============================================================================
# POSTGRESQL (Baseline)
# =============================================================================

resource "docker_image" "postgres" {
  name = "postgres:${var.postgres_version}"
}

resource "docker_container" "postgres" {
  name  = "${var.project_name}-postgres"
  image = docker_image.postgres.image_id

  networks_advanced {
    name = docker_network.experiment_network.name
  }

  ports {
    internal = 5432
    external = 5432
  }

  env = [
    "POSTGRES_USER=aam_user",
    "POSTGRES_PASSWORD=aam_password",
    "POSTGRES_DB=aam_security"
  ]

  volumes {
    host_path      = abspath("${path.module}/../../../database/postgres/schema")
    container_path = "/docker-entrypoint-initdb.d"
  }

  volumes {
    volume_name    = docker_volume.postgres_data.name
    container_path = "/var/lib/postgresql/data"
  }

  healthcheck {
    test         = ["CMD-SHELL", "pg_isready -U aam_user -d aam_security"]
    interval     = "10s"
    timeout      = "5s"
    retries      = 5
    start_period = "10s"
  }
}

resource "docker_volume" "postgres_data" {
  name = "${var.project_name}-postgres-data"
}

# =============================================================================
# SOLANA LOCAL VALIDATOR
# =============================================================================

resource "docker_image" "solana" {
  name = "solanalabs/solana:v${var.solana_version}"
}

resource "docker_container" "solana_validator" {
  name  = "${var.project_name}-solana-validator"
  image = docker_image.solana.image_id

  networks_advanced {
    name = docker_network.experiment_network.name
  }

  ports {
    internal = 8899
    external = 8899
  }
  ports {
    internal = 8900
    external = 8900
  }

  command = [
    "solana-test-validator",
    "--rpc-port", "8899",
    "--bind-address", "0.0.0.0",
    "--reset",
    "--quiet"
  ]

  volumes {
    volume_name    = docker_volume.solana_data.name
    container_path = "/root/.config/solana"
  }
}

resource "docker_volume" "solana_data" {
  name = "${var.project_name}-solana-data"
}

# =============================================================================
# HYPERLEDGER FABRIC - Images
# =============================================================================

resource "docker_image" "fabric_orderer" {
  name = "hyperledger/fabric-orderer:${var.fabric_version}"
}

resource "docker_image" "fabric_peer" {
  name = "hyperledger/fabric-peer:${var.fabric_version}"
}

# =============================================================================
# HYPERLEDGER FABRIC - 3 Raft Orderers
# =============================================================================

resource "docker_container" "orderer" {
  name  = "orderer.example.com"
  image = docker_image.fabric_orderer.image_id

  networks_advanced {
    name    = docker_network.experiment_network.name
    aliases = ["orderer.example.com"]
  }

  ports {
    internal = 7050
    external = 7050
  }
  ports {
    internal = 7053
    external = 7053
  }
  ports {
    internal = 9443
    external = 9443
  }

  env = [
    "FABRIC_LOGGING_SPEC=INFO",
    "ORDERER_GENERAL_LISTENADDRESS=0.0.0.0",
    "ORDERER_GENERAL_LISTENPORT=7050",
    "ORDERER_GENERAL_LOCALMSPID=OrdererMSP",
    "ORDERER_GENERAL_LOCALMSPDIR=/var/hyperledger/orderer/msp",
    "ORDERER_GENERAL_TLS_ENABLED=true",
    "ORDERER_GENERAL_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key",
    "ORDERER_GENERAL_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt",
    "ORDERER_GENERAL_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE=/var/hyperledger/orderer/tls/server.crt",
    "ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY=/var/hyperledger/orderer/tls/server.key",
    "ORDERER_GENERAL_CLUSTER_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_GENERAL_BOOTSTRAPMETHOD=none",
    "ORDERER_CHANNELPARTICIPATION_ENABLED=true",
    "ORDERER_ADMIN_TLS_ENABLED=true",
    "ORDERER_ADMIN_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt",
    "ORDERER_ADMIN_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key",
    "ORDERER_ADMIN_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_ADMIN_TLS_CLIENTROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_ADMIN_LISTENADDRESS=0.0.0.0:7053",
    "ORDERER_OPERATIONS_LISTENADDRESS=orderer.example.com:9443",
    "ORDERER_METRICS_PROVIDER=prometheus"
  ]

  working_dir = "/root"
  command     = ["orderer"]

  volumes {
    host_path      = "${local.orderer_dir}/orderer.example.com/msp"
    container_path = "/var/hyperledger/orderer/msp"
  }
  volumes {
    host_path      = "${local.orderer_dir}/orderer.example.com/tls"
    container_path = "/var/hyperledger/orderer/tls"
  }
  volumes {
    volume_name    = docker_volume.orderer_data.name
    container_path = "/var/hyperledger/production/orderer"
  }
}

resource "docker_volume" "orderer_data" {
  name = "${var.project_name}-orderer-data"
}

resource "docker_container" "orderer2" {
  name  = "orderer2.example.com"
  image = docker_image.fabric_orderer.image_id

  networks_advanced {
    name    = docker_network.experiment_network.name
    aliases = ["orderer2.example.com"]
  }

  ports {
    internal = 7052
    external = 7052
  }
  ports {
    internal = 7055
    external = 7055
  }
  ports {
    internal = 9446
    external = 9446
  }

  env = [
    "FABRIC_LOGGING_SPEC=INFO",
    "ORDERER_GENERAL_LISTENADDRESS=0.0.0.0",
    "ORDERER_GENERAL_LISTENPORT=7052",
    "ORDERER_GENERAL_LOCALMSPID=OrdererMSP",
    "ORDERER_GENERAL_LOCALMSPDIR=/var/hyperledger/orderer/msp",
    "ORDERER_GENERAL_TLS_ENABLED=true",
    "ORDERER_GENERAL_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key",
    "ORDERER_GENERAL_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt",
    "ORDERER_GENERAL_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE=/var/hyperledger/orderer/tls/server.crt",
    "ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY=/var/hyperledger/orderer/tls/server.key",
    "ORDERER_GENERAL_CLUSTER_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_GENERAL_BOOTSTRAPMETHOD=none",
    "ORDERER_CHANNELPARTICIPATION_ENABLED=true",
    "ORDERER_ADMIN_TLS_ENABLED=true",
    "ORDERER_ADMIN_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt",
    "ORDERER_ADMIN_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key",
    "ORDERER_ADMIN_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_ADMIN_TLS_CLIENTROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_ADMIN_LISTENADDRESS=0.0.0.0:7055",
    "ORDERER_OPERATIONS_LISTENADDRESS=orderer2.example.com:9446",
    "ORDERER_METRICS_PROVIDER=prometheus"
  ]

  working_dir = "/root"
  command     = ["orderer"]

  volumes {
    host_path      = "${local.orderer_dir}/orderer2.example.com/msp"
    container_path = "/var/hyperledger/orderer/msp"
  }
  volumes {
    host_path      = "${local.orderer_dir}/orderer2.example.com/tls"
    container_path = "/var/hyperledger/orderer/tls"
  }
  volumes {
    volume_name    = docker_volume.orderer2_data.name
    container_path = "/var/hyperledger/production/orderer"
  }
}

resource "docker_volume" "orderer2_data" {
  name = "${var.project_name}-orderer2-data"
}

resource "docker_container" "orderer3" {
  name  = "orderer3.example.com"
  image = docker_image.fabric_orderer.image_id

  networks_advanced {
    name    = docker_network.experiment_network.name
    aliases = ["orderer3.example.com"]
  }

  ports {
    internal = 7056
    external = 7056
  }
  ports {
    internal = 7057
    external = 7057
  }
  ports {
    internal = 9447
    external = 9447
  }

  env = [
    "FABRIC_LOGGING_SPEC=INFO",
    "ORDERER_GENERAL_LISTENADDRESS=0.0.0.0",
    "ORDERER_GENERAL_LISTENPORT=7056",
    "ORDERER_GENERAL_LOCALMSPID=OrdererMSP",
    "ORDERER_GENERAL_LOCALMSPDIR=/var/hyperledger/orderer/msp",
    "ORDERER_GENERAL_TLS_ENABLED=true",
    "ORDERER_GENERAL_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key",
    "ORDERER_GENERAL_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt",
    "ORDERER_GENERAL_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE=/var/hyperledger/orderer/tls/server.crt",
    "ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY=/var/hyperledger/orderer/tls/server.key",
    "ORDERER_GENERAL_CLUSTER_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_GENERAL_BOOTSTRAPMETHOD=none",
    "ORDERER_CHANNELPARTICIPATION_ENABLED=true",
    "ORDERER_ADMIN_TLS_ENABLED=true",
    "ORDERER_ADMIN_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt",
    "ORDERER_ADMIN_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key",
    "ORDERER_ADMIN_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_ADMIN_TLS_CLIENTROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]",
    "ORDERER_ADMIN_LISTENADDRESS=0.0.0.0:7057",
    "ORDERER_OPERATIONS_LISTENADDRESS=orderer3.example.com:9447",
    "ORDERER_METRICS_PROVIDER=prometheus"
  ]

  working_dir = "/root"
  command     = ["orderer"]

  volumes {
    host_path      = "${local.orderer_dir}/orderer3.example.com/msp"
    container_path = "/var/hyperledger/orderer/msp"
  }
  volumes {
    host_path      = "${local.orderer_dir}/orderer3.example.com/tls"
    container_path = "/var/hyperledger/orderer/tls"
  }
  volumes {
    volume_name    = docker_volume.orderer3_data.name
    container_path = "/var/hyperledger/production/orderer"
  }
}

resource "docker_volume" "orderer3_data" {
  name = "${var.project_name}-orderer3-data"
}

# =============================================================================
# HYPERLEDGER FABRIC - Peers (LevelDB)
# =============================================================================

resource "docker_container" "peer0_org1" {
  name  = "peer0.org1.example.com"
  image = docker_image.fabric_peer.image_id

  depends_on = [docker_container.orderer]

  networks_advanced {
    name    = docker_network.experiment_network.name
    aliases = ["peer0.org1.example.com"]
  }

  ports {
    internal = 7051
    external = 7051
  }
  ports {
    internal = 9444
    external = 9444
  }

  env = [
    "FABRIC_CFG_PATH=/etc/hyperledger/peercfg",
    "FABRIC_LOGGING_SPEC=INFO",
    "CORE_PEER_TLS_ENABLED=true",
    "CORE_PEER_PROFILE_ENABLED=false",
    "CORE_PEER_TLS_CERT_FILE=/etc/hyperledger/fabric/tls/server.crt",
    "CORE_PEER_TLS_KEY_FILE=/etc/hyperledger/fabric/tls/server.key",
    "CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt",
    "CORE_PEER_ID=peer0.org1.example.com",
    "CORE_PEER_ADDRESS=peer0.org1.example.com:7051",
    "CORE_PEER_LISTENADDRESS=0.0.0.0:7051",
    "CORE_PEER_CHAINCODEADDRESS=peer0.org1.example.com:7052",
    "CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:7052",
    "CORE_PEER_GOSSIP_BOOTSTRAP=peer0.org1.example.com:7051",
    "CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer0.org1.example.com:7051",
    "CORE_PEER_LOCALMSPID=Org1MSP",
    "CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp",
    "CORE_OPERATIONS_LISTENADDRESS=peer0.org1.example.com:9444",
    "CORE_METRICS_PROVIDER=prometheus",
    "CORE_CHAINCODE_EXECUTETIMEOUT=300s",
    "CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock",
    "CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=fabric_test"
  ]

  working_dir = "/root"
  command     = ["peer", "node", "start"]

  volumes {
    host_path      = local.org1_peer
    container_path = "/etc/hyperledger/fabric"
  }
  volumes {
    host_path      = local.peercfg
    container_path = "/etc/hyperledger/peercfg"
  }
  volumes {
    volume_name    = docker_volume.peer0_org1_data.name
    container_path = "/var/hyperledger/production"
  }
  volumes {
    host_path      = "/var/run/docker.sock"
    container_path = "/host/var/run/docker.sock"
  }
}

resource "docker_volume" "peer0_org1_data" {
  name = "${var.project_name}-peer0-org1-data"
}

resource "docker_container" "peer0_org2" {
  name  = "peer0.org2.example.com"
  image = docker_image.fabric_peer.image_id

  depends_on = [docker_container.orderer]

  networks_advanced {
    name    = docker_network.experiment_network.name
    aliases = ["peer0.org2.example.com"]
  }

  ports {
    internal = 9051
    external = 9051
  }
  ports {
    internal = 9445
    external = 9445
  }

  env = [
    "FABRIC_CFG_PATH=/etc/hyperledger/peercfg",
    "FABRIC_LOGGING_SPEC=INFO",
    "CORE_PEER_TLS_ENABLED=true",
    "CORE_PEER_PROFILE_ENABLED=false",
    "CORE_PEER_TLS_CERT_FILE=/etc/hyperledger/fabric/tls/server.crt",
    "CORE_PEER_TLS_KEY_FILE=/etc/hyperledger/fabric/tls/server.key",
    "CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt",
    "CORE_PEER_ID=peer0.org2.example.com",
    "CORE_PEER_ADDRESS=peer0.org2.example.com:9051",
    "CORE_PEER_LISTENADDRESS=0.0.0.0:9051",
    "CORE_PEER_CHAINCODEADDRESS=peer0.org2.example.com:9052",
    "CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:9052",
    "CORE_PEER_GOSSIP_BOOTSTRAP=peer0.org2.example.com:9051",
    "CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer0.org2.example.com:9051",
    "CORE_PEER_LOCALMSPID=Org2MSP",
    "CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp",
    "CORE_OPERATIONS_LISTENADDRESS=peer0.org2.example.com:9445",
    "CORE_METRICS_PROVIDER=prometheus",
    "CORE_CHAINCODE_EXECUTETIMEOUT=300s",
    "CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock",
    "CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=fabric_test"
  ]

  working_dir = "/root"
  command     = ["peer", "node", "start"]

  volumes {
    host_path      = local.org2_peer
    container_path = "/etc/hyperledger/fabric"
  }
  volumes {
    host_path      = local.peercfg
    container_path = "/etc/hyperledger/peercfg"
  }
  volumes {
    volume_name    = docker_volume.peer0_org2_data.name
    container_path = "/var/hyperledger/production"
  }
  volumes {
    host_path      = "/var/run/docker.sock"
    container_path = "/host/var/run/docker.sock"
  }
}

resource "docker_volume" "peer0_org2_data" {
  name = "${var.project_name}-peer0-org2-data"
}

# =============================================================================
# METRICS COLLECTION - Prometheus + Grafana
# =============================================================================

resource "docker_image" "prometheus" {
  name = "prom/prometheus:latest"
}

resource "docker_image" "grafana" {
  name = "grafana/grafana:latest"
}

resource "docker_container" "prometheus" {
  name  = "${var.project_name}-prometheus"
  image = docker_image.prometheus.image_id

  networks_advanced {
    name = docker_network.experiment_network.name
  }

  ports {
    internal = 9090
    external = 9090
  }

  volumes {
    host_path      = abspath("${path.module}/../../docker/prometheus.yml")
    container_path = "/etc/prometheus/prometheus.yml"
  }
}

resource "docker_container" "grafana" {
  name  = "${var.project_name}-grafana"
  image = docker_image.grafana.image_id

  networks_advanced {
    name = docker_network.experiment_network.name
  }

  ports {
    internal = 3000
    external = 3000
  }

  env = [
    "GF_SECURITY_ADMIN_USER=admin",
    "GF_SECURITY_ADMIN_PASSWORD=admin"
  ]

  volumes {
    volume_name    = docker_volume.grafana_data.name
    container_path = "/var/lib/grafana"
  }
}

resource "docker_volume" "grafana_data" {
  name = "${var.project_name}-grafana-data"
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "network_name" {
  description = "Docker network name"
  value       = docker_network.experiment_network.name
}

output "postgres" {
  description = "PostgreSQL connection info"
  value = {
    host     = "localhost"
    port     = 5432
    database = "aam_security"
    user     = "aam_user"
    url      = "postgresql://aam_user:aam_password@localhost:5432/aam_security"
  }
  sensitive = true
}

output "solana" {
  description = "Solana validator endpoints"
  value = {
    rpc_url   = "http://localhost:8899"
    ws_url    = "ws://localhost:8900"
    container = docker_container.solana_validator.name
  }
}

output "hyperledger" {
  description = "Hyperledger Fabric endpoints (3 Raft orderers + 2 peers)"
  value = {
    orderer    = "localhost:7050"
    orderer2   = "localhost:7052"
    orderer3   = "localhost:7056"
    peer0_org1 = "localhost:7051"
    peer0_org2 = "localhost:9051"
    next_steps = "cd blockchain/hyperledger/network && ./network.sh createChannel deployCC"
  }
}

output "monitoring" {
  description = "Monitoring endpoints"
  value = {
    prometheus = "http://localhost:9090"
    grafana    = "http://localhost:3000"
  }
}

output "containers" {
  description = "All container names"
  value = {
    postgres          = docker_container.postgres.name
    solana_validator  = docker_container.solana_validator.name
    fabric_orderer    = docker_container.orderer.name
    fabric_orderer2   = docker_container.orderer2.name
    fabric_orderer3   = docker_container.orderer3.name
    fabric_peer0_org1 = docker_container.peer0_org1.name
    fabric_peer0_org2 = docker_container.peer0_org2.name
    prometheus        = docker_container.prometheus.name
    grafana           = docker_container.grafana.name
  }
}
