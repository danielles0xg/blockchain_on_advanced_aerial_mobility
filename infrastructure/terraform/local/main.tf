# =============================================================================
# AAM Security Experiment Infrastructure - Local Docker Deployment
# Provisions: Hyperledger Fabric, Solana Local Validator, PostgreSQL
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
  default     = "2.5"
}

variable "fabric_ca_version" {
  description = "Fabric CA version"
  type        = string
  default     = "1.5"
}

variable "solana_version" {
  description = "Solana version"
  type        = string
  default     = "1.18"
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

# -----------------------------------------------------------------------------
# Docker Networks
# -----------------------------------------------------------------------------

resource "docker_network" "experiment_network" {
  name   = "${var.project_name}-network"
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

  ports {
    internal = 9900
    external = 9900
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

  healthcheck {
    test         = ["CMD-SHELL", "solana cluster-version -u http://localhost:8899 || exit 1"]
    interval     = "10s"
    timeout      = "5s"
    retries      = 10
    start_period = "30s"
  }
}

resource "docker_volume" "solana_data" {
  name = "${var.project_name}-solana-data"
}

# =============================================================================
# HYPERLEDGER FABRIC - Certificate Authorities
# =============================================================================

resource "docker_image" "fabric_ca" {
  name = "hyperledger/fabric-ca:${var.fabric_ca_version}"
}

resource "docker_image" "fabric_peer" {
  name = "hyperledger/fabric-peer:${var.fabric_version}"
}

resource "docker_image" "fabric_orderer" {
  name = "hyperledger/fabric-orderer:${var.fabric_version}"
}

resource "docker_image" "fabric_tools" {
  name = "hyperledger/fabric-tools:${var.fabric_version}"
}

resource "docker_image" "couchdb" {
  name = "couchdb:3.3"
}

# CA - Org1
resource "docker_container" "ca_org1" {
  name  = "ca.org1.${var.project_name}.com"
  image = docker_image.fabric_ca.image_id

  networks_advanced {
    name    = docker_network.experiment_network.name
    aliases = ["ca.org1.aam.com"]
  }

  ports {
    internal = 7054
    external = 7054
  }

  env = [
    "FABRIC_CA_HOME=/etc/hyperledger/fabric-ca-server",
    "FABRIC_CA_SERVER_CA_NAME=ca-org1",
    "FABRIC_CA_SERVER_TLS_ENABLED=true",
    "FABRIC_CA_SERVER_PORT=7054",
    "FABRIC_CA_SERVER_OPERATIONS_LISTENADDRESS=0.0.0.0:17054"
  ]

  command = ["sh", "-c", "fabric-ca-server start -b admin:adminpw -d"]

  volumes {
    host_path      = abspath("${path.module}/../../../blockchain/hyperledger/network/organizations/fabric-ca/org1")
    container_path = "/etc/hyperledger/fabric-ca-server"
  }
}

# CA - Org2
resource "docker_container" "ca_org2" {
  name  = "ca.org2.${var.project_name}.com"
  image = docker_image.fabric_ca.image_id

  networks_advanced {
    name    = docker_network.experiment_network.name
    aliases = ["ca.org2.aam.com"]
  }

  ports {
    internal = 8054
    external = 8054
  }

  env = [
    "FABRIC_CA_HOME=/etc/hyperledger/fabric-ca-server",
    "FABRIC_CA_SERVER_CA_NAME=ca-org2",
    "FABRIC_CA_SERVER_TLS_ENABLED=true",
    "FABRIC_CA_SERVER_PORT=8054",
    "FABRIC_CA_SERVER_OPERATIONS_LISTENADDRESS=0.0.0.0:18054"
  ]

  command = ["sh", "-c", "fabric-ca-server start -b admin:adminpw -d"]

  volumes {
    host_path      = abspath("${path.module}/../../../blockchain/hyperledger/network/organizations/fabric-ca/org2")
    container_path = "/etc/hyperledger/fabric-ca-server"
  }
}

# CA - Orderer
resource "docker_container" "ca_orderer" {
  name  = "ca.orderer.${var.project_name}.com"
  image = docker_image.fabric_ca.image_id

  networks_advanced {
    name    = docker_network.experiment_network.name
    aliases = ["ca.orderer.aam.com"]
  }

  ports {
    internal = 9054
    external = 9054
  }

  env = [
    "FABRIC_CA_HOME=/etc/hyperledger/fabric-ca-server",
    "FABRIC_CA_SERVER_CA_NAME=ca-orderer",
    "FABRIC_CA_SERVER_TLS_ENABLED=true",
    "FABRIC_CA_SERVER_PORT=9054",
    "FABRIC_CA_SERVER_OPERATIONS_LISTENADDRESS=0.0.0.0:19054"
  ]

  command = ["sh", "-c", "fabric-ca-server start -b admin:adminpw -d"]

  volumes {
    host_path      = abspath("${path.module}/../../../blockchain/hyperledger/network/organizations/fabric-ca/ordererOrg")
    container_path = "/etc/hyperledger/fabric-ca-server"
  }
}

# =============================================================================
# HYPERLEDGER FABRIC - CouchDB State Databases
# =============================================================================

resource "docker_container" "couchdb0_org1" {
  name  = "couchdb0.org1.${var.project_name}.com"
  image = docker_image.couchdb.image_id

  networks_advanced {
    name = docker_network.experiment_network.name
  }

  ports {
    internal = 5984
    external = 5984
  }

  env = [
    "COUCHDB_USER=admin",
    "COUCHDB_PASSWORD=adminpw"
  ]
}

resource "docker_container" "couchdb0_org2" {
  name  = "couchdb0.org2.${var.project_name}.com"
  image = docker_image.couchdb.image_id

  networks_advanced {
    name = docker_network.experiment_network.name
  }

  ports {
    internal = 5984
    external = 7984
  }

  env = [
    "COUCHDB_USER=admin",
    "COUCHDB_PASSWORD=adminpw"
  ]
}

# =============================================================================
# HYPERLEDGER FABRIC - Orderer
# =============================================================================

resource "docker_container" "orderer" {
  name  = "orderer.${var.project_name}.com"
  image = docker_image.fabric_orderer.image_id

  depends_on = [docker_container.ca_orderer]

  networks_advanced {
    name    = docker_network.experiment_network.name
    aliases = ["orderer.aam.com"]
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
    "ORDERER_OPERATIONS_LISTENADDRESS=0.0.0.0:9443",
    "ORDERER_METRICS_PROVIDER=prometheus"
  ]

  working_dir = "/root"
  command     = ["orderer"]

  volumes {
    host_path      = abspath("${path.module}/../../../blockchain/hyperledger/network/organizations/ordererOrganizations/aam.com/orderers/orderer.aam.com/msp")
    container_path = "/var/hyperledger/orderer/msp"
  }

  volumes {
    host_path      = abspath("${path.module}/../../../blockchain/hyperledger/network/organizations/ordererOrganizations/aam.com/orderers/orderer.aam.com/tls")
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

# =============================================================================
# HYPERLEDGER FABRIC - Peers
# =============================================================================

# Peer0 - Org1
resource "docker_container" "peer0_org1" {
  name  = "peer0.org1.${var.project_name}.com"
  image = docker_image.fabric_peer.image_id

  depends_on = [
    docker_container.couchdb0_org1,
    docker_container.orderer
  ]

  networks_advanced {
    name    = docker_network.experiment_network.name
    aliases = ["peer0.org1.aam.com"]
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
    "CORE_PEER_ID=peer0.org1.aam.com",
    "CORE_PEER_ADDRESS=peer0.org1.aam.com:7051",
    "CORE_PEER_LISTENADDRESS=0.0.0.0:7051",
    "CORE_PEER_CHAINCODEADDRESS=peer0.org1.aam.com:7052",
    "CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:7052",
    "CORE_PEER_GOSSIP_BOOTSTRAP=peer0.org1.aam.com:7051",
    "CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer0.org1.aam.com:7051",
    "CORE_PEER_LOCALMSPID=Org1MSP",
    "CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp",
    "CORE_OPERATIONS_LISTENADDRESS=0.0.0.0:9444",
    "CORE_METRICS_PROVIDER=prometheus",
    "CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG={\"peername\":\"peer0org1\"}",
    "CORE_CHAINCODE_EXECUTETIMEOUT=300s",
    "CORE_LEDGER_STATE_STATEDATABASE=CouchDB",
    "CORE_LEDGER_STATE_COUCHDBCONFIG_COUCHDBADDRESS=couchdb0.org1.${var.project_name}.com:5984",
    "CORE_LEDGER_STATE_COUCHDBCONFIG_USERNAME=admin",
    "CORE_LEDGER_STATE_COUCHDBCONFIG_PASSWORD=adminpw"
  ]

  working_dir = "/root"
  command     = ["peer", "node", "start"]

  volumes {
    host_path      = abspath("${path.module}/../../../blockchain/hyperledger/network/organizations/peerOrganizations/org1.aam.com/peers/peer0.org1.aam.com")
    container_path = "/etc/hyperledger/fabric"
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

# Peer0 - Org2
resource "docker_container" "peer0_org2" {
  name  = "peer0.org2.${var.project_name}.com"
  image = docker_image.fabric_peer.image_id

  depends_on = [
    docker_container.couchdb0_org2,
    docker_container.orderer
  ]

  networks_advanced {
    name    = docker_network.experiment_network.name
    aliases = ["peer0.org2.aam.com"]
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
    "CORE_PEER_ID=peer0.org2.aam.com",
    "CORE_PEER_ADDRESS=peer0.org2.aam.com:9051",
    "CORE_PEER_LISTENADDRESS=0.0.0.0:9051",
    "CORE_PEER_CHAINCODEADDRESS=peer0.org2.aam.com:9052",
    "CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:9052",
    "CORE_PEER_GOSSIP_BOOTSTRAP=peer0.org2.aam.com:9051",
    "CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer0.org2.aam.com:9051",
    "CORE_PEER_LOCALMSPID=Org2MSP",
    "CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp",
    "CORE_OPERATIONS_LISTENADDRESS=0.0.0.0:9445",
    "CORE_METRICS_PROVIDER=prometheus",
    "CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG={\"peername\":\"peer0org2\"}",
    "CORE_CHAINCODE_EXECUTETIMEOUT=300s",
    "CORE_LEDGER_STATE_STATEDATABASE=CouchDB",
    "CORE_LEDGER_STATE_COUCHDBCONFIG_COUCHDBADDRESS=couchdb0.org2.${var.project_name}.com:5984",
    "CORE_LEDGER_STATE_COUCHDBCONFIG_USERNAME=admin",
    "CORE_LEDGER_STATE_COUCHDBCONFIG_PASSWORD=adminpw"
  ]

  working_dir = "/root"
  command     = ["peer", "node", "start"]

  volumes {
    host_path      = abspath("${path.module}/../../../blockchain/hyperledger/network/organizations/peerOrganizations/org2.aam.com/peers/peer0.org2.aam.com")
    container_path = "/etc/hyperledger/fabric"
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
# HYPERLEDGER FABRIC - CLI
# =============================================================================

resource "docker_container" "fabric_cli" {
  name  = "${var.project_name}-fabric-cli"
  image = docker_image.fabric_tools.image_id

  depends_on = [
    docker_container.peer0_org1,
    docker_container.peer0_org2,
    docker_container.orderer
  ]

  networks_advanced {
    name = docker_network.experiment_network.name
  }

  tty        = true
  stdin_open = true

  env = [
    "GOPATH=/opt/gopath",
    "FABRIC_LOGGING_SPEC=INFO",
    "CORE_PEER_ID=cli",
    "CORE_PEER_ADDRESS=peer0.org1.aam.com:7051",
    "CORE_PEER_LOCALMSPID=Org1MSP",
    "CORE_PEER_TLS_ENABLED=true",
    "CORE_PEER_TLS_CERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/org1.aam.com/peers/peer0.org1.aam.com/tls/server.crt",
    "CORE_PEER_TLS_KEY_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/org1.aam.com/peers/peer0.org1.aam.com/tls/server.key",
    "CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/org1.aam.com/peers/peer0.org1.aam.com/tls/ca.crt",
    "CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/org1.aam.com/users/Admin@org1.aam.com/msp"
  ]

  working_dir = "/opt/gopath/src/github.com/hyperledger/fabric/peer"
  command     = ["/bin/bash"]

  volumes {
    host_path      = abspath("${path.module}/../../../blockchain/hyperledger/network/organizations")
    container_path = "/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations"
  }

  volumes {
    host_path      = abspath("${path.module}/../../../blockchain/hyperledger/chaincode")
    container_path = "/opt/gopath/src/github.com/hyperledger/fabric/peer/chaincode"
  }

  volumes {
    host_path      = abspath("${path.module}/../../../blockchain/hyperledger/scripts")
    container_path = "/opt/gopath/src/github.com/hyperledger/fabric/peer/scripts"
  }

  volumes {
    host_path      = "/var/run/docker.sock"
    container_path = "/host/var/run/docker.sock"
  }
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
    password = "aam_password"
    url      = "postgresql://aam_user:aam_password@localhost:5432/aam_security"
  }
  sensitive = true
}

output "solana" {
  description = "Solana validator endpoints"
  value = {
    rpc_url       = "http://localhost:8899"
    ws_url        = "ws://localhost:8900"
    faucet_url    = "http://localhost:9900"
    container     = docker_container.solana_validator.name
  }
}

output "hyperledger" {
  description = "Hyperledger Fabric endpoints"
  value = {
    orderer_endpoint = "localhost:7050"
    peer0_org1       = "localhost:7051"
    peer0_org2       = "localhost:9051"
    ca_org1          = "https://localhost:7054"
    ca_org2          = "https://localhost:8054"
    couchdb_org1     = "http://localhost:5984/_utils"
    couchdb_org2     = "http://localhost:7984/_utils"
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
    postgres         = docker_container.postgres.name
    solana_validator = docker_container.solana_validator.name
    fabric_orderer   = docker_container.orderer.name
    fabric_peer0_org1 = docker_container.peer0_org1.name
    fabric_peer0_org2 = docker_container.peer0_org2.name
    fabric_cli       = docker_container.fabric_cli.name
    prometheus       = docker_container.prometheus.name
    grafana          = docker_container.grafana.name
  }
}
