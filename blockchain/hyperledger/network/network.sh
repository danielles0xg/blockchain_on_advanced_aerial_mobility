#!/usr/bin/env bash
# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# =============================================================================
# AAM Security - Hyperledger Fabric network manager
# =============================================================================
# Self-contained 3-orderer Raft network (Org1 + Org2, LevelDB) for reproducing
# the Fabric results in the paper. Modeled on the Fabric 2.5 test-network.
#
# Typical flow:
#   ./network.sh install        # one-time: fetch Fabric 2.5.10 binaries + images
#   ./network.sh up             # crypto + start 3 orderers + 2 peers
#   ./network.sh createChannel  # create + join 'aamchannel'
#   ./network.sh deployCC       # package/install/approve/commit aam_security cc
#   ./network.sh down           # tear everything down and clean generated state
#
# Or all at once:  ./network.sh up createChannel deployCC
# =============================================================================

set -o pipefail

export NETWORK_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$NETWORK_HOME"

. "${NETWORK_HOME}/scripts/utils.sh"

# ----- configurable parameters -----------------------------------------------
FABRIC_VERSION="2.5.10"
CA_VERSION="1.5.13"
CHANNEL_NAME="${CHANNEL_NAME:-aamchannel}"
CC_NAME="${CC_NAME:-aam_security}"
CC_SRC_PATH="${NETWORK_HOME}/../chaincode/aam_security"
CC_VERSION="${CC_VERSION:-1.0}"
CC_SEQUENCE="${CC_SEQUENCE:-1}"
CC_POLICY="AND('Org1MSP.peer','Org2MSP.peer')"   # matches the paper
DELAY=3
MAX_RETRY=5

export DOCKER_SOCK="${DOCKER_SOCK:-/var/run/docker.sock}"
export PATH="${NETWORK_HOME}/bin:${HOME}/fabric-samples/bin:${PATH}"
# core.yaml / orderer.yaml live in the fetched config dir (used by peer/osnadmin CLI)
export FABRIC_CFG_PATH="${NETWORK_HOME}/config"

COMPOSE_FILE="compose/compose-aam-net.yaml"

if command -v docker-compose >/dev/null 2>&1; then
  DOCKER_COMPOSE="docker-compose"
else
  DOCKER_COMPOSE="docker compose"
fi

# -----------------------------------------------------------------------------
checkTools() {
  for t in cryptogen configtxgen peer osnadmin; do
    if ! command -v "$t" >/dev/null 2>&1; then
      fatalln "'$t' not found on PATH. Run './network.sh install' first (or add fabric bin/ to PATH)."
    fi
  done
  command -v docker >/dev/null 2>&1 || fatalln "docker not found."
}

# -----------------------------------------------------------------------------
installFabric() {
  infoln "Installing Hyperledger Fabric ${FABRIC_VERSION} binaries + docker images into ${NETWORK_HOME}"
  curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh -o install-fabric.sh
  chmod +x install-fabric.sh
  ./install-fabric.sh --fabric-version "${FABRIC_VERSION}" --ca-version "${CA_VERSION}" binary docker
  successln "Fabric binaries installed to ${NETWORK_HOME}/bin and config to ${NETWORK_HOME}/config"
}

# -----------------------------------------------------------------------------
generateCrypto() {
  infoln "Generating crypto material with cryptogen"
  rm -rf organizations/ordererOrganizations organizations/peerOrganizations
  cryptogen generate --config=./organizations/cryptogen/crypto-config-org1.yaml --output="organizations"
  verifyResult $? "cryptogen (org1) failed"
  cryptogen generate --config=./organizations/cryptogen/crypto-config-org2.yaml --output="organizations"
  verifyResult $? "cryptogen (org2) failed"
  cryptogen generate --config=./organizations/cryptogen/crypto-config-orderer.yaml --output="organizations"
  verifyResult $? "cryptogen (orderer) failed"
  successln "Crypto material generated under organizations/"
}

# -----------------------------------------------------------------------------
networkUp() {
  checkTools
  if [ ! -d "organizations/peerOrganizations" ]; then
    generateCrypto
  fi
  infoln "Starting 3 orderers + 2 peers"
  DOCKER_SOCK="${DOCKER_SOCK}" ${DOCKER_COMPOSE} -f "${COMPOSE_FILE}" up -d
  verifyResult $? "Failed to start docker containers"
  sleep "${DELAY}"
  docker ps --filter "label=service=hyperledger-fabric" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
  successln "Network is up"
}

# -----------------------------------------------------------------------------
createChannelGenesisBlock() {
  mkdir -p channel-artifacts
  local cfg="${FABRIC_CFG_PATH}"
  export FABRIC_CFG_PATH="${NETWORK_HOME}/configtx"
  infoln "Generating genesis block for '${CHANNEL_NAME}'"
  configtxgen -profile ChannelUsingRaft \
    -outputBlock "./channel-artifacts/${CHANNEL_NAME}.block" -channelID "${CHANNEL_NAME}"
  verifyResult $? "configtxgen failed to create the channel genesis block"
  export FABRIC_CFG_PATH="${cfg}"
}

# joinOrderer <admin-port> <orderer-host>
joinOrderer() {
  local port=$1 host=$2
  osnadmin channel join --channelID "${CHANNEL_NAME}" \
    --config-block "./channel-artifacts/${CHANNEL_NAME}.block" \
    -o "localhost:${port}" --ca-file "$ORDERER_CA" \
    --client-cert "${NETWORK_HOME}/organizations/ordererOrganizations/example.com/orderers/${host}/tls/server.crt" \
    --client-key  "${NETWORK_HOME}/organizations/ordererOrganizations/example.com/orderers/${host}/tls/server.key"
}

createChannel() {
  checkTools
  . "${NETWORK_HOME}/scripts/envVar.sh"
  createChannelGenesisBlock

  infoln "Joining 3 orderers to '${CHANNEL_NAME}'"
  local rc=1 counter=1
  while [ $rc -ne 0 ] && [ $counter -lt $MAX_RETRY ]; do
    sleep "${DELAY}"
    joinOrderer 7053 orderer.example.com  && \
    joinOrderer 7055 orderer2.example.com && \
    joinOrderer 7057 orderer3.example.com
    rc=$?
    counter=$((counter + 1))
  done
  verifyResult $rc "Orderers failed to join channel '${CHANNEL_NAME}'"

  infoln "Joining peers to '${CHANNEL_NAME}'"
  local org
  for org in 1 2; do
    setGlobals "$org"
    local prc=1 pc=1
    while [ $prc -ne 0 ] && [ $pc -lt $MAX_RETRY ]; do
      sleep "${DELAY}"
      peer channel join -b "./channel-artifacts/${CHANNEL_NAME}.block"
      prc=$?
      pc=$((pc + 1))
    done
    verifyResult $prc "peer0.org${org} failed to join '${CHANNEL_NAME}'"
  done
  successln "Channel '${CHANNEL_NAME}' created and joined by both peers"
  warnln "Note: anchor peers are not set; the load tester targets both peers explicitly to satisfy AND endorsement."
}

# -----------------------------------------------------------------------------
deployCC() {
  checkTools
  command -v go >/dev/null 2>&1 || fatalln "Go is required to vendor the chaincode."
  . "${NETWORK_HOME}/scripts/envVar.sh"

  infoln "Vendoring chaincode dependencies"
  ( cd "${CC_SRC_PATH}" && GOFLAGS=-mod=mod go mod vendor )
  verifyResult $? "go mod vendor failed"

  infoln "Packaging chaincode"
  peer lifecycle chaincode package "${CC_NAME}.tar.gz" \
    --path "${CC_SRC_PATH}" --lang golang --label "${CC_NAME}_${CC_VERSION}"
  verifyResult $? "Chaincode packaging failed"
  local PACKAGE_ID
  PACKAGE_ID=$(peer lifecycle chaincode calculatepackageid "${CC_NAME}.tar.gz")
  infoln "Package ID: ${PACKAGE_ID}"

  local org
  for org in 1 2; do
    setGlobals "$org"
    infoln "Installing chaincode on peer0.org${org}"
    peer lifecycle chaincode install "${CC_NAME}.tar.gz"
    verifyResult $? "Install on org${org} failed"
    infoln "Approving chaincode for Org${org}"
    peer lifecycle chaincode approveformyorg -o localhost:7050 \
      --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
      --channelID "${CHANNEL_NAME}" --name "${CC_NAME}" --version "${CC_VERSION}" \
      --package-id "${PACKAGE_ID}" --sequence "${CC_SEQUENCE}" --signature-policy "${CC_POLICY}"
    verifyResult $? "Approve for org${org} failed"
  done

  infoln "Checking commit readiness"
  peer lifecycle chaincode checkcommitreadiness --channelID "${CHANNEL_NAME}" \
    --name "${CC_NAME}" --version "${CC_VERSION}" --sequence "${CC_SEQUENCE}" \
    --signature-policy "${CC_POLICY}" --output json

  infoln "Committing chaincode definition"
  parsePeerConnectionParameters 1 2
  peer lifecycle chaincode commit -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
    --channelID "${CHANNEL_NAME}" --name "${CC_NAME}" --version "${CC_VERSION}" \
    --sequence "${CC_SEQUENCE}" --signature-policy "${CC_POLICY}" "${PEER_CONN_PARMS[@]}"
  verifyResult $? "Chaincode commit failed"

  setGlobals 1
  peer lifecycle chaincode querycommitted --channelID "${CHANNEL_NAME}" --name "${CC_NAME}"
  successln "Chaincode '${CC_NAME}' deployed with policy ${CC_POLICY}"
}

# -----------------------------------------------------------------------------
networkDown() {
  infoln "Stopping containers and cleaning generated artifacts"
  DOCKER_SOCK="${DOCKER_SOCK}" ${DOCKER_COMPOSE} -f "${COMPOSE_FILE}" down --volumes --remove-orphans 2>/dev/null
  rm -rf organizations/ordererOrganizations organizations/peerOrganizations
  rm -rf channel-artifacts "${CC_NAME}.tar.gz" log.txt
  rm -rf "${CC_SRC_PATH}/vendor"
  # remove dangling chaincode containers/images
  docker rm -f $(docker ps -aq --filter "name=dev-peer") 2>/dev/null || true
  successln "Network down and cleaned"
}

# -----------------------------------------------------------------------------
printHelp() {
  cat <<EOF
Usage: ./network.sh <command> [<command> ...]

Commands:
  install        Download Fabric ${FABRIC_VERSION} binaries + docker images into this dir
  generate       Generate crypto material only (cryptogen) - used by the Terraform path
  up             Generate crypto (if needed) and start 3 orderers + 2 peers
  createChannel  Create and join channel '${CHANNEL_NAME}'
  deployCC       Package/install/approve/commit the '${CC_NAME}' chaincode
  down           Stop everything and remove generated crypto/artifacts
  restart        down + up
  help           Show this help

Env overrides: CHANNEL_NAME, CC_NAME, CC_VERSION, CC_SEQUENCE, DOCKER_SOCK
EOF
}

# -----------------------------------------------------------------------------
[ $# -eq 0 ] && { printHelp; exit 0; }
for cmd in "$@"; do
  case "$cmd" in
    install)       installFabric ;;
    generate)      checkTools; generateCrypto ;;
    up)            networkUp ;;
    createChannel) createChannel ;;
    deployCC)      deployCC ;;
    down)          networkDown ;;
    restart)       networkDown; networkUp ;;
    help|-h|--help) printHelp ;;
    *) errorln "Unknown command: $cmd"; printHelp; exit 1 ;;
  esac
done
