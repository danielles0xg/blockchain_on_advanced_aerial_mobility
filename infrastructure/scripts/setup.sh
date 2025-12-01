#!/bin/bash
# =============================================================================
# AAM Security Experiment - Setup Script
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "========================================"
echo "AAM Security Experiment Setup"
echo "========================================"
echo "Project root: $PROJECT_ROOT"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."

    # Docker
    if command -v docker &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Docker: $(docker --version)"
    else
        echo -e "  ${RED}✗${NC} Docker not found"
        exit 1
    fi

    # Terraform
    if command -v terraform &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Terraform: $(terraform version -json | jq -r '.terraform_version')"
    else
        echo -e "  ${RED}✗${NC} Terraform not found"
        exit 1
    fi

    # Python
    if command -v python3 &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Python: $(python3 --version)"
    else
        echo -e "  ${RED}✗${NC} Python 3 not found"
        exit 1
    fi

    # Go (optional for chaincode development)
    if command -v go &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Go: $(go version)"
    else
        echo -e "  ${YELLOW}!${NC} Go not found (optional for Hyperledger chaincode)"
    fi

    # Rust/Anchor (optional for Solana development)
    if command -v anchor &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Anchor: $(anchor --version)"
    else
        echo -e "  ${YELLOW}!${NC} Anchor not found (optional for Solana program)"
    fi

    echo ""
}

# Create required directories
create_directories() {
    echo "Creating directories..."

    # Hyperledger Fabric directories
    mkdir -p "$PROJECT_ROOT/blockchain/hyperledger/network/organizations/fabric-ca/org1"
    mkdir -p "$PROJECT_ROOT/blockchain/hyperledger/network/organizations/fabric-ca/org2"
    mkdir -p "$PROJECT_ROOT/blockchain/hyperledger/network/organizations/fabric-ca/ordererOrg"
    mkdir -p "$PROJECT_ROOT/blockchain/hyperledger/network/organizations/peerOrganizations"
    mkdir -p "$PROJECT_ROOT/blockchain/hyperledger/network/organizations/ordererOrganizations"

    # Data directories
    mkdir -p "$PROJECT_ROOT/data/raw"
    mkdir -p "$PROJECT_ROOT/data/processed"

    # Results directories
    mkdir -p "$PROJECT_ROOT/results/metrics"
    mkdir -p "$PROJECT_ROOT/results/reports"
    mkdir -p "$PROJECT_ROOT/results/plots"

    echo -e "  ${GREEN}✓${NC} Directories created"
    echo ""
}

# Install Python dependencies
install_python_deps() {
    echo "Installing Python dependencies..."

    cd "$PROJECT_ROOT"

    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt --quiet
        echo -e "  ${GREEN}✓${NC} Python dependencies installed"
    else
        echo -e "  ${YELLOW}!${NC} requirements.txt not found"
    fi

    echo ""
}

# Initialize Terraform
init_terraform() {
    echo "Initializing Terraform..."

    cd "$PROJECT_ROOT/infrastructure/terraform/local"
    terraform init -input=false

    echo -e "  ${GREEN}✓${NC} Terraform initialized"
    echo ""
}

# Deploy infrastructure
deploy_infrastructure() {
    echo "Deploying local infrastructure..."
    echo -e "  ${YELLOW}!${NC} This will start Docker containers for PostgreSQL, Solana, and Hyperledger Fabric"
    echo ""

    read -p "Continue with deployment? (y/n) " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cd "$PROJECT_ROOT/infrastructure/terraform/local"
        terraform apply -auto-approve

        echo ""
        echo -e "  ${GREEN}✓${NC} Infrastructure deployed"

        # Show endpoints
        echo ""
        echo "Endpoints:"
        terraform output -json | jq -r '
            "  PostgreSQL: " + .postgres.value.url,
            "  Solana RPC: " + .solana.value.rpc_url,
            "  Hyperledger Peer: " + .hyperledger.value.peer0_org1,
            "  Prometheus: " + .monitoring.value.prometheus,
            "  Grafana: " + .monitoring.value.grafana
        '
    else
        echo "Skipping deployment"
    fi

    echo ""
}

# Generate synthetic test data
generate_test_data() {
    echo "Generating synthetic test data..."

    cd "$PROJECT_ROOT"
    python3 -c "
from src.event_generator.generator import DatasetLoader
from pathlib import Path

loader = DatasetLoader(Path('data'))
df = loader.create_synthetic_dataset(num_events=10000)
print(f'  Generated {len(df)} synthetic events')
"

    echo -e "  ${GREEN}✓${NC} Test data generated"
    echo ""
}

# Run quick test
run_quick_test() {
    echo "Running quick test (PostgreSQL only)..."

    cd "$PROJECT_ROOT"

    python3 -c "
import asyncio
from src.clients.postgres_client.client import PostgresClient
from src.event_generator.generator import EventGenerator

# Test connection
try:
    client = PostgresClient()
    client.connect()

    # Generate and log test event
    generator = EventGenerator()
    event = generator.generate_random_events(1)[0]
    result = client.log_event(event)

    if result.success:
        print(f'  Event logged: ID={result.event_id}, latency={result.latency_ms:.2f}ms')
        print('  PostgreSQL connection: OK')
    else:
        print(f'  Error: {result.error_message}')

    client.disconnect()
except Exception as e:
    print(f'  PostgreSQL not available: {e}')
    print('  (This is expected if infrastructure is not deployed)')
"

    echo ""
}

# Print next steps
print_next_steps() {
    echo "========================================"
    echo "Setup Complete!"
    echo "========================================"
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Deploy infrastructure (if not done):"
    echo "   cd infrastructure/terraform/local && terraform apply"
    echo ""
    echo "2. Run PostgreSQL baseline experiment:"
    echo "   python src/run_experiment.py --systems postgresql --scenario both"
    echo ""
    echo "3. Deploy and test Solana program:"
    echo "   cd blockchain/solana && anchor build && anchor deploy"
    echo ""
    echo "4. Deploy and test Hyperledger chaincode:"
    echo "   cd blockchain/hyperledger && ./scripts/deploy_chaincode.sh"
    echo ""
    echo "5. Run full experiment:"
    echo "   python src/run_experiment.py --systems postgresql solana hyperledger"
    echo ""
    echo "Documentation: README.md"
    echo ""
}

# Main
main() {
    check_prerequisites
    create_directories
    install_python_deps
    init_terraform

    read -p "Deploy infrastructure now? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        deploy_infrastructure
        generate_test_data
        run_quick_test
    fi

    print_next_steps
}

# Run main function
main "$@"
