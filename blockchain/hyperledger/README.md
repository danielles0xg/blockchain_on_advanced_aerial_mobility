# Hyperledger Fabric — AAM Security Network

Self-contained Hyperledger Fabric **2.5.10** network used to reproduce the paper's
Fabric results. Topology matches the paper:

- **3 Raft orderers** (`orderer`, `orderer2`, `orderer3` @ `example.com`)
- **2 organizations** (`Org1`, `Org2`), one peer each
- **Channel** `aamchannel`
- **State DB** LevelDB
- **Endorsement policy** `AND('Org1MSP.peer','Org2MSP.peer')`
- **Chaincode** `aam_security` (Go), see [`chaincode/aam_security`](chaincode/aam_security)

```
chaincode/aam_security/      Go chaincode (LogSecurityEvent, GetEvent, ...)
network/
├── network.sh               One-stop manager (install/up/createChannel/deployCC/down)
├── configtx/configtx.yaml   3-consenter Raft channel profile
├── organizations/cryptogen/ crypto-config-{orderer,org1,org2}.yaml
├── compose/compose-aam-net.yaml   3 orderers + 2 peers (LevelDB)
├── compose/docker/peercfg/core.yaml
└── scripts/                 envVar.sh, utils.sh
```

## Prerequisites

- Docker + Docker Compose (daemon running)
- Go ≥ 1.21 (to vendor the chaincode at deploy time)
- `curl` (used by `network.sh install`)

## Quick start

```bash
cd blockchain/hyperledger/network

./network.sh install                    # one-time: fetch Fabric 2.5.10 bin + images
./network.sh up createChannel deployCC  # crypto + start + channel + chaincode
```

`./network.sh up` generates crypto with `cryptogen` (if not already present) and
starts the containers. `createChannel` builds the genesis block with `configtxgen`,
joins all 3 orderers via `osnadmin`, and joins both peers. `deployCC` vendors,
packages, installs, approves (both orgs), and commits the chaincode.

Tear down (removes containers + generated crypto/artifacts):

```bash
./network.sh down
```

## Run the load test against this network

```bash
# from repo root, with the network up + chaincode deployed
python blast.py --target hyperledger --peer localhost:7051 --tps 1 --duration 30
```

`blast.py` defaults to this repo's network (`blockchain/hyperledger/network`).
Override with `FABRIC_NETWORK_HOME`, `FABRIC_BIN`, `FABRIC_CFG_PATH` if you use an
external Fabric install.

## Ports

| Node | General | Admin | Operations |
|------|--------:|------:|-----------:|
| orderer  | 7050 | 7053 | 9443 |
| orderer2 | 7052 | 7055 | 9446 |
| orderer3 | 7056 | 7057 | 9447 |
| peer0.org1 | 7051 | — | 9444 |
| peer0.org2 | 9051 | — | 9445 |

## Terraform alternative

`infrastructure/terraform/local/main.tf` brings up the same topology via the
Docker provider. It consumes the cryptogen output, so run crypto generation first:

```bash
cd blockchain/hyperledger/network && ./network.sh install && ./network.sh generate
cd ../../../infrastructure/terraform/local && terraform init && terraform apply
cd ../../../blockchain/hyperledger/network && ./network.sh createChannel deployCC
```

> The `network.sh` + compose path is the primary, tested path. Terraform is
> provided as an IaC alternative.

## Notes / caveats

- **LevelDB** (per the paper). The chaincode's rich-query helpers
  (`GetEventsByVehicle`, `GetEventsByType`) require CouchDB and will return an
  error under LevelDB. The load test only exercises `LogSecurityEvent`, which
  works on LevelDB. Switch the peers to CouchDB if you need rich queries.
- **Anchor peers are not configured.** The load tester targets both peers
  explicitly (`--peerAddresses`) so `AND(Org1, Org2)` endorsement is satisfied
  without anchor-peer–based service discovery.
- Validated here: chaincode compiles, `cryptogen` + `configtxgen` build the
  genesis block, the compose file and Terraform config parse/validate. A full
  live bring-up requires a running Docker daemon.
