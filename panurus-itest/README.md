# RD and DFABI on Fabric-X with Panurus

Privacy-preserving RD (cash) and DFABI (bond) with Panurus (ZKAT-DLOG driver) on Fabric-X.
BI is issuer of both tokens and DFABI custodian; `bank2..bank4` own tokens. Amounts, token types and owners are hidden
from every other participant (zero-knowledge proofs, Idemix pseudonyms).

Every institution is its own organisation and runs its own orderer party, committer and FSC endorser, so banks keep
transacting while BI or any one bank is down:

| Institution | Orderer party (Arma BFT) | MSP | CA | Committer | FSC nodes |
|---|---|---|---|---|---|
| BI | 1 | `Org1MSP` | `fca-org1` | cluster (`committer-*`, NodePorts 30560/30580) | `issuer`, `endorser-1` |
| Bank A | 2 | `OrdererOrg2MSP` | `fca-orderer-org2` | `committer-bank2` (127.0.0.1:25130/25140) | `bank2`, `endorser-2` |
| Bank B | 3 | `OrdererOrg3MSP` | `fca-orderer-org3` | `committer-bank3` (127.0.0.1:35130/35140) | `bank3`, `endorser-3` |
| Bank C | 4 | `OrdererOrg4MSP` | `fca-orderer-org4` | `committer-bank4` (127.0.0.1:45130/45140) | `bank4`, `endorser-4` |

- Token namespace `rd_dfabi`: endorsement policy `OutOf(3, Org1MSP, OrdererOrg2MSP, OrdererOrg3MSP, OrdererOrg4MSP)`.
- Channel `LifecycleEndorsement` (who may create or change a namespace): all four organisations.
- Public parameters list **no auditor**. With an auditor Panurus requires its signature on every token request
  (`token/core/common/validator_auditing.go`), which stops every transfer while BI is offline. BI learns about
  bank-to-bank transactions from the banks' reports instead (below).

## Reports to BI

After finality the bank that initiated a transaction sends BI the full token request (`rdbi/report`): the actions
plus the metadata with the openings (amount, token type, blinding factors) and the owners' audit information. BI
runs the check a Panurus auditor runs (`AuditCheck`: the openings must match the commitments) and stores the request
in its audit store, whose finality listener compares it with the token request hash on the ledger. A forged or
altered report is refused. The driver reports after every issue, transfer, swap and burn; while BI is offline the
report fails and the transaction stays final.

- `rdbi-driver report` (`make live-report`): every node sends what it holds, pass after pass until nothing new is
  recorded (BI needs the openings of a transaction's inputs from an earlier report, so reports must arrive in causal
  order). A receiver's copy lacks the other parties' openings and is refused; the initiator's copy is accepted.
- `scripts/reconcile.py` (`make live-reconcile`): every token transaction on the ledger (token request key in
  `ns_rd_dfabi` of BI's committer) must have a confirmed record at BI; lists the gaps, exit 1 if any.
- `rdbi-driver audited`: BI's records, one line per movement (sender, recipient, amount, type, ledger status).

This is a detective control: a bank can delay or withhold a report, and BI finds it with the reconciliation.

## Committer per bank

`../multiorg/committer` runs Fabric-X committer 1.0.4 (sidecar, coordinator, validator-committer, verifier, query
service, Postgres) per bank with docker compose on this host: `committer.sh up|down|status [bank…]`
(`make live-committers`). Each pulls blocks from the four assemblers (NodePorts 30052..30352,
`assembler-nodeports.yaml`, forwarded through the docker bridge by the forward shim because the config block names
them by their in-cluster names) and signs as `committer-<bank>` from the bank's CA. A bank's FSC nodes read the
ledger only from their own committer (`assemble.py`; `BANK_COMMITTERS=0` points them back at BI's).

| What | Where |
|---|---|
| Local integration test (own Fabric-X in docker, upstream code) | `make test` (not yet updated to this topology) |
| Live deployment against the existing Fabric-X network | `make live-*` (below) |
| Channel genesis / config updates | `../multiorg/cfgupdate` |
| Nodes (`rdbi/cmd/node`) and scenario driver (`rdbi/cmd/driver`) | same SDK composition as the NWO test nodes |

## Live deployment

Target: Alibaba cluster, k8s namespace `fabricx`, channel `arma`, committer/orderer 1.0.4.

```
make prepare fsc-patch panurus-patch  # Panurus v0.24.0 checkout, tools, patched FSC and Panurus
make live-gen                         # crypto, wallets, public parameters (no process started)
make live-enroll                      # one ledger identity per node at its organisation's CA (FABRIC_CA_CLIENT, KUBECONFIG)
make live-assemble live-build         # retarget generated configs to the network; build rdbi-node / rdbi-driver
make live-start                       # forward shim + 8 FSC nodes
make live-committers                  # one committer per bank (docker), then re-run live-assemble and restart
make live-pp                          # once per namespace (after `fxconfig namespace create`, see below)
make live-scenario                    # issue, transfer, DvP swap, burn; checks balances; reports to BI
make live-report live-reconcile       # catch up reports after BI was offline; ledger vs BI's records
```

Everything private lives in `$RDBI_HOME` (default `~/.fabricx-token`, mode 0700), never in the repo.
The namespace is created with the multi-organisation `fxconfig` flow (`namespace create --output`, `tx endorse` with
one identity of each of the four organisations, `tx merge`, `tx submit`).

`rdbi-driver transfer <from> <to> <type> <amount>` and `rdbi-driver swap <from> <to> <type> <amount> <type> <amount>`
run single operations; `./scripts/run.sh stop-node|start-node <node>` takes one node down or up.

## Channel reset of 2026-11-01

The network was deployed by the `hyperledger.fabricx` Ansible collection 0.8.26, whose `configtx.yaml.j2` sets no
capabilities. The MSPs then run as MSPv1_0, which ignores the admin NodeOU, and every `Admins` policy (every
`mod_policy`) is unsatisfiable: no config update can ever pass. The channel was reset with a new genesis
(`cfgupdate genesis`, checked offline with `cfgupdate check-genesis`): same orgs, crypto and Arma config, plus
capabilities Channel V3_0 / Orderer V2_0 / Application V2_5 (as the fabric-x-orderer v1.0.4 sample), the banks in the
Application group and LifecycleEndorsement 4-of-4. Orderer and sidecar data moved to `/data/v2`; the old chain was
deleted. Backups: `$RDBI_HOME/backup/2026-11-01-pre-multiorg/`.

## Deviations from the upstream, tested path (read before relying on this)

1. **Full certificates instead of cached certificate IDs** (`patches/fsc-full-certificate.patch`). The FSC fabricx
   driver always sends `certificate_id`; the committer only accepts that for certificates listed in the channel config
   (`known_certs`). Ours are not listed. Official route (not taken): add them to `known_certs` with a config update.
2. **Shared submitter identity instead of an Idemix creator.** The channel has no `IdemixOrgMSP`, so the `idemix`
   label is mapped to one Org1MSP identity (`ids/anon`) shared by all nodes; every ledger transaction has the same
   creator. Any node holding that key can sign as the shared creator at the Fabric layer (token ownership is still
   protected by Idemix). Official route (not taken): add an Idemix MSP to the channel config.
3. **Network shim** (`rdbi/cmd/node/netshim.go`): the in-cluster orderer names resolve to 127.0.0.1 and a forwarder
   maps 7050/7150/7250/7350 to the router NodePorts.
4. **Panurus patches** (`patches/panurus-*.patch`, applied by `make panurus-patch`):
   - `endorser-failover`: the `namespace` endorser selector picks a random policy-satisfying set and knows nothing
     about reachability, so with one endorser down most 3-of-4 attempts failed. On failure the request is retried
     without each configured endorser in turn; the endorser store accepts the retried, identical request for a txid
     it already recorded (a different request is still refused). Handles one unreachable endorser.
   - `sequential-remote-signatures`: remote owner signatures were requested concurrently per signer identity; a
     counterparty paying with two tokens has two identities on one node, the requests interleaved on its session and
     the DvP failed with `signer identity mismatch`. They are now requested one after the other.
   - `auditor-limits`: the demo holding limit (3000) in the recipient view is configurable via `policy.env`.
   - `issuer-keeps-audit-tokens`: Panurus stores the outputs of an audited transaction as audit tokens only on a node
     that holds an auditor wallet listed in the public parameters. With no auditor listed, the node holding a listed
     issuer wallet (BI) now does, so that the check of a later report finds the openings of its inputs.
5. **One-off migration of BI's store (2026-11-01).** Transactions from before the reports existed: the tokens BI had
   issued were marked as audit tokens, and the stale rows of two earlier burns were removed so they could be
   recorded again (Panurus skips a transaction whose tokens it already holds). Backups:
   `$RDBI_HOME/backup/2026-11-01-report-migration*`.
6. **Bank committers' Postgres without TLS** on the bank's own compose network (not published to the host); the
   password is passed as an environment variable, so `docker inspect` shows it to whoever controls the host.

## Test results (live, 2026-11-01)

- Scenario (issue RD/DFABI, transfer RD and DFABI, DvP, burn) and the negative cases (no issue view on banks, overspend,
  atomic DvP refusals, unknown recipient, double spend, bank4 untouched): pass.
- BI down (`issuer`, `endorser-1` stopped): transfer and DvP between banks pass. BI's orderer party also down
  (4 pods scaled to 0): transfer passes.
- Bank C down (`bank4`, `endorser-4` stopped): 5 transfers and 3 DvPs between bank2 and bank3 pass.
- BI and Bank C down together: transfer refused (3-of-4 cannot be met), no balance moved.

With a committer per bank and reports to BI (2026-11-01, later):

- Scenario and negative cases pass; every issue, transfer, DvP and burn is recorded by BI right after finality.
- **BI fully down** (`issuer`, `endorser-1`, BI's committer services and orderer party 1 scaled to 0; only BI's
  committer database left running): 3 transfers and 1 DvP between banks final on the banks' committers; reports
  not delivered. After BI was back, `driver report` recorded all 4; reconciliation 41 of 41.
- **Bank C fully down** (`bank4`, `endorser-4`, `committer-bank4`): 2 transfers and 1 DvP between bank2 and bank3,
  each recorded by BI at once; Bank C's committer caught up after restart.
- Reconciliation found a transaction no one had reported (a transfer from a test run) until `driver report` sent it;
  at the end 48 of 48 token transactions on the ledger are confirmed in BI's audit store.

## Known limits

- Reporting is detective, not preventive: BI sees a bank-to-bank transaction only after the bank reports it, and
  finds a missing report with the reconciliation (which reads BI's own committer).
- Issuance and burn need BI (issuer).
- An FSC node exits if its committer's query service is unreachable at start; start the committer first.
- A failed DvP can leave the payer's tokens locked: the sherdlock lease cleanup did not release them on the node's
  SQLite store (rows matched the stale rule but were not deleted); they were released by hand. Root cause not found.
- `scripts/e2e.sh`, `scripts/verify_privacy.py` and `rdbi/rdbi_test.go` still assume the auditor design.
- The nodes and the banks' committers run on one host; the institutions are separate organisations with separate
  keys and databases, and the lab operator holds all CA registrar credentials (logical, not operational, separation).
- Ledger readers see that a token transaction happened (time, size, input ids: NOGH does not hide the spending graph).
- `fxconfig ... --wait` and the sidecar notification stream can hit gRPC `too_many_pings`.
