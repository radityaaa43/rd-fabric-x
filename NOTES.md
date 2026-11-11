# fabric-x upstream pins

Resolved 2026-11-10 by `fabric`. Rule: TEAM.md §6 "Trusted sources only". Commit = what the official repo tag points to (`git ls-remote`, 2026-11-10).

| Component | Repo | Tag | Commit | Pinned at (file:line) |
|-----------|------|-----|--------|-----------------------|
| Panurus (token SDK) | LFDT-Panurus/panurus | v0.24.0 | 5f3c49e2d9e4507138ef330d34d60ec560fd1525 (local checkout `panurus-itest/.work/panurus`, `git log -1`; shallow clone of the tag) | `panurus-itest/Makefile:3` (`PANURUS_TAG`), `:15` (clone) |
| Fabric Smart Client | hyperledger-labs/fabric-smart-client | v0.24.0 | 86539af4967445249dc778403bf6cba23116ef3d (Go module cache `.../@v/v0.24.0.info`, Origin.Hash) | `panurus-itest/.work/panurus/integration/go.mod:14`; patched copy via `replace` at `integration/go.mod:254` (`panurus-itest/Makefile` target `fsc-patch`, `patches/fsc-full-certificate.patch`) |
| fabric-x-committer | hyperledger/fabric-x-committer | v1.0.4 | 08a469d2a7074968afde7b2781da5833489f12a0 | `multiorg/committer/compose.yaml:7` (image `docker.io/hyperledger/fabric-x-committer:1.0.4`); live pods use the same tag (kubectl, ns fabricx) |
| fabric-x-orderer (Arma) | hyperledger/fabric-x-orderer | v1.0.4 | dd296e3ff6fb98931b96196f78de174df633ab28 (annotated tag, peeled `^{}`) | live pods `docker.io/hyperledger/fabric-x-orderer:1.0.4` (kubectl, ns fabricx); `panurus-itest/README.md:82` |
| Ansible collection `hyperledger.fabricx` | LF-Decentralized-Trust-labs/fabric-x-ansible-collection | 0.8.26 | 315a91cea0385eb578c636a91e22dd911fa0573c | `~/.ansible/collections/ansible_collections/hyperledger/fabricx/galaxy.yml:9-10`; `panurus-itest/README.md:105` |
| fabric-x-common (Go dep) | hyperledger/fabric-x-common | v0.2.8 | not resolved | `panurus-itest/.work/panurus/go.mod:20` |

[unverified]: the docker image tag `1.0.4` is assumed to be built from git tag `v1.0.4`; the image digest was not compared with a release build.
Not pinned here: upstream `hyperledger/fabric-x` (ls-remote returned no tags).

## Our changes on top of upstream, and the official alternative

Fabric-X custom code is kept; the no-custom rule applies to new work only (user decision 2026-11-10). Every patch and every line of our own code below is tagged **[custom]**.

Asked by `lead` 2026-11-10 (user rule: no custom workarounds on official components). Upstream line refs are on the unpatched tag (Panurus `5f3c49e2`, FSC `86539af4` from the module cache). Diff sizes = added/removed lines of the patch file. "Official alternative" is what the upstream release offers instead; "[unverified]" = not sourced in this session.

| Component | Upstream @ pin | OUR change (file:line, size) | Official alternative |
|-----------|----------------|------------------------------|----------------------|
| Fabric Smart Client | hyperledger-labs/fabric-smart-client@86539af4 (v0.24.0) | **[custom]** `panurus-itest/patches/fsc-full-certificate.patch`: `platform/fabricx/core/transaction/transaction.go` sends the full certificate, not the certificate-ID (+9/-11). Upstream behavior: `transaction.go:770-800` (`toEndorserIdentityWithCertID`, `pemToMSPIdentity`). Applied by `make fsc-patch` (`Makefile:28-29`) as a local copy plus `replace` at `.work/panurus/integration/go.mod` (+3 lines, not committed) | List the signer certs as `known_certs` in the channel config (README:115-117; MSP side `fabric-x-common@v0.2.8:msp/mspimplsetup.go:190`). Needs a config update, impossible on a channel without Capabilities (our own `multiorg/cfgupdate/main.go:10-14` header; upstream Ansible `configtx.yaml.j2` setting no Capabilities: `panurus-itest/README.md:105`); `cfgupdate genesis` writes the capabilities but not `known_certs` [unverified: not checked in the live genesis] |
| Panurus (token SDK) | LFDT-Panurus/panurus@5f3c49e2 (v0.24.0) | **[custom]** 4 patches, applied by `make panurus-patch` (`Makefile:34-36`):<br>**[custom, kept (option A)]** `panurus-endorser-failover.patch` (+100/-0, 4 files incl. 2 tests) retries the namespace-policy endorsement without each endorser in turn; upstream `token/services/network/fabric/endorsement/fsc/service.go:119-138` picks a random set (`:123`, `:126`).<br>**[custom, kept (option A)]** `panurus-sequential-remote-signatures.patch` (+9/-17) removes the fan-out; upstream `token/services/ttx/collectendorsements.go:385` and `:625`.<br>**[custom, kept (option A)]** `panurus-issuer-keeps-audit-tokens.patch` (+24/-0, 2 files): the issuer keeps audit tokens when there is no auditor; upstream `token/core/common/authorization.go:45-55`.<br>**[custom]** `panurus-auditor-limits.patch` (+20/-5, 2 files): holding limit 3000 configurable; upstream `integration/token/fungible/views/accept.go:41,49` (demo view) | Failover: none in v0.24.0 [unverified: newer release not checked]. Sequential signatures: none (upstream fans out in parallel). Audit tokens without auditor: none; the official route is an auditor, which stops transfers while BI is offline (README:29). Limits: none needed if the demo view is not used [unverified whether our flows still call it] |
| fabric-x-committer | hyperledger/fabric-x-committer@08a469d2 (v1.0.4) | Image unmodified (`multiorg/committer/compose.yaml:7`, `panurus-itest/scripts/k8s.py:32`). **[custom]** config only: `multiorg/committer/config/*.yaml`, `compose.yaml`, `committer.sh`, `assembler-nodeports.yaml`. Bank committers' Postgres has no TLS (README deviation 6) | Official sample configs with TLS [unverified: not compared] |
| Orderer (Arma) | hyperledger/fabric-x-orderer@dd296e3f (v1.0.4) | Image unmodified (live pods, ns fabricx). Our choice: banks reuse `OrdererOrg2..4MSP` as application orgs (config, not code) | none needed |
| Ansible collection | LF-Decentralized-Trust-labs/fabric-x-ansible-collection@315a91ce (0.8.26) | Collection not modified [unverified: not diffed against the tag]. Its channel has no Capabilities, so the genesis was replaced by `multiorg/cfgupdate/main.go` (**[custom]** 369 lines, own Go tool, `go.mod` without `replace`): a channel reset with capabilities taken from the fabric-x-orderer v1.0.4 sample `configtx.yaml` (header, `main.go:1-22`) | A newer collection release that sets Capabilities, or the official `configtxgen` of fabric-x-common [unverified: neither checked] |
| rdbi nodes (`rdbi-bi`, `rdbi-bank2..4`) | built from Panurus v0.24.0 + FSC v0.24.0 as above | **[custom]** `panurus-itest/rdbi/` (2,782 Go lines incl. tests; `cmd/driver` 1,466, `award` 581, `report` 262, `cmd/node` 174, `cmd/ppgen` 57, package root 242 incl. `topology.go` 93), copied into the Panurus integration module (`Makefile:6,21,39-40`). **[custom]** own image `ghcr.io/radityaaa43/rdbi-node` on `debian:bookworm-slim` (`k8s/Dockerfile:3-6`, `Makefile:66`), deployed by `scripts/k8s.py` (399 lines). Shared submitter identity instead of an Idemix creator (README deviation 2) | Panurus's own `integration/token/fungible` sample app has no BI report, award, or OPA door [unverified]. Idemix creator: add an Idemix MSP to the channel config (README:121) |
| `cmd/node/netshim.go` | n/a | **[custom]** 130 lines, in-process DNS plus TCP forwards for nodes outside the cluster (README deviation 3). Not referenced in `scripts/k8s.py`, so cluster pods do not use it | In-cluster DNS (what `rdbi-*` pods use) |
| fx-gw gateways (`fx-gw-1..4`) | `envoyproxy/envoy:v1.38.9`, `openpolicyagent/opa:1.21.1-envoy-1-static` (official images, `k8s.py:281-282`) | **[custom]** `driver serve` (`cmd/driver/serve.go`, 346 lines), manifests from `scripts/k8s.py` (`gw render`), rego bundle shared with besu (`fabric-x/opa/DESIGN.md`), `fabric-x/opa/networkpolicy.yaml` (94 lines) | OPA/Envoy ext_authz is the official pattern; the Fabric-X door behind it has no official equivalent [unverified] |
| panurus-itest harness | n/a | **[custom]** `Makefile`, `scripts/*` (1,267 lines), `README.md`; `make test` not updated to the current topology (README:75) | Panurus upstream integration tests (`make integration-tests` in the Panurus repo) [unverified] |

## Operational notes (moved from agents/blockchain/NOTES.md, 2026-11-11)

## Fabric-X (ns fabricx), award image, updated 2026-11-03 05:12Z

1. Image `ghcr.io/radityaaa43/rdbi-node@sha256:71e3b6782215c4c9451148ec318ee39b2d9809a4bc2c4bdeea7d8527572bd675`
   (tag award-69f7e16, private; code 053fb2e + 8659e10 + 579e91e on feat/fabric-x-multibank). Only these containers run it:
   rdbi-bank2/bank2, rdbi-bank3/bank3, rdbi-bank4/bank4, rdbi-bi/issuer, rdbi-driver/driver. The endorser-N containers, the
   committers, the DB and the orderer/CA pods are unchanged (endorser-N still `rdbi-node:ebbb28f1d552`).
2. Rollback, one container at a time, then a 1-unit transfer smoke:
   `kubectl -n fabricx set image deploy/rdbi-bankN bankN=ghcr.io/radityaaa43/rdbi-node:ebbb28f1d552` (bank2/3/4),
   `deploy/rdbi-bi issuer=…:ebbb28f1d552`, `deploy/rdbi-driver driver=ghcr.io/radityaaa43/rdbi-node:82fa0e65271c`.
   The old images only lack the award command and views; ledger data needs no change. Deploy backups:
   besu/zeto/out/fabricx-award-rollout-20261103T045711Z/.
3. Live proof: award BI -> bank2 tx 93650e89… (1 DFABI-2027A for 1,000,000 RD) in one transaction with the old endorsers;
   bank3/bank4 hold no record. Evidence: besu/zeto/out/award/fabricx-award-phase2.txt.
4. Hazard: panurus's ttxdb (store.go:542-558) labels BI's DFABI issue in an award as `transfer bank2->bank2`; code that
   reads records must detect an award by shape (DFABI to a bank and RD from that bank to the issuer in one tx).
5. Hazard: the deployments are `strategy: Recreate`, so a bank's FSC node, endorser and committer pod restart together
   (about 10-60 s); run no Fabric-X write while one rolls.
6. Price: the award views accept only RD = DFABI x 1,000,000 (PricePerUnit in rdbi/award/checks.go); a change of the
   Lensa PRICE_PER_UNIT needs the same change there and a new image.

## Parked ideas

- 2026-11-03 award: Lensa's BI RD balance reads Noto's cashIssuer, but award RD lands on bondCustodian (and on BI's own
  accounts/addresses in Iroha/Stealth/Zeto). Proposal: BI's RD = sum over BI's RD-holding identities per model
  (Noto: cashIssuer + bondCustodian). Lead decides after all models. -> DECIDED 67dd1d0 (§7.1 "BI balance"), fixed on fix/award-bi-balance.
- 2026-11-03 Fabric-X: the existing panurus SwapResponderView (party SDK) signs blind like the first award responder did:
  it does not check the initiator's identity, the counter-leg amount or recipient before endorsing. The award views now check
  the exact request shape (rdbi/award/checks.go); swap is unchanged. Proposal: a rdbi-side swap responder with the same checks.

## BI-down proof (2026-11-11, user-approved, run by `fabric`)

Fabric-X transfers with `rdbi-bi` scaled to 0 (ns fabricx, 570 s watchdog), through fx-gw-2 with the lensa cert. Times UTC.
- Cycle 0 (07:05): `403` in 0.0 s. Cause: OPA `amount_ok` needs a string amount (`besu/opa/bundles/bi/bi/platform/fabricx/fabricx.rego:149-150`, `regex.match`); my script sent the integer 5 and OPA failed closed. BI was down 35 s, nothing moved. Lensa sends strings.
- Window 1 (07:09:50, BI down 4m36 s): transfer bank2 to bank3, RD 5: HTTP 200 after 266.7 s; submit 133362 ms, final 997 ms, report 132284 ms; report `not delivered: ... dial tcp 10.200.8.79:5101: connect: connection timed out`; bank2 log `retrying without configured endorser [0]` 122 s after the start. Balances bank2 -5, bank3 +5. After BI returned (Ready 13 s): `report` = `recorded`, then `already recorded`; BI records show 5 + change 995 confirmed.
- Window 2 (07:15:43): T1 bank2 to bank3 at +1 s: HTTP 200 after 134.6 s (BI not in its endorser set: submit 2108 ms; report 131464 ms, not delivered). T2 bank2 to bank4 at +21 s: HTTP 504 after 300.0 s (Envoy route timeout, `scripts/k8s.py:299`), but the transaction committed at 07:20:10 (bank4 +5, finality true); its failover log is 236 s after its start. Both reports were redelivered by hand afterwards.
- H1 confirmed: one connection lock per FSC node is held across the dial, `fsc platform/view/services/comm/host/websocket/ws/multiplexed_provider.go:150-162` (`RLock` on every stream open, `Lock` across `OpenWSClientConn`). While a dial to dead BI hangs (~127 s, OS connect timeout, `tcp(7)` `tcp_syn_retries=6`), every new stream of that bank waits. A second transfer therefore takes ~380 s (T2: ~246 s submit + ~131 s report).
- Limit, documented: while BI is down, two transfers in a row from one bank can exceed Envoy's 300 s and Lensa's deadlines although both commit; Lensa (fe change) is to hold the per-sender slot until the gateway answers. Reports not delivered are redelivered by the loop in `rdbi/cmd/driver/redeliver.go` (see `opa/DESIGN.md` section 9 follow-up). The probe's latency with BI down is [unverified] until the live run of the new image.
- Redelivery limits (PR #5, review by iroha): (1) the probe proves BI's gateway (fx-gw-1) answers, not this bank node's FSC path: if BI dies right after a 200 probe the report view can still block ~127 s on the node's connection lock; the gate removes the steady retry, not that single call. (2) While BI is down each probe leaves a handler running in fx-gw-1 after the client's 3 s timeout (`usage` takes no context): about 127 s / 60 s per bank, bounded. (3) [unverified until the live run] OPA on fx-gw-1 admitting `op: usage` from a bank gateway cert (a 403 would mean redelivery never runs), and the probe's latency with BI down. (4) Reports go out in arrival order (BI needs earlier reports first); a report BI keeps refusing is retried 5 times (`maxRefusals`), then dropped; `op: report` retries it by hand.
