# S11/S18: render the Arma party pods (fabricx)

Status: PRE-STAGE. Repo-only; `render.py` prints YAML and applies nothing. Source: final-design/fabricx/PLAN.md S11 (parties 1-3, cluster 1) and S18 (party 4, cluster 2); ARCHITECTURE-fabricx 2a.1 rows "Arma party endpoints" and "Gateway + NetworkPolicy", DELTA 14. `orderer@dd296e3` = hyperledger/fabric-x-orderer v1.0.4.
Applying is a CLUSTER-OP step (one GO per cluster); nothing here is applied or checked against a cluster.

## What it renders (namespace `rd-fabricx-<party>`)
Apply order: ConfigMap `genesis-block`; ConfigMap `arma-public-<N>`; ConfigMaps `arma-config-{router,batcher,consenter,assembler}-<N>`; NetworkPolicy `allow-arma-peers`; StatefulSets `orderer-{router,batcher,consenter,assembler}-<N>`.
Not rendered: the key Secrets `orderer-<role>-<N>-secret` (made by `multiorg/fca/enroll.py`, S9) and Service `lb-<N>` (made by `multiorg/lb/render.py`, S16). Both must exist before the StatefulSets are applied.
Party -> N: bi 1, bank-a 2, bank-b 3, bank-c 4. bank-c is cluster 2 (S18); the other three are cluster 1 (S11).

## Command
```
python3 multiorg/arma/render.py <party> --exchange <dir with org1..org4> --genesis <genesis.block> --genesis-sha256 <hex> \
  [--image repo@sha256:<hex>] [--replicas 1] [--zone Z] [--storage-class SC] [--ips FILE] [--msp-id-format 'org{n}']
```
- `--exchange`: the four public trees from `enroll.py`; each is checked with `check_exchange.problems` (any private key, missing file or bad manifest = refuse) and its `endpoints.yaml` must carry the name plan below (Host `<role>-<N>.arma.rd`, ports from `PORT_PLAN`).
- `--genesis` + `--genesis-sha256`: refused unless the sha256 (64 lowercase hex) matches and the file is at most 700 KiB (the ConfigMap limit is 1 MiB for the whole object and `binaryData` is base64, x 4/3). It goes into `genesis-block` as `binaryData`.
- `--image`: default is the 1.0.4 digest running today; anything that is not `repo@sha256:<64 hex>` is refused.
- `--replicas`: default 1, 0 is refused. `--zone`/`--storage-class`: cluster 1 defaults `ap-southeast-5b` / `alicloud-essd-wffc`; bank-c REQUIRES `--storage-class` (`fabricx-essd`, WaitForFirstConsumer, Retain, read before every apply) and has NO zone pin unless `--zone` is given: zone `ap-southeast-1a` had no pod/volume room on 2026-11-11 (0/8 nodes available: 2 too many pods, 2 max volume count, 4 selector).
- Every refusal prints nothing on stdout. Pipe to `kubectl --kubeconfig <party kubeconfig> apply -f -` only inside a GO window.

## Names and hostAliases (decision A: one config block, stable names, per-pod resolution)
The genesis `Host` of every role is `<role>-<N>.arma.rd` (roles `router`, `batcher1`, `consenter`, `assembler`), so all parties share one config block. Ports are `PORT_PLAN` (assembler 8011, consenter 8012, router 8013, batcher1 8014). The names are not in any DNS: each pod resolves them with `hostAliases` in its own pod spec (no CoreDNS or kube-system change, no public DNS). One entry per address, each with the four names of that party:

| names of party | cluster 1 pods (parties 1-3) | cluster 2 pods (party 4) |
|---|---|---|
| 1 (bi) | 10.200.55.11 (ClusterIP lb-1) | 8.215.24.249 (public LB lb-1) |
| 2 (bank-a) | 10.200.27.215 (ClusterIP lb-2) | 8.215.30.255 (public LB lb-2) |
| 3 (bank-b) | 10.200.63.143 (ClusterIP lb-3) | 147.139.133.68 (public LB lb-3) |
| 4 (bank-c) | 47.236.199.240 (public LB lb-4) | 10.210.48.103 (ClusterIP lb-4) |

The table is data (`IPS` at the top of `render.py`, tested). A later change needs no code edit: `--ips FILE` with the same shape (`cluster1:` and `cluster2:`, each `1..4: <IPv4>`); every address is validated as IPv4, parties may not share an address.
Dependency to settle before S10: the TLS certificates must carry the SAN `<role>-<N>.arma.rd` for their own role. The B3 certificates carry the cluster-DNS names only, so a B3-SAN re-issue (`enroll.py --extra-san <role>=<role>-<N>.arma.rd`, see RUNBOOK-S9 section 9) is needed. [unverified] that the nodes verify the SAN of the dialled name (expected for gRPC TLS, not read in the source).

## Pod contract (matches `multiorg/lb/render.py`, asserted in the tests)
- Labels: `rd-fabricx/arma-party: "<N>"` (the Service selector), `app.kubernetes.io/part-of: rd-fabricx`, `party: <party>`, `app.kubernetes.io/name: orderer-<role>-<N>`.
- Named containerPorts: the role port (`router` 8013, `batcher1` 8014, `consenter` 8012, `assembler` 8011) plus `ops` (7060 router, 7061 batcher, 7062 consenter, 7063 assembler; metrics, not in the Service).
- StatefulSet, serviceName `lb-<N>`, args `[<router|batcher|consenter|assembler>, --config=/config/node_config.yaml]` on the image entrypoint, PVC `data` 2Gi at `/data`.
- Mounts (all `subPath`, read-only): Secret items to `/config/msp/keystore/priv_sk`, `/config/msp/signcerts/<role>-cert.pem`, `/config/tls/server.key`, `/config/tls/server.crt` (defaultMode 0400); `/config/tls/ca.crt` = TLS CA bundle of all four orgs; `/config/msp/cacerts/ca.pem` = this org's CA; `/config/genesis.block`; `/config/node_config.yaml`.
- PSS restricted: runAsNonRoot, uid/fsGroup 10001, RuntimeDefault seccomp, no privilege escalation, drop ALL; requests and limits for cpu, memory, ephemeral-storage.
- Placement: nodeSelector zone; cluster 1 only: required nodeAffinity hostname NotIn `member-16033-node`, `member-16034-node` (as `panurus-itest/scripts/k8s.py` AVOID_NODES); preferred (weight 100) anti-affinity on hostname between the four pods of the same party.
- NetworkPolicy `allow-arma-peers`: ingress to the party's pods on TCP 8011-8014 from namespaces labelled `part-of: rd-fabricx` (cluster 1 only) and from the other cluster's egress address as ipBlock (cluster-1 namespaces allow `47.237.84.150/32`, bank-c allows `8.215.62.92/32`). Default-deny stays the base.

## Node configs
`arma-config-<role>-<N>` is generated from `multiorg/arma/templates/<role>-1.yaml` (the batcher file is `batcher-1.yaml`). Provenance: copied from the live old namespace ConfigMaps `orderer-<role>-1-config`, key `node-config.yaml`, 2026-11-11; public settings only, no secrets. Text substitution of ONLY: `PartyID`, `General.LocalMSPID`, `General.ListenPort` (= `PORT_PLAN`), `Operations.ListenPort` (7060 + role index), `Batcher.ShardID` (1) and the line `- /config/mtls/prometheus/ca.crt` is removed (no Prometheus in the new namespaces). A template that no longer has exactly one of each of those lines is refused. Everything else, comments included, is byte-identical (tested with a diff).
MSP id: the genesis builder names the orderer orgs `org<N>` and the consenter mapping `MSPID: org<N>` (`orderer@dd296e3 config/generate/config_block_gen.go:56,102-103`; `createBlock` reaches it via `common/tools/armageddon/armageddon.go:301`). The generator's own local configs use the same value: `config/generate/local_config_gen.go:209` sets `LocalMSPID: fmt.Sprintf("org%d", partyID)` (checked by the author at the pinned commit). The render therefore defaults `LocalMSPID` to `org<N>`; the old `OrdererOrg1` came from the old genesis. [unverified] that the node needs `LocalMSPID` to equal the config-block MSP id (`node/server/arma.go:71,106,147,188` only passes it to `BuildLocalMSP`; `config/local_config.go:323` only checks it is non-empty). Override with `--msp-id-format 'OrdererOrg{n}'`.
TLS roots: outbound connections verify with the per-party `TLSCACerts` of the genesis (`node/batcher/primary_ack_connector.go:106`, `node/batcher/consensus_replicator_creator.go:30`, `node/batcher/puller.go:113`), and the inbound client roots are the genesis TLS CAs plus `General.TLS.ClientRootCAs` (`config/config.go:263-284`). I found no use of `General.TLS.RootCAs` in `config/config.go`, so the bundle at `/config/tls/ca.crt` matters for `Operations.TLS.ClientRootCAs`, and for `RootCAs` only if a path not read here uses it. [unverified] which of the two the node reads for outbound verification of the other roles.

## Start-up contract (found on the cluster 2026-11-11, now asserted)
- Each role runs the arma CLI command `router`, `batcher`, `consensus` (NOT `consenter`) or `assembler` (`orderer@dd296e3 node/server/arma.go:30-58`); the object names keep the role name.
- The node local MSP needs an admin: the org's PUBLIC admin cert (exchange `msp/admincerts`) is in `arma-public-<N>` key `msp-admincert.pem` and mounted at `/config/msp/admincerts/admin.pem` (`fabric-x-common msp/mspimplsetup.go:211` panics otherwise). The render refuses an exchange tree without admincerts.
- `smoke.py` runs the pinned upstream `arma` (orderer@dd296e3, `./cmd/arma`) offline on the rendered args and mount layout of all four parties (throwaway keys, a real genesis from our own tools) and fails if any role exits or panics. Run it before every apply of a changed render: `python3 -I multiorg/arma/smoke.py --arma BIN --armageddon BIN --sample-config DIR --cfgupdate BIN` (BIN as in its docstring). With the old render it fails on exactly the two panics seen live (`administrators must be declared ...`, `expected command but got "consenter"`).

## Rollout (learnt on the cluster 2026-11-11)
A StatefulSet RollingUpdate never replaces a pod that has not become Ready. After a spec fix the update revision differs from the current one and a crash-looping pod keeps the OLD spec: update the spec, then delete the stuck pods (PVCs stay). Check `kubectl get sts -o custom-columns=N:.metadata.name,CUR:.status.currentRevision,UPD:.status.updateRevision` before judging a fix. A spec change on a Pending pod (bank-c, unschedulable) also needs the pod deleted when the pod object was already created with the old spec.

## CLB shape on the live Services (found 2026-11-12) and the opt-in health-check element
The first four lb-<N> Services were built with externalTrafficPolicy Local (no backend-type). From cluster 2, bank-c's batcher got a persistent `connection refused` from `lb-2:8014` (8.215.30.255) while the hosted-runner probe timed out (so not an ACL drop): with Local each role pod sits on a different node and a node forwards a port only if it has a local pod for that port. Field change under the orchestrator's word, lb-2 first (canary): `spec.externalTrafficPolicy: Cluster` + annotation `service.beta.kubernetes.io/backend-type: eni`; read back with ACL annotations, ranges and LB IP unchanged. With eni the CLB health check comes from `100.64.0.0/10`, which `allow-arma-peers` does not admit, so the render has the opt-in `--clb-health-cidr 100.64.0.0/10` (exactly that value, nothing else) that appends `{ipBlock: 100.64.0.0/10}` to the same ingress rule. S10b order: add it only AFTER the annotation/listener ACL read-back and a hosted-runner probe that TIMES OUT (a refusal does not count).

## Unverified
- Resource sizes: requests 30m / 64Mi / 64Mi (resized 2026-11-12 from 50m / 128Mi, GO resize; orderer pods are idle-light), limits 1 / 512Mi / 512Mi unchanged; first guesses, `kubectl top` after the resize is the check.
- Whether the Terway policy engine sees the preserved client source IP behind the CLB with `externalTrafficPolicy: Local` (the `ipBlock` rules depend on it).
- Secret `defaultMode 0400` with `fsGroup`: the kubelet adds group read for fsGroup volumes, so the effective mode is probably 0440, which uid 10001 reads through the fsGroup. Not tried on a node.
- Whether the node needs more files under `/config/msp` than the four mounted ones (no `config.yaml`, `admincerts`, `tlscacerts`). The old Secrets carried the same four keys.
- Whether a pod reaching its OWN party through the lb-<N> ClusterIP works without hairpin trouble.
- The SAN dependency above, the MSP id above, the genesis checks `ValidateNewConfig` of S10 (not here).
- Label mismatch to settle: PLAN S11 rollback says `-l part-of=arma`; the objects here carry `app.kubernetes.io/part-of: rd-fabricx` (the label of the other rd-fabricx objects). A rollback selector would be `rd-fabricx/arma-party` or `app.kubernetes.io/name`.

## AFTER check
ARCHITECTURE-fabricx 2a.1 rows "Arma party endpoints" (:237: same config block everywhere, public Host/Port per role) and "Gateway + NetworkPolicy" (:243: orderer ports open between parties, default-deny as base), the diagram edge :215 (cross-cluster only between party 4 and parties 1-3: the only cross-cluster rules are the ipBlock and the lb-4 / lb-1..3 public addresses) and DELTA 14 (:285).
PLAN S11 RED proof after apply: `kubectl -n rd-fabricx-bi get sts -o wide` all `1/1`; the party-1 orderer logs show a leader with 3 parties up [log line unverified].
