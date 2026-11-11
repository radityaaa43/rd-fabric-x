# S12: render the committer per org (fabricx)

Status: PRE-STAGE. Repo-only; `render.py` prints YAML and applies nothing. Source: final-design/fabricx/PLAN.md S12 (DELTA 4). Upstream facts below are from `fabric-x-committer` module v1.0.4 (the docs/samples at `08a469d` were not in this checkout). Applying is a CLUSTER-OP step.

## Command
```
python3 multiorg/committer/render.py <bi|bank-a|bank-b|bank-c> [--image repo@sha256:<hex>] [--pg-image repo@sha256:<hex>] \
  [--zone Z] [--storage-class SC] [--ips FILE] [--msp-id-format 'org{n}']
```
Images default to the digests the cluster runs today (`panurus-itest/scripts/k8s.py:37-38`: committer 1.0.4, postgres 17.10); a tag is refused. bank-c (cluster 2) REQUIRES `--zone` and `--storage-class` (lead: `ap-southeast-1a`, `fabricx-essd`); cluster 1 defaults `ap-southeast-5b` / `alicloud-essd-wffc`. `--ips`/hostAliases data are the ones of `multiorg/arma/render.py`. Refusals print nothing on stdout. A StorageClass is never created.

## Objects (namespace `rd-fabricx-<party>`, apply order)
ConfigMaps `committer-config-{verifier,vc,coordinator,sidecar,query}` and `committer-msp-config`; NetworkPolicy `committer-traffic`; Services (all ClusterIP) `committer-{db,verifier,vc,coordinator,sidecar,query-service}`; StatefulSet `committer-db` (Postgres, PVC `data` 5Gi); Deployments `committer-{verifier,vc,coordinator}`; StatefulSet `committer-sidecar` (PVC `ledger` 2Gi at `/data`); Deployment `committer-query`. All objects carry `rd-fabricx/committer=true` (rollback selector). Pods: PSS restricted (uid/fsGroup 10001; Postgres 999 as in `k8s.py:205`), requests and limits on every container, named ports, `args: [start, <svc>, --config=/config/<svc>.yaml]` (`k8s.py:216`).
Configs are the old `multiorg/committer/config/*.yaml` with ONLY these lines changed (each rule must hit once, otherwise the render dies): vc comment line 1 + `endpoints` -> `committer-db:5432` + `tls: {mode: tls, ca-cert-path: /config/db-tls/ca.crt}` (replaces the no-TLS line `vc.yaml:19`); query `endpoints` + the same tls line; coordinator `verifier`/`vc` endpoints -> `committer-verifier:5110`, `committer-vc:5100`; sidecar `committer.endpoint` -> `committer-coordinator:5120`. Unchanged and already as S12 asks: sidecar `mtls`, `fault-tolerance-level: BFT`, `latest-known-config-block-path: /config/config-block.pb.bin`. Sidecar MSP id comes from env (`org<N>`, as the Arma genesis).

## Secrets and ConfigMap the render needs but does not create (names and keys)
- `committer-db-tls`: `server.crt` (SAN `committer-db`: the client uses `sslmode=verify-full`, `utils/dbconn/database_connection.go:54-58`), `server.key`, `ca.crt` (the CA that issued it).
- `committer-db-credentials`: `password` (Postgres, vc, query; Postgres keeps the password of its first start).
- `committer-tls`: `server.crt`, `server.key`, `ca.crt`. One org certificate serves all components, as the old `sidecar.yaml` header says. SANs: `committer-verifier`, `committer-vc`, `committer-coordinator`, `committer-sidecar`, `committer-query-service`. `ca.crt` verifies the peers' client certificates.
- `committer-sidecar-msp`: `keystore-priv_sk`, `signcert.pem`, `cacert.pem` (the committer identity; `config.yaml` with NodeOUs is the rendered ConfigMap `committer-msp-config`, certificate path `cacerts/ca.pem`).
- ConfigMap `genesis-block` key `genesis.block` (from `multiorg/arma/render.py`; mounted as the config block).

## Upstream facts used (module v1.0.4)
- DB TLS: `tls.mode` none|tls and `tls.ca-cert-path`, no mtls: `docs/tls-configurations.md:129-136`, `cmd/config/samples/vc.yaml:62-67`, `utils/dbconn/database_connection.go:51-62`. The query service uses the same `vc.DatabaseConfig` (`service/query/config.go:36`), so query gets the same TLS lines.
- Sidecar BFT and config block: `cmd/config/samples/sidecar.yaml:66-76`; keys `fault-tolerance-level`, `latest-known-config-block-path`, `identity.msp-id` in `utils/ordererdial/config.go:25-41`.
- Orderer endpoints come from the config block per party (`utils/ordererdial/dialinfo.go:45-63`, shuffled at `:78`), not from a sidecar config key.
- Image: `ENTRYPOINT ["/bin/entrypoint"]`, `USER 10001` (`docker/images/release/Dockerfile:51,58`).

## Unverified (not read or not provable here)
- OWN assembler only: the sidecar config has NO key to pin the orderer. BFT delivery runs one data stream plus header-only streams to several orderers (`utils/deliverorderer/config.go:56-59`), so the sidecar needs ALL four assemblers. The render therefore gives the sidecar the four `*.arma.rd` names as hostAliases (own `assembler-<N>.arma.rd` included) and the NetworkPolicy opens TCP 8011 to the four assembler addresses. Which party's assembler the data stream uses first is random (shuffle) in the files read. PLAN S12 "reads blocks from the assembler of its own party" is NOT enforceable by config: parent/analyst to decide.
- `docs/tls-configurations.md:85-95` documents `orderer.organizations`; `ordererdial.Config` in v1.0.4 has no such key. Not used.
- Whether the orderers accept the committer-tls client certificate (mtls from the sidecar; trust is the genesis TLS CAs, not read) and whether the identity `cacert.pem` is the same CA as `arma-public-<N>` `msp-cacert.pem`.
- Whether the config block endpoints list the assembler with the `deliver` API on `<role>-<N>.arma.rd:8011` (not read from a real block).
- Postgres: key file permissions through `fsGroup` 999 + Secret `defaultMode 0400` (postgres source not read); `ssl_cert_file`/`ssl_key_file` names (PostgreSQL docs not opened); the server still accepts non-TLS clients unless `pg_hba` is `hostssl` (not set here); uid 999 with the image entrypoint and `PGDATA` subdirectory (as `k8s.py:222-224`, a live form).
- NetworkPolicy: whether Terway matches pod IP or ClusterIP for egress (own assembler is covered by both `podSelector: {}` and the ipBlock); ingress is the whole namespace so S13 FSC pods can reach sidecar/query; kube-system DNS label `kubernetes.io/metadata.name`.
- Resource sizes (committer 50m/64Mi/64Mi requests, 1/512Mi/512Mi limits; db 100m/128Mi/64Mi, 1/1Gi/512Mi; ledger 2Gi) are first guesses. No probes are rendered. Whether the sidecar creates `/data/ledger` itself (sample comment says yes, `sidecar.yaml:110-111`).
- No start-up was tried; only the pinned binaries on the cluster can show it.

## AFTER check
PLAN S12 RED proof after apply (inside the CLUSTER-OP window): `kubectl -n rd-fabricx-<party> get sts,deploy` all ready; committer-vc log reports a TLS DB connection (`dbinit.go:57` logs `tls_mode=tls`, upstream `service/vc/dbinit.go`); a committer query-service read; sidecar log block height equals the party's assembler height. Rollback: delete by `-l rd-fabricx/committer=true` in that namespace (user-only).
