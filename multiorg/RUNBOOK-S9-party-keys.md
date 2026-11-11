# S9 runbook: per-org Arma party keys and the public-material exchange (fabricx)

Status: PRE-STAGE, nothing here has been run. Source: final-design/fabricx/PLAN.md S9 (DELTA 3, 3a); topology 3/1 decided (README row 13).
Every cluster step below is a CLUSTER-OP with its own GO from `lead`; steps 1-3 run in the org's own namespace with its `party-admin` kubeconfig.
`orderer@dd296e3` = hyperledger/fabric-x-orderer v1.0.4; files below were read at that commit.

## 1. What upstream gives (and does not)
- `armageddon generate` writes the crypto of ALL parties in one run, with "a fake CA ... for each party": `cmd/armageddon/README.md:48-51, :91`. Its flags are only `config`, `output`, `sampleConfigPath` (:38-42). No per-party or existing-CA flag was found: PLAN S9 stays BLOCKED(upstream) for a one-tool route.
- Layout it writes, per party `org<N>`: `ca`, `tlsca`, `msp/{cacerts,tlscacerts,knowncerts,admincerts}`, `orderers/party<N>/{router,batcher<k>,consenter,assembler}/{tls,msp/{cacerts,admincerts,keystore,signcerts,tlscacerts}}`, `users/`: `common/tools/armageddon/cryptogen.go:30-73`.
- The genesis needs only PUBLIC paths per party: `CACerts`, `TLSCACerts`, each role's `TLSCert`, `SignCert` for batchers and the consenter, and each role's `Host`/`Port`: `config/party_shared_config.go:11-68`.
- `createBlock` builds `bootstrap.block` from `sharedConfigYaml` and a `baseDir` that "contains a crypto subdirectory": `cmd/armageddon/README.md:260-286`. Whether it opens any private key is [unverified].
- Every node starts from the same genesis; operators distribute it: `docs/architecture.md:148-153`.
- GATE 1 SETTLED (scratch run, section 7): node file names, from a real `armageddon generate` and the code that reads them: a node reads `<LocalMSPDir>/keystore/priv_sk` (`config/config.go:308, :396`) and `tls/server.key` + `tls/server.crt` (`config/generate/local_config_gen.go:195-196`); the key writer names it `priv_sk` (`internal/cryptogen/csp/csp.go:104`). Public per role: `tls/server.crt`, `tls/ca.crt`, `msp/signcerts/<role>-cert.pem` (batcher1, consenter feed `SignCert`). Fabric CA names keys `<hash>_sk`, so enroll.py renames into the Secret key `msp-keystore-priv_sk`. Cert profile: ECDSA P-256 keys; `tls` = KeyEncipherment+DigitalSignature, `sign` = DigitalSignature, both ExtKeyUsage client+server auth, SANs = the node hostname (`common/tools/armageddon/cryptogen.go:175-179, :218, :228-231`); a Fabric CA `tls` enrollment with `--csr.hosts` gives the same.
- GATE 2 SETTLED (scratch run): `createBlock` reads only certificates. The shared config loader reads CA cert, TLS CA cert and node TLS certs with `utils.ReadPem` (`config/shared_config.go:145-165`). Run on a copy of the generated tree with every `priv_sk` and `*.key` deleted (0 files containing `PRIVATE KEY`, 214 files left), `createBlock` exited 0 and wrote `bootstrap.block`. Paths in `shared_config.yaml` resolve against the current directory, not `--baseDir`: run it from inside the base directory (the first attempt from outside failed on a relative path, not on a key). The block is NOT byte-identical to the one `generate` wrote (103535 B vs 76.7 KB); why is [unverified] (different profile inputs are likely), so S10 must build the genesis with `createBlock` only and never mix the two.

## 2. Who holds what
| Material | Who generates | Where it lives | Leaves the org? |
|---|---|---|---|
| Org CA + TLS CA private keys | the org | Secret in `rd-fabricx-<party>` | no |
| Node TLS + signing private keys (router, batcher<k>, consenter, assembler) | the org | Secrets `orderer-{router,batcher,consenter,assembler}-<N>-secret` | no |
| CA certs, TLS CA certs, node TLS certs, signing certs, `endpoints.yaml` | the org | `exchange/org<N>/` | yes, to the assembler (public) |
| `shared_config.yaml`, `bootstrap.block` | the assembler (operator, public inputs only) | operator host, then every party | yes, same file to all |

## 3. Public-material exchange layout (checked by `check_exchange.py`)
```
exchange/org<N>/                     one directory per org, built by that org from its own tree
  msp/cacerts/*.pem                  -> PartyConfig.CACerts
  msp/tlscacerts/*.pem               -> PartyConfig.TLSCACerts
  orderers/party<N>/router/tls/*.pem              -> RouterConfig.TLSCert
  orderers/party<N>/batcher<k>/tls/*.pem          -> BatchersConfig[k].TLSCert
  orderers/party<N>/batcher<k>/msp/signcerts/*.pem  -> BatchersConfig[k].SignCert
  orderers/party<N>/consenter/{tls/*.pem,msp/signcerts/*.pem}  -> ConsenterConfig.TLSCert, SignCert
  orderers/party<N>/assembler/tls/*.pem           -> AssemblerConfig.TLSCert
  endpoints.yaml                     {router|batcher<k>|consenter|assembler: {Host, Port}}  (final DNS names, see 5)
  MANIFEST.sha256                    "<sha256>  <relative path>" for every file above
```
Rules: certificates and `endpoints.yaml` only. `python3 multiorg/check_exchange.py exchange/org<N> <N>` must exit 0 before the directory leaves the org: it refuses any file with `PRIVATE KEY`, a `keystore` directory or `*_sk` file, a missing role or CA cert, and a manifest that does not match.
The org sends the directory and tells `lead` the sha256 of `MANIFEST.sha256` on a second channel; the assembler compares it before use.

## 4. Procedure (per org N; BI, bank-a, bank-b on cluster 1, bank-c on cluster 2 under S18)
0. Done (section 7): scratch `generate` + certs-only `createBlock`; names and gates settled. Nothing to repeat.
1. CA: `python3 multiorg/fca/enroll.py init <party> rd-fabricx-<party> --kubeconfig K --work W` (admin password -> W and Secret `fca-org<N>-admin`), then `python3 multiorg/fca/render.py <party> | kubectl --kubeconfig K apply -f -` (Service, PVC `fca-org<N>-data` 2Gi, Deployment, restricted-PSS, image by digest). The CA key and registry live on that PVC. [CLUSTER-OP] PRE: the Role needs `pods/portforward` (added in `namespaces/templates/rbac.yaml`; the four live Roles do not have it: a Role update is its own GO).
2. With `kubectl --kubeconfig K -n <ns> port-forward svc/fca-org<N> 7054` running: `python3 multiorg/fca/enroll.py enroll <party> rd-fabricx-<party> --kubeconfig K --ca-url http://localhost:7054 --work W --out exchange/org<N>`. It registers and enrolls router, batcher1, consenter, assembler (msp + tls profile, `--csr.hosts` = final node hostname). `enroll.py` is NOT live-tested: `fabric-ca-client` is not installed on the build host and the CA is not deployed; its layout code and the checker are tested offline.
3. `enroll.py` creates Secrets `orderer-{router,batcher,consenter,assembler}-<N>-secret` (keys `msp-keystore-priv_sk`, `msp-signcert.pem`, `tls-server.key`, `tls-server.crt`) with `kubectl create -f -` (the `party-admin` Role has no `get`/`apply` on secrets), then shreds W. Proof it ran: `find W` shows nothing. [CLUSTER-OP]
4. `enroll.py` builds `exchange/org<N>/` from the public files, writes `endpoints.yaml` and the manifest and runs `check_exchange.py`; run `python3 multiorg/check_exchange.py exchange/org<N> <N>` once more by hand before handing over.
5. Assembler: put the four `exchange/org*` trees into `baseDir/crypto/ordererOrganizations/org*/` (certs only), write `shared_config.yaml` pointing at those paths, run `armageddon createBlock --sharedConfigYaml ... --baseDir ... --blockOutput ... --sampleConfigPath ...`. Check: `grep -r "PRIVATE KEY" <baseDir>` finds nothing. If `createBlock` refuses without key files, use the fallback.
6. Send the same `bootstrap.block` (sha256 recorded) to every party; S10 turns it into the channel genesis.

## 5. Open points that change the plan
- Hostnames: `endpoints.yaml` hosts and the node TLS SANs must be the final names, because moving a party address means a new genesis (ADR 0001, `config/party_shared_config.go`). In-cluster names `<role>-<N>.rd-fabricx-<party>.svc.cluster.local` fit parties 1-3; party 4 (cluster 2) needs a name reachable from cluster 1: decide before step 2 (not decided).
- Fallback (PLAN S9): central `armageddon generate` by the operator, then each party's private directory handed to its org and every other copy destroyed; the step report records the destruction. Weaker: the operator touched all private keys.
- `known_certs`, Idemix MSP and `ids/anon` are S5/S10, not here.

## 6. Done when (PLAN S9 RED proof)
`kubectl -n rd-fabricx-bank-a get secret -o name` (run by qa with the ADMIN kubeconfig: `party-admin` has no `get`/`list` on secrets) lists only Org2 names; `kubectl auth can-i get secret -n rd-fabricx-bi --as system:serviceaccount:rd-fabricx-bank-a:party-admin` = `no`; the assembler's `baseDir` has no private key; `check_exchange.py` exit 0 for all four orgs.

## 7. Scratch run that settled the gates (no cluster, throwaway keys)
`armageddon` built from orderer@dd296e3 (Go 1.26.5 toolchain fetched by `go build`), run in the session scratchpad: `generate` for a 4-party template (hosts `*.rd-fabricx-<party>.svc.cluster.local`, mTLS) exit 0 -> per org 61 files; then `createBlock` on a copy without private keys exit 0 (Gate 2). `check_exchange.py` exit 0 on an exchange tree cut from that real output, and non-zero with a real `server.key` slipped in. The scratch keys were never used anywhere.

## 8. Decided run rules (lead, 2026-11-11) and weak points
- Window start: install `fabric-ca-client` on the operator host at a PINNED version (the server image is fabric-ca 1.5.22; use the same) and run a throwaway-identity enroll against the org's CA (register `probe-<N>`, enroll, delete the identity and the files). Any error: stop, report; rollback only on the user's word. Only then the real run.
- Sequential per org: own party kubeconfig, `--work` under `/dev/shm` (enforced by `enroll.py`, umask 077 set there), Secrets created, then the work dir is shredded (`enroll.py` does it in a `finally`) BEFORE the next org starts. Proof per org: `ls /dev/shm/<work>` -> No such file.
- Lead classification: ACCEPTED interim shortcut. One operator host holds each org's keys on tmpfs, transiently, between enroll and Secret create. The recorded decentralization gap is the per-bank operator host. This text goes into the GO request.
- `fca-org<N>` is pinned to a zone with `nodeSelector` (`render.py <p> [--zone Z]`): cluster 1 defaults to ap-southeast-5b (as `k8s.py`); bank-c REQUIRES `--zone`, taken from the cluster-2 PRE (qa: `get nodes -L topology.kubernetes.io/zone` + per-node csinode allocatable minus volumeattachments; the zone with the most free attach slots). `alicloud-essd-wffc` is WaitForFirstConsumer: the disk binds to its first pod's zone.
- Storage class: cluster 1 uses `alicloud-essd-wffc` (default). Cluster 2 has no such class (qa PRE: `alicloud-essd` Immediate Delete, `fabricx-essd` WaitForFirstConsumer Retain), so `render.py bank-c` REQUIRES `--storage-class`. Decided (lead): bank-c = `fabricx-essd`: WaitForFirstConsumer binds the disk in the pod's zone (ap-southeast-1a with `--zone`), and `Retain` means the CA key disk survives a PVC/namespace delete (a retained disk then holds the bank-c CA key: destroy it deliberately). Command: `python3 multiorg/fca/render.py bank-c --zone ap-southeast-1a --storage-class fabricx-essd | kubectl --kubeconfig K apply -f -`.
- Placement: `fca-org<N>` has a REQUIRED podAntiAffinity on `kubernetes.io/hostname` against the other `fca-org*` pods (all namespaces). Found by qa: fca-org1/2/3 all ran on member-16044-node. Applying it to the three running CAs is a future GO line B3-PLACE: a rolling re-schedule of fca-org2/3 (Recreate: short CA outage, CA data on the PVC is unaffected; WaitForFirstConsumer zone 5b has 3+ nodes with free slots). If fewer nodes than CAs have slots, the pod stays Pending: a required rule never double-books a node.
- Exact bank-c order (options only AFTER the party name): `python3 multiorg/fca/render.py bank-c --zone ap-southeast-1a --storage-class fabricx-essd | kubectl --kubeconfig K apply -f -`.
- Retain on cluster 2 (`fabricx-essd`): after any bank-c rollback (or namespace delete) the PV behind `fca-org4-data` stays `Released` and the disk keeps the bank-c CA key. Who deletes it: the cluster-2 admin, only on the user's word (S22 decommission step text: "delete the Released PV of `fca-org4-data` and its cloud disk, cluster-2 admin, user-only"). qa row: no `Released` PV for `fca-org4-data`, or it is listed with that owner.
- Retry after a failed `enroll`: a role identity registered before the failure makes `register` fail with `Identity '<role>-<N>' is already registered` (seen in the offline test). The CA registry is on the PVC, so a retry needs either a fresh CA home (new PVC) or the stale identities revoked by the CA admin first; do not retry blindly.
- PVC per CA: qa PRE checks disk-attach capacity on the target nodes and the storage class (`alicloud-essd-wffc`); if there is no slot, stop before apply.
- The four live Roles lack `pods/portforward`: updating them is GO line B-F0 (rollback = remove the rule).
- Secrets never go on a command line (qa finding): the admin password and each role's enrollment secret reach `fabric-ca-client` only through its environment (`FABRIC_CA_CLIENT_URL`; `/proc/<pid>/environ` is readable by the same uid only, `cmdline` is world-readable). `register` omits `--id.secret`; the server-generated `Password:` is read from stdout. A failing command prints only its first 3 argv words plus stderr with every known secret replaced by `***`. [unverified live] that the real client honours `FABRIC_CA_CLIENT_URL` and prints that password; the window-start throwaway enroll settles it, and the stub tests cannot.
- `enroll.py init` leaves `admin.pass` in W until `enroll` runs. If `enroll` never runs, shred W by hand: `find W -type f -exec shred -u {} +; rm -r W`.
- The CA key and registry sit on a PVC, not in a Secret: `party-admin` cannot read them; the cluster admin and snapshots can.
- `fca-org<N>` runs without TLS in-namespace (`--tls.enabled=false`; port-forward only). TLS is S13.
- S10 builds the genesis with `createBlock` only: its block is not byte-identical to the one `generate` writes (cause unverified).
