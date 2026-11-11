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
- File names inside `tls/` and `msp/signcerts/` are not listed in the README: [unverified], take them from a scratch `generate` run (section 6, step 0).

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
0. Dry run, no cluster: on a scratch host run `armageddon generate` for a 4-party template and keep only the file names and layout (not the keys); this fixes the exact names `createBlock` expects. [CLUSTER-OP: none]
1. CA: deploy `fca-org<N>` (+ db) in `rd-fabricx-<party>` (PLAN S9 Does). [CLUSTER-OP]
2. Issue the identities from that CA: TLS cert + key for router, each batcher, consenter, assembler; signing cert + key for each batcher and the consenter (`cryptogen.go:30-33` says what each node needs). Tool: `fabric-ca-client enroll`, as this repo already does for the committer identities (`panurus-itest/scripts/k8s.py:38-40`, `fca-orderer-org<N>`); the Arma cert profile (key type, SANs, usages) is [unverified], compare with the scratch run of step 0.
3. Store the private keys as Secrets `orderer-{router,batcher,consenter,assembler}-<N>-secret` in the org's namespace, with `kubectl create secret` (the `party-admin` Role has no `get`/`apply` on secrets). [CLUSTER-OP]
4. Build `exchange/org<N>/` from the public files, write `endpoints.yaml` and the manifest, run `check_exchange.py`, hand over.
5. Assembler: put the four `exchange/org*` trees into `baseDir/crypto/ordererOrganizations/org*/` (certs only), write `shared_config.yaml` pointing at those paths, run `armageddon createBlock --sharedConfigYaml ... --baseDir ... --blockOutput ... --sampleConfigPath ...`. Check: `grep -r "PRIVATE KEY" <baseDir>` finds nothing. If `createBlock` refuses without key files, use the fallback.
6. Send the same `bootstrap.block` (sha256 recorded) to every party; S10 turns it into the channel genesis.

## 5. Open points that change the plan
- Hostnames: `endpoints.yaml` hosts and the node TLS SANs must be the final names, because moving a party address means a new genesis (ADR 0001, `config/party_shared_config.go`). In-cluster names `<role>-<N>.rd-fabricx-<party>.svc.cluster.local` fit parties 1-3; party 4 (cluster 2) needs a name reachable from cluster 1: decide before step 2 (not decided).
- Fallback (PLAN S9): central `armageddon generate` by the operator, then each party's private directory handed to its org and every other copy destroyed; the step report records the destruction. Weaker: the operator touched all private keys.
- `known_certs`, Idemix MSP and `ids/anon` are S5/S10, not here.

## 6. Done when (PLAN S9 RED proof)
`kubectl -n rd-fabricx-bank-a get secret -o name` lists only Org2 names; `kubectl auth can-i get secret -n rd-fabricx-bi --as system:serviceaccount:rd-fabricx-bank-a:party-admin` = `no`; the assembler's `baseDir` has no private key; `check_exchange.py` exit 0 for all four orgs.
