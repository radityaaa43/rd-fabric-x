# S10 prep: build the genesis from the four public trees (fabricx)

Status: PRE-STAGE. Repo-only; no cluster read or write. Source: final-design/fabricx/PLAN.md S10 (DELTA 3a). `orderer@dd296e3` = hyperledger/fabric-x-orderer v1.0.4.
S10 itself stays BLOCKED/user-only (new ledger); this PR only provides and proves the build step.

## Command (one machine, once)
```
python3 multiorg/s10/build_genesis.py --exchange <dir with org1..org4> --armageddon <bin built from orderer@dd296e3> \
  --sample-config <orderer>/testutil/fabric/sampleconfig --out <new dir> --heads 1=<sha256>,2=...,3=...,4=...
```
It (1) runs `check_exchange` on every org (any private key, missing role, bad manifest = refuse, nothing started), (2) compares each `MANIFEST.sha256` hash with the one the org announced (`--heads`), (3) copies the trees into a certs-only baseDir and greps it for `PRIVATE KEY`, (4) writes `shared_config.yaml` (hosts and ports from each org's `endpoints.yaml`; Consensus/Batching/MaxPartyID copied from upstream's own `generate` output, run in a scratch dir whose throwaway keys are shredded), (5) runs `createBlock` INSIDE baseDir (paths in the shared config resolve against the CWD, S9 gate 2), (6) prints the block sha256.
`createBlock` reads certificates only (`config/shared_config.go:145-165`), shown in S9.

## What the real run showed (B3 trees, scratch output, nothing applied)
- Built from the real B3 exchange trees of org1..org4 with the pinned `armageddon`: rc 0, 0 files with `PRIVATE KEY` under baseDir, block 66613 B; hosts are the `<role>-<N>.rd-fabricx-<party>.svc.cluster.local` names from `endpoints.yaml`.
- The block is NOT reproducible: two builds from identical inputs gave different sha256 (50363fff… vs 33600a8a…). So the genesis is built ONCE and the file is distributed; every org verifies the sha256 of that file (PLAN S10: published to all orgs). Never rebuild "to compare".
- The block contains the capability strings `V3_0`, `V2_0`, `V2_5` once each (grep of the binary block). That they sit in the right places (Channel/Orderer/Application) is [unverified]; PLAN S10's `check-genesis` is the proof and is not part of this PR.

## Run rules (lead)
- `--heads` is REQUIRED on the command line: without the announced MANIFEST hashes the check against what each org really sent would be skipped, so the CLI refuses to build. Every org must be listed (a missing or wrong entry stops the build).
- S10 VERIFY row: every org's received block file has a sha256 equal to the published value, and the file holds no private key. No rebuild to compare: the block is not reproducible.

## Port plan (single source: `PORT_PLAN` in `multiorg/fca/enroll.py`)
Proposed from the upstream Arma sample, not guessed: `orderer@dd296e3:deployment/vms/sample-config/config.yaml:8-13` uses assembler 8011, consenter 8012, router 8013, batcher shards 8014, 8015 for every party (`deployment/README.md:10`: same port per role on different hosts). Ours: assembler 8011, consenter 8012, router 8013, batcher1 8014 (one shard; a second shard would take 8015). They are distinct per role, so a per-party LB can carry all four. `enroll.py` writes `endpoints.yaml` from this table. Orgs enrolled in B3 have `endpoints.yaml` with 7050: it must be regenerated (re-run the exchange build, or edit the endpoints before the one real build) because ports are part of the genesis (ADR 0001).

## Regenerate the endpoints and dry-run the pipeline (repo-only; shown on the real B3 trees)
```
python3 multiorg/s10/regen_endpoints.py --exchange <B3 trees> --out <NEW dir> --lb-host-template '{role}-{n}.lb.{party}'   # prints the new --heads
python3 multiorg/s10/build_genesis.py --dry-run --exchange <NEW dir> --armageddon <bin> --sample-config <dir> --out <dir> --heads <printed heads>
```
`regen_endpoints.py` writes ports from `PORT_PLAN` (8011-8014) and hosts from the template into a COPY (the source trees are never modified, the destination must not exist), rewrites each org's `MANIFEST.sha256`, and prints the new hashes: each org must announce them again. Placeholder hosts are `<role>-<N>.lb.<party>` until S16 provides the real LB hosts.
`build_genesis.py` now REFUSES a real build when a host is a `*.lb.<party>` placeholder or a port is not the planned one (this catches the B3 trees, which still say 7050). `--dry-run` accepts placeholders and keeps neither the block nor the base dir: it proves the pipeline only.
Real-tree result (scratch, nothing applied): B3 trees -> regenerated copy (ports 8011-8014, placeholder hosts) -> real build refused with the placeholder message -> `--dry-run` rc 0, 4 parties, sha256 printed (`1e850d24...`, meaningless: the block is not reproducible), no block kept; the original trees still have port 7050.

## Endpoint and SAN plan (lead design, ADR 0001 3/1 topology; decided, LBs not built yet)
- Intra-cluster paths (parties 1-3 among themselves): `<role>-<N>.rd-fabricx-<party>.svc.cluster.local`.
- Every cross-cluster path (party 4 <-> parties 1-3) uses the PUBLIC LB endpoint of the target role (per-role or per-party LB, TCP, ACL-first rule, S16). The genesis `Host` of a role that is reached cross-cluster is therefore the LB host.
- Certificates of those roles need BOTH names: the cluster DNS name and the LB host or IP. `enroll.py` takes `--extra-san <host|ip>` (all four roles) or `--extra-san <role>=<host|ip>` (one role), repeatable; each goes into `--csr.hosts` next to the cluster name. Checked offline against the real client and CA: a router enrolled with `--extra-san lb.bank-c.example.org --extra-san router=203.0.113.5` got `DNS:router-4....svc.cluster.local, DNS:lb.bank-c.example.org, IP Address:203.0.113.5`; the assembler got no IP.
- Future GO line **B3-SAN** (needs the LBs to exist first): re-enroll the affected roles in the owning namespace with the LB SANs, replace the Secrets (`kubectl create` of new names, or `replace`), shred the old certs and the work dir, rebuild the exchange tree (new manifest hash, announced again). The certs from B3 carry the cluster names only, so B3-SAN is also what makes party 4 reachable.
- No real genesis build before the port plan is applied to `endpoints.yaml`, the LB hosts are known, and B3-SAN has run.

## Not in this build
- Idemix MSP and `known_certs` (S6 PASS) and the S8 lifecycle policy: S8/S11 items, config-update inputs, not in `build_genesis.py`.
- Capabilities and the channel/orderer/application profile come from the upstream `testutil/fabric/sampleconfig/configtx.yaml` (the `--sample-config` directory), not from this repo. The strings `V3_0`, `V2_0`, `V2_5` are present once each in the scratch block, but that they sit under the right sections and that this profile is the one S10 wants is [unverified] until that file is read against PLAN S10 and `check-genesis` runs.
