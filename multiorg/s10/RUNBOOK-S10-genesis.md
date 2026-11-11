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

## Open points (not solved here)
- Ports: `endpoints.yaml` carries 7050 for every role (enroll.py default). They are part of the genesis (ADR 0001: moving an address is a new genesis); S11 must run the nodes on exactly the hosts/ports in the block, or the endpoints must be rewritten BEFORE the one real build.
- Party 4 (cluster 2): `<role>-4.rd-fabricx-bank-c.svc.cluster.local` is not resolvable from cluster 1; a name reachable across clusters is still undecided (S9 runbook section 5). Decide before the real build: the TLS certificates were issued for the in-cluster names (SANs), so a change also means re-issuing.
- Idemix MSP and `known_certs` (S6 PASS) are not in this build; lifecycle policy per S8 is not either (those are config-update inputs, PLAN S8/S10).
- Capabilities and the application/orderer profile come from the upstream `sampleconfig/configtx.yaml`, not from this repo: whether that profile is the one S10 wants is [unverified].
