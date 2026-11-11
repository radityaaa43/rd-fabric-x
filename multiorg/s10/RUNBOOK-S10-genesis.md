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

## Port plan (single source: `PORT_PLAN` in `multiorg/fca/enroll.py`)
Proposed from the upstream Arma sample, not guessed: `orderer@dd296e3:deployment/vms/sample-config/config.yaml:8-13` uses assembler 8011, consenter 8012, router 8013, batcher shards 8014, 8015 for every party (`deployment/README.md:10`: same port per role on different hosts). Ours: assembler 8011, consenter 8012, router 8013, batcher1 8014 (one shard; a second shard would take 8015). They are distinct per role, so a per-party LB can carry all four. `enroll.py` writes `endpoints.yaml` from this table. Orgs enrolled in B3 have `endpoints.yaml` with 7050: it must be regenerated (re-run the exchange build, or edit the endpoints before the one real build) because ports are part of the genesis (ADR 0001).

## Endpoint and SAN plan (lead design, ADR 0001 3/1 topology; decided, LBs not built yet)
- Intra-cluster paths (parties 1-3 among themselves): `<role>-<N>.rd-fabricx-<party>.svc.cluster.local`.
- Every cross-cluster path (party 4 <-> parties 1-3) uses the PUBLIC LB endpoint of the target role (per-role or per-party LB, TCP, ACL-first rule, S16). The genesis `Host` of a role that is reached cross-cluster is therefore the LB host.
- Certificates of those roles need BOTH names: the cluster DNS name and the LB host or IP. `enroll.py` takes `--extra-san <host|ip>` (all four roles) or `--extra-san <role>=<host|ip>` (one role), repeatable; each goes into `--csr.hosts` next to the cluster name. Checked offline against the real client and CA: a router enrolled with `--extra-san lb.bank-c.example.org --extra-san router=203.0.113.5` got `DNS:router-4....svc.cluster.local, DNS:lb.bank-c.example.org, IP Address:203.0.113.5`; the assembler got no IP.
- Future GO line **B3-SAN** (needs the LBs to exist first): re-enroll the affected roles in the owning namespace with the LB SANs, replace the Secrets (`kubectl create` of new names, or `replace`), shred the old certs and the work dir, rebuild the exchange tree (new manifest hash, announced again). The certs from B3 carry the cluster names only, so B3-SAN is also what makes party 4 reachable.
- No real genesis build before the port plan is applied to `endpoints.yaml`, the LB hosts are known, and B3-SAN has run.

## Not in this build
- Idemix MSP and `known_certs` (S6 PASS) and the S8 lifecycle policy: S8/S11 items, config-update inputs, not in `build_genesis.py`.
- Capabilities and the channel/orderer/application profile come from the upstream `testutil/fabric/sampleconfig/configtx.yaml` (the `--sample-config` directory), not from this repo. The strings `V3_0`, `V2_0`, `V2_5` are present once each in the scratch block, but that they sit under the right sections and that this profile is the one S10 wants is [unverified] until that file is read against PLAN S10 and `check-genesis` runs.
