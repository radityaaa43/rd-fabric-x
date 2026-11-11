# Complete genesis: finalize, inspect, check-admins (fabricx S8/S10)

Status: tooling only. Nothing here touches a cluster. Decisions (lead + orchestrator, 2026-11-11): ADR 0003 MAJORITY (3 of the 4 BANKS), `known_certs` = FSC endorser certs, Idemix never counts in an admin/endorsement/lifecycle policy. **DECIDED: genesis C** (orchestrator, "fabricx genesis C": no Idemix org, Channel V3_0, explicit OutOf(3) signature policies; ids/anon and the FSC full-certificate patch stay = S6 deviation). The Idemix org is an OPTION, OFF by default (`finalize -idemix-dir <dir>`, `inspect -idemix=true`), blocked at Channel V3_0 by the error below. AFTER: ARCHITECTURE-fabricx :237 + 3a, DELTA 5.

## Commands (`go build` in this directory; one heavy build at a time)
```
cfgupdate finalize     -block <createBlock block> [-idemix-dir <dir>  # OPTIONAL, off] -out <genesis> [-bank-ids org1,org2,org3,org4] [-threshold 3] [-channel-capability V3_0]
cfgupdate inspect      -block <genesis> [-bank-ids ...] [-threshold 3] [-idemix=false|true  # default false] [-channel-capability V3_0]
cfgupdate check-admins -block <genesis> -admin org1=<admin msp dir> [-admin org2=...] -expect pass|fail
```
- `finalize` replaces the three implicit `MAJORITY` policies of the Application group by explicit signature policies over the bank MSPs, and, only when `-idemix-dir` is given, adds the shared org `IdemixOrgMSP` (Application org of MSP type idemix, Readers/Writers only, mod_policy `/Channel/Application/Admins`). MSP ids are what `createBlock` gives the orgs: `org1`..`org4` (orderer@dd296e3 `config/generate/config_block_gen.go:56,102-103`).

| Application policy | Rule | Why this role |
|---|---|---|
| Admins | OutOf(3, org1..org4 `.admin`) | sample org-level Admins = OR(admin), `sampleconfig/configtx.yaml:66-68` |
| Endorsement | OutOf(3, org1..org4 `.member`) | org-level Endorsement = OR(member), `:68-69` |
| LifecycleEndorsement | OutOf(3, org1..org4 `.member`) | not the template default (OR over all peer orgs, Idemix included) |
Readers/Writers stay ANY, Idemix included. The sample's implicit `MAJORITY` would count the Idemix org (5 Application orgs: majority 3 of 5, a bank could count twice: its own MSP and an Idemix creator).
- `inspect` (offline) asserts: capabilities (Channel V3_0 / Orderer V2_0 / Application V2_5), exactly the bank orgs (+ `IdemixOrg` only with `-idemix=true`), every bank MSP has admin certs and known_certs, with `-idemix=true`: the Idemix org is an idemix MSP named `IdemixOrgMSP` with both keys, only Readers/Writers on it and not an Orderer org, the three policies are signature policies OutOf(n) over EXACTLY the bank ids with the right role, and `IdemixOrgMSP` is in no Admins/Endorsement/LifecycleEndorsement policy at Channel or Application level. Exit 1 on any deviation.
- `check-admins` builds the channel bundle, runs the start-up checks (Arma `ValidateNewConfig` parties 1..4, committer `ParseLifecycleEndorsementPolicy`) and evaluates `/Channel/Application/Admins` and `/Channel/Application/LifecycleEndorsement` with real signatures of the given admins. PLAN S8 RED proof: majority `-expect pass`, one admin `-expect fail`. An admin MSP dir holds `signcerts/cert.pem` and `keystore/<x>_sk` (PKCS8): from the Secret `orderer-admin-<N>-secret` keys `msp-signcert.pem` and `msp-keystore-priv_sk`. Assembling several orgs' admin keys on one host is a custody step (text through lead; /dev/shm, shredded).

## FINDING (S6-inline step b): an Idemix org and Channel V3_0 cannot coexist at the pinned versions
Offline rehearsal on a real `armageddon createBlock` block (throwaway keys, `rehearse/make_trees.py`, real CA Idemix keys from `getcainfo`):

| genesis | start-up checks | 3 admins | 1 / 2 admins |
|---|---|---|---|
| A: Idemix org + Channel V3_0 | FAIL: `creating the MSP manager failed: Invalid *IdemixNewOpts. Version not recognized [4]` | n/a | n/a |
| B: Idemix org + Channel V2_0 (MSPv1_4_3) | PASS | PASS | FAIL / FAIL |
| C: no Idemix org + Channel V3_0 (MSPv3_0) | PASS | PASS | FAIL / FAIL |

Cause: `fabric-x-common msp/factory.go:70-90` builds an Idemix MSP only for MSP versions 1.1, 1.3 and 1.4.3, and capability V3_0 selects MSPv3_0 (`common/capabilities/channel.go:88-91`). So (C) is the S6 FAIL branch: ids/anon and the FSC full-certificate patch stay. (B) is possible but moves the channel off the sample capability set; what V3_0 gives the orderer/committer at runtime is [unverified]. An Idemix org at V3_0 needs a newer fabric-x-common (upstream; no new custom code).
`known_certs` is processed in the shared MSP setup (`msp/mspimplsetup.go:550,598`) and was read as `known_certs=1` per bank in both B and C.

## Rehearsal (no cluster, throwaway keys)
`python3 -I multiorg/cfgupdate/rehearse/make_trees.py <dir>` writes 4 throwaway org CAs (openssl), admin/endorser/node certs, public trees under `<dir>/exchange` and admin MSP dirs under `<dir>/admins`, prints the heads; then `build_genesis.py --exchange <dir>/exchange ... --heads <heads>`, `cfgupdate finalize|inspect|check-admins`. Keys exist only under `<dir>/keys` at run time: delete the directory afterwards.

## C3 (getcainfo) is dropped for genesis C
`fabric-ca-client getcainfo` on fca-org1 yields the public Idemix issuer/revocation keys. They are needed only when the Idemix option is used, so for genesis C step C3 is not run. (The keys in `testdata/idemix/msp` are real PUBLIC keys from a throwaway CA, used by the tests of the option.)
