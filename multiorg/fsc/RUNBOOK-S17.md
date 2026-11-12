# S17: scheduled report per bank = redelivery tick + read-only reconcile (fabricx)

Status: PRE-STAGE, repo only. AFTER deviation S17 accepted by user word "A" 2026-11-12 (no CronJob); analyst ruling: ALIGNED A with five conditions (below).

## What replaces the CronJob
- The fxapi container of every `fx-gw-<N>` redelivers due reports to BI: a tick every `RDBI_REDELIVER_INTERVAL` and a startup pass that sends everything the node holds (the `report` view with an empty TxID), `panurus-itest/rdbi/cmd/driver/redeliver.go:11-33`. The S16 render sets it to `60s` on all four gateways; `multiorg/gw/test_render.py::test_redelivery_tick_is_60s_on_every_gateway` fails if it is empty or `0` (empty = 60 s default, `0` = off, `redeliverInterval`).
- The probe-before-dial gate stays: BI is probed through its gateway (op `usage`, type RD, 3 s) and the report view runs only when it answers 200 (`redeliver.go:25-30`, `probeBI` at `:272`). Do not remove or relax it.
- `reconcile.py` (this directory): BI's detective control. Ledger token-request keys of BI's committer DB vs the confirmed records (status 2) of the issuer's audit store, both read with `kubectl exec` inside `rd-fabricx-bi` only. READ ONLY: no apply/create/delete/patch, one namespace, the DB password is expanded in the pod. Use the org's OWN credential (BI's party for BI's namespace; never another org's), with a kubeconfig that has `pods/exec` in that namespace (party-admin has none). Exit 1 and `UNREPORTED tx ...` lines when a transaction is not confirmed.

```
python3 multiorg/fsc/reconcile.py --kubeconfig <bi kubeconfig> [--ns rd-fabricx-bi] [--token-ns rd_dfabi_v2]
```

## Credential: the Role (analyst Q18 = A)
`reconcile_role.py` prints the TIME-BOXED (R13, operator-applied, deleted right after; never standing) Role `reconcile` + RoleBinding in `rd-fabricx-bi`: verbs exactly `get` on `pods` and `create` on `pods/exec`, on ONLY `committer-db-0` (the FSC pod is a key holder and is no longer named: its audit-store half needs another read path). Old text: on exactly two names (`committer-db-0` and the current FSC pod), no list/watch/wildcard, subject = the `party-admin` ServiceAccount of `rd-fabricx-bi` only. `reconcile.py --fsc-pod <name>` addresses the pods by name and forces SPDY (`KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false`: kubectl >= 1.31 would otherwise need `get` on `pods/exec`). The FSC pod name changes at every rollout, so the Role is re-rendered and re-applied as a step of EVERY FSC rollout text; a failed reconcile after a rollout is reported as "Role stale" and never retried under cluster-admin. UNVERIFIED until the first apply: that SPDY exec with `create` only is accepted (the render was only server-dry-run validated).

## Proof (a user-word window, NOT part of this PR)
1. BI down (user-only window), send a real transfer between two banks; the bank's report answers "not delivered".
2. Restart the bank's fxapi container while BI is still down (the due set is in memory; the startup pass must recover it).
3. BI up. The fxapi redelivery log line appears [text unverified until the live run] and BI `records` contains the txid; `reconcile.py` exits 0.
4. While BI is down the gateway latency must stay below Lensa's deadline (probe gate).
