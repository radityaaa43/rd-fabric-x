# OPA Kebijakan on Fabric-X: design (draft for lead review)

Branch `feat/opa-fabricx` (worktree `platform-ekplorasi-opa-fabricx`), off `feat/opa-kebijakan` 2578a2d.
Status: design only. No live writes made.

## 1. Facts this design rests on (checked 2026-11-06, read-only)

- The FSC token nodes expose no REST API. Their only client door is the FSC view gRPC service
  (`CallView(fid, json)`, signed with the caller's X509 identity, server TLS, `clientAuthRequired: false`).
- Today Lensa runs `kubectl exec deploy/rdbi-driver -c driver -- rdbi-driver api <cmd>`
  (`frontend/server/src/adapters/fabricx.ts:11-13,107-108`).
  - rdbi-driver mounts Secret `rdbi-driver-files`, which holds the client identities of ALL nodes.
  - Ledger reads use `psql` via `kubectl exec committer-db-0` and `rdbi-bankN -c db`.
- Party to node: BI=`issuer` (pod rdbi-bi, with endorser-1), A=`bank2`, B=`bank3`, C=`bank4`
  (each rdbi-bankN pod also holds endorser-N, its committer parts and Postgres).
- Ports (grpc, p2p, web): issuer 5100-5102, bank2 5103-5105, bank3 5106-5108, bank4 5109-5111,
  endorser-1..4 5112-5123. All ClusterIP. web is disabled.
- **ns `fabricx` has NO NetworkPolicy today.** Only `fabricx-bi`, `fabricx-bank-a` and `fabricx-bank-b`
  have `default-deny-all`; `fabricx-bank-c` has none. Those namespaces hold the separate
  fabricx-transfer-v2 stack, which Lensa does not use.
- Node memory is tight (member nodes at 91-99%). Paladin gateway sizing: envoy 20m/32Mi (lim 128Mi), opa 20m/64Mi (lim 256Mi).
- Existing server-side limits (`patches/panurus-auditor-limits.patch`) are set to uint64 max: no real policy is enforced on Fabric-X today.

## 2. Enforcement hop

OPA cannot sit on the FSC gRPC door: the view name and amounts sit inside nested protobuf `bytes` inside a
signed command, and rego cannot decode protobuf. So the gateway fronts a new HTTP door instead.

```
Lensa --mTLS HTTP--> fx-gw-N (ns fabricx, one pod per party)
                       envoy :8443  -- ext_authz (body) -->  opa 127.0.0.1:9191   (gw/allow, target=fabricx)
                         |
                         v 127.0.0.1:8080
                       fxapi (new `rdbi-driver serve`, holds ONLY party N's client identity)
                         |  FSC view gRPC, own node only
                         v
                       issuer | bank2 | bank3 | bank4
```

- `rdbi-driver serve --party <node> --listen 127.0.0.1:8080`: a new subcommand that reuses the `api`
  functions. Body example: `{"op":"transfer","from":"bank2","to":"bank3","type":"RD","amount":"100"}`.
  The shim refuses any `from` other than its own party, as defence in depth behind OPA.
- Ops: `issue`, `award` (gw-1 only), `transfer`, `swap`, `redeem` (new: the api has none today),
  `balance`, `history`, `records`, `finality`, `report` (redeliver), `usage` (see 5).
  Any other op is denied by OPA.
- `run()` today waits for finality on the counterparties with their identities. In serve mode the shim waits
  only on its own node. Lensa then asks the counterparty gateway for `finality`, a read.
- Fabric's 3-of-4 endorsement, PP, channel config, rd_dfabi_v2 and FSC identities stay untouched. OPA sits on top.

## 3. DvP (swap) and award: counterparty rules

A swap is initiated by the seller's node. The buyer's RD outflow is signed by the buyer's node over P2P,
without the buyer's gateway. Award has the same shape (BI initiates, the bank pays RD).
To keep the buyer's bank rules (frozen, hours, counterparties, max_per_tx, daily_limit) enforced at the
buyer's own gateway:
- Before submitting, the initiator's fxapi POSTs `{"op":"precheck","leg":{...buyer leg...}}` to the
  counterparty gateway over mTLS. That gateway's OPA decides with its own bank bundle and usage, and the
  counterparty fxapi answers 200 without any chain action. A deny aborts the swap.
- Limit: this is enforced by trusted infrastructure, not by the buyer's node. A party that bypasses its own
  gateway (cluster admin) can still collect the buyer's signature, because the buyer node's responder
  view signs automatically. A node-side responder hook (patch to the Panurus accept view) closes that,
  but it is out of scope for v1.
- Lead decision 2026-11-06: v1 accepted, on four conditions.
  - The precheck carries the swap id, both legs, the amounts and the parties, and the buyer gateway decides on exactly that.
  - The verdict lands in the buyer gateway's sink.
  - An unreachable buyer gateway counts as deny.
  - **Known gap:** enforced by gateways, not by the buyer node; a modified initiator can skip it.

## 4. Rego (bundles shared with the Paladin gateways)

- `gw/gw.rego` is noto's (shared layer). It already dispatches on Envoy `context_extensions` `target=fabricx` to
  `data.bi.platform.fabricx` / `data.bank.platform.fabricx`. I add no rule there.
- Registry entry: `fabricx {gateways: [fx-gw-1..4], usage source}`. Format per noto's interface note.
- `bi/platform/fabricx` (BI side):
  - `issue` and `award`: gw-1 only, `max_mint_per_tx`, hours, frozen recipient.
  - `transfer`, `swap` and `redeem`: `max_per_tx`, hours, holidays, frozen sender or recipient.
  - Unknown op, token or node: deny.
- `bank/platform/fabricx` (bank side): default allow with deny overrides, mirroring `bank/paladin`.
  It covers counterparties, the bank hours window, `max_per_tx` and `daily_limit`.
- Token map in `bi/config/data.json` under `fabricx`: `RD`->`RD`, `DFABI-2027A`->`DFABI`.
  Nodes `issuer|bank2|bank3|bank4` map to `bi|bank-a|bank-b|bank-c`.
- Platform-aware helpers (`clock.token_open`, `ident.frozen_nodes`, check files) and the policy document shape
  come from noto's N-platform interface. I build against it and do not edit the shared files.

## 5. daily_limit usage from rd_dfabi_v2 token records

- The source is the party's own FSC node store (`acceptedTransactionHistory`; BI uses `audited`). These are the
  rd_dfabi_v2 token records with amounts in clear. The committer DB rows are opaque and unusable.
- `fxapi` `GET /usage?token=RD&since=<RFC3339>` sums outflows where sender == own EID, recipient != sender
  (change is excluded), action is transfer or redeem, status is not deleted, and timestamp >= since.
  Note: the timestamp is when the node stored the record, not the commit time.
- Bank rule: `http.send` to `http://127.0.0.1:8080/usage` (same pod), 2s timeout, fail closed.
  Same pattern as the Paladin `ptx_queryTransactionsFull` call.
- The Lensa Kebijakan usage view calls the same endpoint through the gateway (op `usage`, read).

## 6. Bundles, signing, decision logs (no rollout on publish)

- fx-gw-N pulls the SAME `/N/bi.tar.gz` and `/N/bank.tar.gz` from `bundle-server` in ns paladin,
  signed with `~/.opa-keys` (bi, bank-a/b/c). One publish therefore reaches bank-gw-N and fx-gw-N.
- OPA config: reuse CM `bank-gw-opa-v2` content (copied into ns fabricx as `fx-gw-opa`) with
  `decision_logs`/`status` pointing at `bundle-server.paladin.svc:8081`. The gateway id is `fx-gw-N`.
- The publish `waitFor` must wait for both bank-gw-N and fx-gw-N revisions (noto's publish code, noted to noto).
- Revision format and `model=fabricx` docs come from noto's generalisation.

## 7. mTLS

- `mtls/gen-certs.sh` gains server certs `fx-gw-1..4` from the same CA in `~/.opa-mtls`,
  plus client cert `fx-gw` for the gateway-to-gateway precheck. The `lensa` client cert is reused.
- Secrets `fx-gw-N-mtls` in ns fabricx. Envoy requires a client cert on :8443.

## 8. NetworkPolicy in ns fabricx (new; ns has none today)

Ingress-only, like the paladin set. Each flow and its evidence (to be re-verified before apply by
watching `ss`/conntrack in each pod):

File: `fabric-x/opa/networkpolicy.yaml`. Server dry-run passes. The evidence is in its header.

| Policy | Selects | Allows ingress from | Port(s) |
|---|---|---|---|
| rdbi-<pod>-ingress | rdbi-bi / rdbi-bankN | part-of=rdbi | that pod's node and endorser p2p (5101+5113, 5104+5116, 5107+5119, 5110+5122) |
| | | fx-gw-N only | that pod's view gRPC (5100 / 5103 / 5106 / 5109) |
| | | rdbi-driver | all ports (maintenance or e2e only, while scaled up) |
| default-deny-all | ns fabricx-bank-c (0 pods) | none | none |

- Bank committers and Postgres are pod-local, so they need no rule. The rdbi pods have no probes.
- fx-gw pods are not selected. Their door is guarded by mTLS, the same as bank-gw-N in ns paladin.

rdbi-driver: after cut-over, scale to 0 (it holds all identities). It comes back up only for maintenance or e2e,
with a lead go.

## 9. Remaining bypasses after cut-over

1. `kubectl exec` into rdbi-bi/rdbi-bankN or fx-gw-N, or into rdbi-driver if scaled up: needs cluster-admin
   kubeconfig. Not closable by OPA; same as Paladin.
2. `kubectl port-forward` to an FSC gRPC port: kubelet traffic is not subject to NetworkPolicy. Cluster-admin only.
3. The host `~/.fabricx-token/live/*/client-config.yaml` keys + port-forward: same as 2.
4. Ledger reads via `psql` exec (committer-db, bank db): reads only, no policy effect. Kept for Lensa ledger views.
5. Direct submission to orderer routers (NodePorts 30050..30350) with a party's keys: still needs 3-of-4 endorsement
   and owner signatures, so no unilateral move. Fabric's own policy covers this.
6. DvP counterparty leg (section 3) if the initiator bypasses its gateway.

## 10. Footprint

4 new pods `fx-gw-1..4` (ns fabricx), no PVC:
- envoy 20m/32Mi (lim 128Mi)
- opa 20m/64Mi (lim 256Mi)
- fxapi 10m/32Mi (lim 256Mi)

Total requests: 200m CPU / 512Mi. One image push: `ghcr.io/radityaaa43/rdbi-node` with `serve` (same image as nodes).
New Secrets: `fx-gw-N-files` (party N identity only) and `fx-gw-N-mtls`.

## 11. Lensa

- `fabricx.ts` transport: `kubectl exec` replaced by HTTPS mTLS to `127.0.0.1:<port>`, via new
  `lensa-pf@fx-gw-N` units (same as Paladin). Ledger psql reads stay as they are (bypass 4).
- Lensa holds 3 tx in flight, one per sender; unchanged.

Placement (lead condition):
- Before any apply, show per-node allocatable vs requested memory.
- Pin fx-gw-N with nodeSelector/affinity to nodes with headroom.
- If no node fits: stop and report. No eviction.

## 12. Live-write sequence (each step needs lead go + user go)

Order per lead: bring up fx-gw-N, switch Lensa, verify, then scale rdbi-driver to 0 (this frees memory).
The NetworkPolicy step also covers `fabricx-bank-c`, which has no default-deny today.

1. Image push (`serve`).
2. Secrets `fx-gw-N-files`, `fx-gw-N-mtls`, CM `fx-gw-opa`.
3. Deploy fx-gw-1..4. Paladin netpol: add a bundle-server ingress allow from ns fabricx app=fx-gw if needed.
4. Publish bundles with the fabricx rules. Prove Zeto/Noto verdicts are unchanged:
   - the opa test suite is unchanged and green;
   - replaying recent sink decision inputs through the old and new bundles gives 0 diffs.
5. Lensa switch (update.sh + restart).
6. NetworkPolicy in ns fabricx.
7. Scale rdbi-driver to 0.
8. Live S1-S6 on fabricx with restore.

Rollback per step:
- delete fx-gw / netpol;
- republish the previous CM;
- revert Lensa to exec;
- scale rdbi-driver back to 1.
