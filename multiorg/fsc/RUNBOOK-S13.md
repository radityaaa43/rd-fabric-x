# S13: FSC node + endorser per org (fabricx), custody pieces

Status: repo only. Nothing here touches a cluster. Source: final-design/fabricx/PLAN.md S13 (DELTA 10, 1).

## Pieces
1. `core_rewrite.py`: `per_org_core(core, node, home, pod_root) -> (core, manifest)` turns the NWO-generated `~/.fabricx-token/live/<node>/core.yaml` (local template) into the per-org core.yaml. Private files only under `own/<node>/` (the issuer and endorser-1 share one pod), other nodes only as public certs under `public/`; another node's private path or an unclassified host path is REFUSED. `fsc.client.certs` = the node's own `<node>-admin` cert (`own/<node>/fsc/admin.pem`), replaced by the org's fx-gw client cert in S16; never the central Admin@fsc cert. Committer endpoints = the org's own `committer-sidecar:5130` / `committer-query-service:5140` (S12). MSP ids org1..org4.
2. `enroll_fsc.py <party> rd-fabricx-<party> --kubeconfig K --ca-url http://localhost:<port> --work /dev/shm/<dir> --exchange <dir with org<N>/msp/{cacerts,knowncerts}> --out <new>/org<N> [--generation TAG]`: identities at the org's OWN CA (all type client, not removable): `<node>-fsc`, `<node>-admin` (cert only), `<node>-id` (issuer/banks), `endorser-<N>-tls` (endorsers). ONE Secret `rdbi-<pod>-files` (pods bi, bank2, bank3, bank4; `kubectl create`, keys = pod paths with `/` as `__`, `secret_key()`/`secret_path()`) and a public tree (`fsc/<node>.pem`, `admin/<node>-admin.pem`, `ids/<node>/msp/{signcerts,cacerts}`, MANIFEST). Same custody rules as enroll.py/make_secrets.py. `ids/endorser-<N>/msp` is the EXISTING Secret `fsc-endorser-<N>-secret` (the genesis known_certs identity; never re-registered or copied), to be mounted by the render.
3. (next) render, 4. (next) import-central + smoke.

## Pod layout (what the render must produce)
`$T/own/<node>/{fsc/{cert.pem,key.pem,tls.crt,tls.key,tls-ca.crt,admin.pem},tls/{cert.pem,key.pem},ids/<node>/msp/...}` from the Secret items (`secret_path()` restores the sub-path), `$T/public/...` from ConfigMap `rdbi-public` (the other orgs' public trees + all four TLS CAs), `$T/live/<node>/{data,trace.out}` = the PVC.

## Unverified (the first node start on the cluster settles them)
- FSC P2P verifies a peer by the PINNED resolver cert (`fsc.endpoint.resolvers[].identity.path`), not by a chain to one CA. Working assumption (lead 2026-11-12); hostAliases keep the node names that the TLS certs carry.
- The FSC MSP loader accepts the layout without a NodeOU `config.yaml` (the committer needed one in S12).
- Real core.yaml keys that the local template does not show. The rewriter refuses unknown host paths on purpose.
- ids/anon, the Idemix owner wallet and the issuer wallet MSP stay central until S15: an own-only import step (piece 4), never another node's files.
