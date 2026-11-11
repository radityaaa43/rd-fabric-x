# S16: render the fx-gw-<N> gateway per org (fabricx)

Status: PRE-STAGE. Repo-only; `render.py` prints YAML and applies nothing. Source: final-design/fabricx/PLAN.md S16 (DELTA 9), old form `panurus-itest/scripts/k8s.py:287-420`, shape of besu's stealth gateway (rd-besu #55).

## Command
```
python3 multiorg/gw/render.py <bi|bank-a|bank-b|bank-c> --templates ~/.fabricx-token/live --image <rdbi-node@sha256> --envoy-image <envoy@sha256> --opa-image <opa@sha256> \
  --opa-config ~/.opa-keys/opa-config.yaml --gw-cert <public cert of identity <node>-gw> --gw-ips FILE --client-cidr <ipv4>/32 ... [--lb-acl acl-ID --lb-range <ipv4>/32 ...]
```
No default for the images (digest or refusal), the OPA config (public keys only, a `PRIVATE KEY` refuses), `--gw-ips` (the address of each gateway for peers in the OTHER cluster) or `--client-cidr` (Lensa source, /32 only).

## Objects (namespace `rd-fabricx-<party>`)
ConfigMaps `fx-gw-<N>-envoy`, `fx-gw-<N>-opa`, `fx-gw-<N>-client`; Services `fx-gw-<N>` (ClusterIP 8443) and one ExternalName `fx-gw-<M>` per same-cluster peer; NetworkPolicy `fx-gw-<N>` (ingress 8443: gateway pods of namespaces `part-of=rd-fabricx`, the other cluster's egress /32, `--client-cidr`; plus 100.64.0.0/10 only with the LB); Deployment `fx-gw-<N>` (envoy + OPA + fxapi, one pod, Recreate). LoadBalancer Service `fx-gw-<N>-lb` only with `--lb-acl` (existing ACL, eTP Cluster, `backend-type: eni`).

## Secrets the render needs but does not create (custody step)
- `fx-gw-<N>-server`: `tls.crt`, `tls.key` (SAN `fx-gw-<N>`, from the org's OWN TLS CA).
- `fx-gw-<N>-client-ca`: `ca.crt` = `bank-gw-ca-<N>` public CA (Lensa) + the 4 orgs' public TLS CAs (peer gateways).
- `fx-gw-<N>-peer`: `tls.crt`, `tls.key` (identity `fx-gw-<N>-peer`, client + server EKU, SAN `fx-gw-<N>`). fxapi presents it to the other gateways (`FXGW_TLS=/peer`, `serve.go:104-117`).
- `fx-gw-<N>-client`: `gw.key` (identity `<node>-gw`, client, org CA). Its public cert goes into the render (`--gw-cert`) and into ConfigMap `fx-gw-<N>-client`.
- ConfigMap `rdbi-public` (S13, key `ca-bundle.pem`) is projected as the peer RootCAs and the node's TLS CA.

## Why peers work without a driver change
The driver dials `https://fx-gw-<M>:8443/` (`serve.go:43`, hardcoded). Same-cluster peers resolve through ExternalName Services, cross-cluster peers through `hostAliases` (`--gw-ips`). The SAN `fx-gw-<M>` still matches.

## Identity binding (lead's condition; the rego is besu's)
Trust bundle = Lensa CA + 4 TLS CAs, so any org CA can mint `CN=fx-gw-1`. Envoy therefore sets `forward_client_cert_details: SANITIZE_SET` and `set_current_client_cert_details {cert, subject}`; the rego must accept `fx-gw-<N>` only when the leaf verifies against org N's TLS CA, and `lensa` only against `bank-gw-ca-<N>`. XFCC has NO issuer field at the pinned envoy (a config with `issuer: true` is refused by `--mode validate`), so the rego verifies the forwarded leaf PEM against CA PEMs from its data.

## Smoke (run before every apply of a changed render)
`python3 -I multiorg/gw/smoke.py --templates DIR --opa-config FILE --gw-ips FILE --envoy-image ... --opa-image ...`: `envoy --mode validate` on the rendered config and OPA started with the rendered args (must reach `Starting gRPC server`; only the bundle pull may fail).

## Unverified
- fxapi needs `HOME` writable (emptyDir `/home/rdbi`) and the files under `$HOME/.fabricx-token/{live,gw}` read-only; no start-up of `rdbi-driver serve` was tried with this layout.
- Whether the rdbi-node image carries `bash` for the fxapi readiness probe (old form used it).
- NetworkPolicy is ingress-only; egress of the gateway pod is open (OPA to the bundle-server, fxapi to `<node>`, peers).
- The node still lists the `<node>-admin` cert in `fsc.client.certs` until the S16 field-change line swaps it for the `<node>-gw` cert.

## Known gap (record, closed at S15)
A peer org that controls DNS or hostAliases in a gateway pod could impersonate a peer gateway server (fxapi trusts the 4 TLS CA roots, SAN match only). Per-peer pinning needs the driver (S15 rebuild).
