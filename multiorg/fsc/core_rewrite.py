#!/usr/bin/env python3
"""Per-org core.yaml of one FSC node (fabricx S13 piece 1; pure function, no cluster, no key read).

per_org_core(core, node, home, pod_root) -> (new_core, manifest)
  core      the NWO-generated live/<node>/core.yaml of panurus-itest as a dict (paths under `home`), never modified
  node      issuer | bank2..4 | endorser-1..4
  manifest  {pod path: {"src": host path, "kind": "secret"|"public"|"state"}}: what the per-org Secret (secret) and ConfigMap (public) must hold
Pod layout under pod_root: own/<node>/{fsc,tls,ids,wallets}/... (per node: the issuer and endorser-1 share one pod) (this node's private material: secret), public/{fsc,ids}/<peer>/... and public/ca-bundle.pem
(certificates only: public), live/<node>/{data,trace.out} (state, the PVC). A path of another node's private material is REFUSED; so is any host path this
function does not know (a new core.yaml key must be classified before it can be rendered).
Also rewritten: view API listens on 0.0.0.0; P2P resolver addresses become <node>:<port> (the node TLS certificates carry the node name; the other orgs'
names are resolved with hostAliases by the render); the committer endpoints are this org's own Services committer-sidecar:5130 and
committer-query-service:5140; MSP ids follow the genesis (org1..org4, Idemix org untouched until S15).
"""
import copy, re

NODE_ORG = {"issuer": 1, "bank2": 2, "bank3": 3, "bank4": 4, "endorser-1": 1, "endorser-2": 2, "endorser-3": 3, "endorser-4": 4}
MSP_NEW = {"Org1MSP": "org1", "OrdererOrg2MSP": "org2", "OrdererOrg3MSP": "org3", "OrdererOrg4MSP": "org4"}
SIDECAR, QUERY = "committer-sidecar:5130", "committer-query-service:5140"
FSC_PEER = r"livegen/fsc/crypto/peerOrganizations/fsc\.example\.com/peers/([A-Za-z0-9-]+)\.fsc\.example\.com"


def port(addr):
    return int(addr.rsplit(":", 1)[-1].rsplit("/", 1)[-1])


def per_org_core(core, node, home, pod_root, gw_cert=None):
    if node not in NODE_ORG:
        raise ValueError(f"unknown node {node!r}")
    manifest = {}
    own_ids = {node, "anon"}

    def put(pod, src, kind):
        manifest[pod] = {"src": src, "kind": kind}
        return pod

    def mapped(p):
        rel = p[len(home) + 1:]
        T = pod_root
        m = re.fullmatch(FSC_PEER + r"/msp/signcerts/[^/]+-cert\.pem", rel)
        if m:
            return put(f"{T}/own/{node}/fsc/cert.pem", p, "public") if m[1] == node else put(f"{T}/public/fsc/{m[1]}.pem", p, "public")
        m = re.fullmatch(FSC_PEER + r"/(msp/keystore/priv_sk|tls/server\.key)", rel)
        if m and m[1] == node:
            return put(f"{T}/own/{node}/fsc/{'key.pem' if m[2].startswith('msp') else 'tls.key'}", p, "secret")
        m = re.fullmatch(FSC_PEER + r"/tls/(server\.crt|ca\.crt)", rel)
        if m and m[1] == node:
            return put(f"{T}/own/{node}/fsc/{'tls.crt' if m[2] == 'server.crt' else 'tls-ca.crt'}", p, "public")
        if re.fullmatch(r"livegen/fsc/crypto/peerOrganizations/fsc\.example\.com/users/Admin@fsc\.example\.com/msp/signcerts/Admin@fsc\.example\.com-cert\.pem", rel):
            if gw_cert:   # S16/S14: the view API accepts the gateway's own client identity `<node>-gw` (enroll_gw.py), not the <node>-admin cert whose key was dropped
                return put(f"{T}/public/gw/{node}-gw.pem", gw_cert, "public")
            return put(f"{T}/own/{node}/fsc/admin.pem", p, "public")   # the org's own <node>-admin cert (enroll_fsc.py); never the central Admin
        m = re.fullmatch(r"ids/([A-Za-z0-9-]+)/msp", rel)
        if m:
            return put(f"{T}/own/{node}/ids/{m[1]}/msp", p, "secret") if m[1] in own_ids else put(f"{T}/public/ids/{m[1]}/msp", p, "public")
        m = re.fullmatch(r"ids/([A-Za-z0-9-]+)/tls/signcerts/cert\.pem", rel)
        if m and m[1] == node:
            return put(f"{T}/own/{node}/tls/cert.pem", p, "public")
        m = re.fullmatch(r"ids/([A-Za-z0-9-]+)/tls/keystore/[A-Za-z0-9_]+", rel)
        if m and m[1] == node:
            return put(f"{T}/own/{node}/tls/key.pem", p, "secret")
        if rel == "live/ca-bundle.pem":
            return put(f"{T}/public/ca-bundle.pem", p, "public")
        m = re.fullmatch(r"live/([A-Za-z0-9-]+)/(data/default\.sqlite|trace\.out)", rel)
        if m and m[1] == node:
            return put(f"{T}/live/{node}/{m[2]}", p, "state")
        m = re.fullmatch(r"livegen/token/crypto/[A-Za-z0-9_-]+/idemix/([A-Za-z0-9-]+)", rel)
        if m and m[1] == node:
            return put(f"{T}/own/{node}/wallets/{m[1]}", p, "secret")
        if node == "issuer" and re.fullmatch(r"livegen/token/crypto/[A-Za-z0-9_-]+/issuer/issuers/peerOrganizations/Orgissuer\.example\.com/users/issuer@Orgissuer\.example\.com/msp", rel):
            return put(f"{T}/own/{node}/wallets/issuer-msp", p, "secret")
        raise ValueError(f"host path {p!r} is not in this node's layout (another node's private material, or an unclassified key)")

    def walk(o):
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        if isinstance(o, str) and o.startswith(home + "/"):
            return mapped(o)
        return o

    out = walk(copy.deepcopy(core))
    f = out["fsc"]
    f["grpc"]["address"] = f"0.0.0.0:{port(f['grpc']['address'])}"
    for r in f["endpoint"]["resolvers"]:
        if r["name"] in NODE_ORG and (r.get("addresses") or {}).get("P2P"):
            r["addresses"]["P2P"] = f"{r['name']}:{port(r['addresses']['P2P'])}"
    d = out["fabric"]["default"]
    d["peers"][0]["address"] = d["notificationService"]["endpoints"][0]["address"] = SIDECAR
    d["queryService"]["endpoints"][0]["address"] = QUERY
    for m in d.get("msps", []):
        if m.get("mspID") in MSP_NEW:
            m["mspID"] = MSP_NEW[m["mspID"]]
    for r in d["endpoint"]["resolvers"]:
        i = r.get("identity", {})
        if i.get("mspID") in MSP_NEW:
            i["mspID"] = MSP_NEW[i["mspID"]]
    return out, manifest
