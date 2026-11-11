#!/usr/bin/env python3
"""Print the FSC pod of one org for its own namespace (fabricx PLAN S13 piece 3; stdout only, nothing is applied, no cluster, no key read).

usage: render.py bi|bank-a|bank-b|bank-c --templates <live dir with <node>/{core.yaml,role,policy.env}> --fsc-exchange <dir with org1..org4 from enroll_fsc.py --out>
                 --tls-exchange <dir with org<N>/msp/tlscacerts> --image repo@sha256:HEX --p2p-ips FILE --bootstrap-cert FILE [--central-keys FILE] [--allow-uncovered]
                 [--gw-exchange <dir with org<N>/gw/<node>-gw.pem from enroll_gw.py>] [--storage-class SC] [--zone Z] [--p2p-lb-acl acl-ID --p2p-lb-range <ipv4>/32 ...]
Objects (apply order): ConfigMap rdbi-public (every node's public certs + the TLS CA bundle), ConfigMaps rdbi-core-<node> (multiorg/fsc/core_rewrite.py output),
Services <node> (grpc/p2p/web; the node TLS certificates carry the node name), PVC rdbi-<pod>-state, NetworkPolicy rdbi-traffic, Deployment rdbi-<pod> (the org's
two nodes: init container lays the files out under $T like k8s.py did from a tarball: own/<node> from a projected volume of Secret rdbi-<pod>-files (enroll_fsc.py),
the EXISTING Secret fsc-endorser-<N>-secret and ConfigMap arma-public-<N>; public/ from rdbi-public). No Secret is rendered. The P2P LoadBalancer Service is NOT rendered
unless --p2p-lb-acl is given (spend + ACL are user-only; existing ACL id only, externalTrafficPolicy Cluster, /32 ranges only).
--central-keys: JSON list of the Secret keys the own-only import step adds to rdbi-<pod>-files (ids/anon, Idemix owner wallet, issuer wallet; central until S15).
A private path of the core that no volume item covers REFUSES the render (--allow-uncovered renders it anyway, for dry checks).
"""
import argparse, glob, json, os, re, sys
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "fca"))
import core_rewrite as cr
import enroll_fsc
import importlib.util
_spec = importlib.util.spec_from_file_location("arma_render", os.path.join(os.path.dirname(HERE), "arma", "render.py"))
arma = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(arma)

T = "/home/rdbi/.fabricx-token"
PARTY_N = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
UID = 10001
A = "service.beta.kubernetes.io/alibaba-cloud-loadbalancer-"
LABELS = {"app.kubernetes.io/part-of": "rd-fabricx"}


def die(msg):
    sys.exit(f"render.py: {msg}")


def port(addr):
    return int(addr.rsplit(":", 1)[-1].rsplit("/", 1)[-1])


def res(mem="64Mi", limit="512Mi"):
    return {"requests": {"cpu": "20m", "memory": mem, "ephemeral-storage": "64Mi"}, "limits": {"cpu": "1", "memory": limit, "ephemeral-storage": "512Mi"}}


SEC = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": UID}


def flat(rel):
    return rel.replace("/", "__")


def render(party, templates, fsc_exchange, tls_exchange, image, p2p_ips, storage_class=None, zone=None, central_keys=(), allow_uncovered=False, p2p_lb=None, home=None, bootstrap_cert=None, gw_exchange=None):
    if party not in PARTY_N:
        die(f"party {party!r} must be one of {', '.join(PARTY_N)}")
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image or ""):
        die("--image must be pinned by digest (repo@sha256:<64 hex>)")
    if not p2p_ips:
        die("--p2p-ips is required: the other orgs' node names are resolved with hostAliases (the P2P addresses are not known without it)")
    arma.check_ips(p2p_ips, "--p2p-ips")
    n, ns = PARTY_N[party], f"rd-fabricx-{party}"
    cluster = "cluster2" if party == "bank-c" else "cluster1"
    if party == "bank-c" and storage_class is None:
        die("bank-c is cluster 2: --storage-class is required (never guessed); --zone is optional (none = no zone pin)")
    if zone is None and party != "bank-c":
        zone = arma.DEFAULT_ZONE
    storage_class = arma.DEFAULT_SC if storage_class is None else storage_class
    pod, nodes = enroll_fsc.NODES[party]
    home = home or os.path.expanduser("~/.fabricx-token")
    base = {**LABELS, "party": party}
    meta = lambda name, extra=None: {"name": name, "namespace": ns, "labels": {**base, **(extra or {})}}

    cores, manifests, ports, role_env = {}, {}, {}, {}
    gw_public = {}
    all_nodes = {m: enroll_fsc.NODES[p][1] for p, m in PARTY_N.items()}
    p2p_ports = {}
    for m, ns_ in all_nodes.items():
        for x in ns_:
            c = yaml.safe_load(open(f"{templates}/{x}/core.yaml"))
            p2p_ports[x] = (port(c["fsc"]["grpc"]["address"]), port(c["fsc"]["p2p"]["listenAddress"]), port(c["fsc"]["web"]["address"]))
            if x in nodes:
                gwc = None
                if gw_exchange and x == nodes[0]:   # S14: the party node (issuer/bank<N>) is the one the gateway calls; the endorser has no gateway
                    gwc = f"{gw_exchange}/org{n}/gw/{x}-gw.pem"
                    if not os.path.isfile(gwc):
                        die(f"--gw-exchange: {gwc} is missing (enroll_gw.py output)")
                    if "PRIVATE KEY" in open(gwc).read():
                        die(f"{gwc} holds a private key: only the public gateway certificate belongs here")
                    gw_public[f"gw__{x}-gw.pem"] = open(gwc).read()
                cores[x], manifests[x] = cr.per_org_core(c, x, home, T, gw_cert=gwc)
                env = [{"name": "FSCNODE_CFG_PATH", "value": f"{T}/live/{x}"}, {"name": "RDBI_ROLE", "value": open(f"{templates}/{x}/role").read().strip()}]
                pe = f"{templates}/{x}/policy.env"
                if os.path.exists(pe):
                    env += [{"name": k, "value": v} for k, v in (l.strip().split("=", 1) for l in open(pe) if "=" in l)]
                role_env[x] = env

    # public material: every node's certificates + the TLS CAs of all four orgs
    public = dict(gw_public)
    for m, ns_ in all_nodes.items():
        for x in ns_:
            for rel in (f"fsc/{x}.pem", f"ids/{x}/msp/signcerts/cert.pem", f"ids/{x}/msp/cacerts/ca.pem"):
                public[flat(rel)] = open(f"{fsc_exchange}/org{m}/{rel}").read()
    bundle = ""
    for m in (1, 2, 3, 4):
        for p in sorted(glob.glob(f"{tls_exchange}/org{m}/msp/tlscacerts/*.pem")):
            t = open(p).read()
            bundle += t if t.endswith("\n") else t + "\n"
        if not glob.glob(f"{tls_exchange}/org{m}/msp/tlscacerts/*.pem"):
            die(f"{tls_exchange}/org{m}/msp/tlscacerts/*.pem is missing")
    public["ca-bundle.pem"] = bundle
    if not bootstrap_cert or not os.path.isfile(bootstrap_cert):
        die("--bootstrap-cert is required: the core's resolver lib-p2p-bootstrap-node names a PUBLIC cert file that the node reads at start")
    public["fsc__lib-p2p-bootstrap-node.pem"] = open(bootstrap_cert).read()

    # projected "own" volume: this pod's Secret + the existing endorser Secret + the org CA cert
    own_items = [{"key": flat(f"own/{x}/{rel}"), "path": f"{x}/{rel}"} for x in nodes for rel in enroll_fsc.own_files(x)]
    for k in central_keys:
        own_items.append({"key": k, "path": enroll_fsc.secret_path(k)[len("own/"):]})
    ex = [x for x in nodes if x.startswith("endorser-")][0]
    sources = [{"secret": {"name": f"rdbi-{pod}-files", "items": own_items}},
               {"secret": {"name": f"fsc-endorser-{n}-secret", "items": [{"key": "msp-keystore-priv_sk", "path": f"{ex}/ids/{ex}/msp/keystore/priv_sk"},
                                                                          {"key": "msp-signcert.pem", "path": f"{ex}/ids/{ex}/msp/signcerts/cert.pem"}]}},
               {"configMap": {"name": f"arma-public-{n}", "items": [{"key": "msp-cacert.pem", "path": f"{ex}/ids/{ex}/msp/cacerts/ca.pem"}]}}]
    covered = {i["path"] for s in sources for i in (s.get("secret") or s["configMap"])["items"]}
    missing = []
    for x in nodes:
        for pp, info in manifests[x].items():
            if info["kind"] == "state" or not pp.startswith(f"{T}/own/"):
                continue
            rel = pp[len(f"{T}/own/"):]
            if rel not in covered and not any(c.startswith(rel + "/") for c in covered):
                missing.append(rel)
    if missing and not allow_uncovered:
        die("these private paths of the core are covered by no volume item (central import keys missing?): " + ", ".join(sorted(missing)))

    docs = [{"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta("rdbi-public"), "data": public}]
    for x in nodes:
        docs.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(f"rdbi-core-{x}"), "data": {"core.yaml": yaml.safe_dump(cores[x], sort_keys=False, width=200)}})
    for x in nodes:
        g, p, w = p2p_ports[x]
        docs.append({"apiVersion": "v1", "kind": "Service", "metadata": meta(x),
                     "spec": {"selector": {"app.kubernetes.io/name": f"rdbi-{pod}"}, "ports": [{"name": k, "port": v, "targetPort": v} for k, v in (("grpc", g), ("p2p", p), ("web", w))]}})
    docs.append({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": meta(f"rdbi-{pod}-state"),
                 "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": storage_class, "resources": {"requests": {"storage": "2Gi"}}}})
    own_g, own_p = sorted(p2p_ports[x][0] for x in nodes), sorted(p2p_ports[x][1] for x in nodes)
    all_p = sorted(v[1] for v in p2p_ports.values())
    arma_ips = arma.IPS[cluster]
    peers_from = ([{"namespaceSelector": {"matchLabels": {"part-of": "rd-fabricx"}}}] if cluster == "cluster1" else []) + [{"ipBlock": {"cidr": arma.PEER_EGRESS[cluster]}}, {"ipBlock": {"cidr": arma.CLB_HEALTH}}]
    docs.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta("rdbi-traffic"),
                 "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": f"rdbi-{pod}"}}, "policyTypes": ["Ingress", "Egress"],
                          "ingress": [{"from": [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": f"fx-gw-{n}"}}}], "ports": [{"protocol": "TCP", "port": v} for v in own_g]},
                                      # P2P from the other orgs: the shape proven on the arma CLBs (lb-1..4, 2026-11-12): the org namespaces of this cluster, the OTHER cluster's egress /32
                                      # and the CLB health check source (backend-type eni); never any source. The CLB ACL stays the first filter.
                                      {"from": peers_from, "ports": [{"protocol": "TCP", "port": v} for v in own_p]}],
                          "egress": [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
                                     {"to": [{"podSelector": {}}]},
                                     {"to": [{"ipBlock": {"cidr": f"{ip}/32"}} for ip in sorted({*p2p_ips[cluster].values(), *arma_ips.values()})],
                                      "ports": [{"protocol": "TCP", "port": v} for v in sorted({8011, 8013, *all_p})]}]}})
    aliases = [{"ip": p2p_ips[cluster][m], "hostnames": list(ns_)} for m, ns_ in sorted(all_nodes.items()) if m != n]
    for m in (1, 2, 3, 4):   # the node dials the orderers by the genesis names (UNVERIFIED, see RUNBOOK-S13): router and assembler of every party
        aliases.append({"ip": arma_ips[m], "hostnames": [f"{r}-{m}.arma.rd" for r in ("assembler", "router")]})
    init = "set -e; mkdir -p /rdbi/public; cp -rL /src/public/. /rdbi/public/; " + "; ".join(
        f"mkdir -p /rdbi/own/{x} /rdbi/live/{x}/data /state/{x}; cp -rL /src/own/{x}/. /rdbi/own/{x}/; cp /src/core/{x}/core.yaml /rdbi/live/{x}/core.yaml" for x in nodes)
    vols = [{"name": "own", "projected": {"sources": sources, "defaultMode": 0o400}},
            {"name": "public", "configMap": {"name": "rdbi-public", "items": [{"key": k, "path": enroll_fsc.secret_path(k)} for k in public]}},
            *[{"name": f"core-{x}", "configMap": {"name": f"rdbi-core-{x}"}} for x in nodes],
            {"name": "rdbi", "emptyDir": {}}, {"name": "state", "persistentVolumeClaim": {"claimName": f"rdbi-{pod}-state"}}]
    init_c = {"name": "layout", "image": image, "securityContext": SEC, "command": ["sh", "-c", init], "resources": res("16Mi", "128Mi"),
              "volumeMounts": [{"name": "own", "mountPath": "/src/own", "readOnly": True}, {"name": "public", "mountPath": "/src/public", "readOnly": True},
                               *[{"name": f"core-{x}", "mountPath": f"/src/core/{x}", "readOnly": True} for x in nodes],
                               {"name": "rdbi", "mountPath": "/rdbi"}, {"name": "state", "mountPath": "/state"}]}
    conts = []
    for x in nodes:
        cfg = cores[x]["fabric"]["default"]
        wait = "; ".join(f"until (: >/dev/tcp/{h}/{p}) 2>/dev/null; do sleep 2; done" for h, p in (a.rsplit(":", 1) for a in (cfg["peers"][0]["address"], cfg["queryService"]["endpoints"][0]["address"])))
        conts.append({"name": x, "image": image, "securityContext": SEC, "command": ["bash", "-c", f"{wait}; exec rdbi-node node start"], "env": role_env[x],
                      "volumeMounts": [{"name": "rdbi", "mountPath": T}, {"name": "state", "mountPath": f"{T}/live/{x}/data", "subPath": x}], "resources": res()})
    spec = {"imagePullSecrets": [{"name": "ghcr-pull"}], "hostAliases": aliases,
            "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "fsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
            "initContainers": [init_c], "containers": conts, "volumes": vols}
    if zone:
        spec["nodeSelector"] = {"topology.kubernetes.io/zone": zone}
    pl = {"app.kubernetes.io/name": f"rdbi-{pod}"}
    docs.append({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta(f"rdbi-{pod}", pl),
                 "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": pl}, "template": {"metadata": {"labels": {**base, **pl}}, "spec": spec}}})
    if p2p_lb:
        acl, ranges = p2p_lb.get("acl_id"), p2p_lb.get("ranges") or []
        if not re.fullmatch(r"acl-[a-z0-9]+", acl or ""):
            die("--p2p-lb-acl must be an EXISTING access control list id (acl-...): no LB without an ACL")
        if not ranges or any(not re.fullmatch(r"\d+\.\d+\.\d+\.\d+/32", r) for r in ranges):
            die("--p2p-lb-range must be one or more <ipv4>/32 (nothing wider)")
        docs.append({"apiVersion": "v1", "kind": "Service",
                     "metadata": {**meta(f"rdbi-p2p-{pod}"), "annotations": {A + "acl-status": "on", A + "acl-id": acl, A + "acl-type": "white", A + "address-type": "internet", A + "scheduler": "wrr",
                                                                    "service.beta.kubernetes.io/backend-type": "eni"}},
                     "spec": {"type": "LoadBalancer", "externalTrafficPolicy": "Cluster", "loadBalancerSourceRanges": ranges, "selector": pl,
                              "ports": [{"name": f"p2p-{x}", "port": p2p_ports[x][1], "targetPort": p2p_ports[x][1], "protocol": "TCP"} for x in nodes]}})
    return yaml.safe_dump_all(docs, sort_keys=False)


if __name__ == "__main__":
    p = argparse.ArgumentParser(usage=__doc__, allow_abbrev=False)
    p.add_argument("party")
    for o in ("templates", "fsc-exchange", "tls-exchange", "image", "p2p-ips", "central-keys", "storage-class", "zone", "p2p-lb-acl", "bootstrap-cert", "gw-exchange"):
        p.add_argument(f"--{o}")
    p.add_argument("--p2p-lb-range", action="append", default=[])
    p.add_argument("--allow-uncovered", action="store_true")
    a = p.parse_args()
    if not (a.templates and a.fsc_exchange and a.tls_exchange and a.image):
        sys.exit(__doc__)
    ips = arma.load_ips(a.p2p_ips) if a.p2p_ips else None
    central = json.load(open(a.central_keys)) if a.central_keys else []
    lb = {"acl_id": a.p2p_lb_acl, "ranges": a.p2p_lb_range} if a.p2p_lb_acl else None
    sys.stdout.write(render(a.party, a.templates, a.fsc_exchange, a.tls_exchange, a.image, ips, a.storage_class, a.zone, central, a.allow_uncovered, lb, bootstrap_cert=a.bootstrap_cert, gw_exchange=a.gw_exchange))
