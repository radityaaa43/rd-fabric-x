#!/usr/bin/env python3
"""Print everything one Arma party needs in its namespace (fabricx PLAN S11 parties 1-3 on cluster 1, S18 party 4 on cluster 2; stdout only, nothing is applied, no cluster).

usage: render.py bi|bank-a|bank-b|bank-c --exchange DIR --genesis FILE --genesis-sha256 HEX [--image repo@sha256:HEX] [--replicas N]
                 [--zone Z] [--storage-class SC] [--ips FILE] [--msp-id-format org{n}]
bank-c is cluster 2: --zone and --storage-class are required (lead: ap-southeast-1a, fabricx-essd). Cluster 1 defaults: ap-southeast-5b, alicloud-essd-wffc.
DIR holds org1..org4 (public trees from multiorg/fca/enroll.py; each is checked with check_exchange and must be clean). FILE is the S10 genesis block,
refused unless its sha256 equals HEX and it is at most 700 KiB. Output (YAML documents, apply order): ConfigMaps genesis-block, arma-public-<N>, 4 x arma-config-<role>-<N>,
NetworkPolicy allow-arma-peers, then 4 StatefulSets orderer-{router,batcher,consenter,assembler}-<N>. No Secret (orderer-<role>-<N>-secret is made by enroll.py)
and no Service (lb-<N> is made by multiorg/lb/render.py). See RUNBOOK-S11.md.
"""
import argparse, base64, glob, hashlib, ipaddress, os, re, sys
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fca"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from enroll import PARTY_N, PORT_PLAN, ROLES, SECRET_ROLE   # PORT_PLAN is the single source of the ports (ADR 0001)
import check_exchange

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE = "docker.io/hyperledger/fabric-x-orderer@sha256:052ae8e16571d3d4de2e1a0c4e9ed0d979d782d3539d3c8fb1f7f66fe560e265"  # 1.0.4, as running today
DEFAULT_SC, DEFAULT_ZONE = "alicloud-essd-wffc", "ap-southeast-5b"   # cluster 1, as multiorg/fca/render.py
AVOID_NODES = ["member-16033-node", "member-16034-node"]            # as panurus-itest/scripts/k8s.py: nodes other work uses (cluster 1)
# the block goes into a ConfigMap as base64 binaryData (x 4/3) and the whole object must stay under 1 MiB: 700 KiB raw is ~934 KiB encoded
MAX_GENESIS = 700 * 1024
UID = 10001
ID_ARG = {"router": "router", "batcher1": "batcher", "consenter": "consenter", "assembler": "assembler"}   # args the old StatefulSets used; = SECRET_ROLE
HOST = "{role}-{n}.arma.rd"   # genesis Host of every role (decision A: one config block with stable names; each pod resolves them with hostAliases)

# Name -> address per pod cluster (decision A). Cluster 1 pods reach parties 1-3 through the ClusterIP of Service lb-<N> and party 4 through the public
# address of lb-4; cluster 2 pods the reverse. A later change is `--ips FILE` (same shape), no code edit.
IPS = {"cluster1": {1: "10.200.55.11", 2: "10.200.27.215", 3: "10.200.63.143", 4: "47.236.199.240"},
       "cluster2": {1: "8.215.24.249", 2: "8.215.30.255", 3: "147.139.133.68", 4: "10.210.48.103"}}
# Ingress allowed from the OTHER cluster: its egress address. cluster1 namespaces allow cluster 2's, bank-c (cluster 2) allows cluster 1's.
PEER_EGRESS = {"cluster1": "47.237.84.150/32", "cluster2": "8.215.62.92/32"}
# [unverified] first-guess sizes, to be settled by the first run
RESOURCES = {"requests": {"cpu": "50m", "memory": "128Mi", "ephemeral-storage": "64Mi"},
             "limits": {"cpu": "1", "memory": "512Mi", "ephemeral-storage": "512Mi"}}

yaml.add_representer(str, lambda d, s: d.represent_scalar("tag:yaml.org,2002:str", s, style="|" if "\n" in s else None), Dumper=yaml.SafeDumper)


def die(msg):
    sys.exit(f"render.py: {msg}")


def check_ips(doc, where):
    if not isinstance(doc, dict) or set(doc) != set(IPS):
        die(f"{where}: needs exactly the keys {', '.join(IPS)}")
    for cl, table in doc.items():
        if not isinstance(table, dict) or set(table) != {1, 2, 3, 4}:
            die(f"{where}: {cl} needs exactly the parties 1, 2, 3, 4")
        for n, ip in table.items():
            try:
                a = ipaddress.IPv4Address(ip)
            except (ValueError, TypeError):
                die(f"{where}: {cl} party {n}: {ip!r} is not an IPv4 address")
            if a.is_unspecified or a.is_loopback or a.is_multicast or a.is_link_local:
                die(f"{where}: {cl} party {n}: {ip} is not a usable address")
        if len(set(table.values())) != 4:
            die(f"{where}: {cl}: two parties share one address")
    return doc


def load_ips(path):
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        die(f"--ips {path}: {e}")
    return check_ips(doc, f"--ips {path}")


def read_exchange(exchange, n):
    """Validate all four public trees; return (TLS CA bundle of all orgs, this org's CA certs)."""
    for m in (1, 2, 3, 4):
        d = f"{exchange}/org{m}"
        if not os.path.isdir(d):
            die(f"{d} is missing: --exchange needs org1..org4")
        found = check_exchange.problems(d, m)
        if found:
            die(f"org{m} exchange tree is not clean: {'; '.join(found[:5])}")
        ep = yaml.safe_load(open(f"{d}/endpoints.yaml"))
        for role in ROLES:   # the genesis Host/Port are the name plan; hostAliases only resolve those names
            want = {"Host": HOST.format(role=role, n=m), "Port": PORT_PLAN[role]}
            got = ep.get(role)
            if not isinstance(got, dict) or {k: got.get(k) for k in want} != want:
                die(f"org{m}: endpoints.yaml {role} is {got!r}, the name plan wants {want}")

    def pems(pattern):
        return "".join(t if t.endswith("\n") else t + "\n" for p in sorted(glob.glob(pattern)) for t in [open(p).read()])
    return pems(f"{exchange}/org*/msp/tlscacerts/*.pem"), pems(f"{exchange}/org{n}/msp/cacerts/*.pem")


def read_genesis(path, sha):
    if not re.fullmatch(r"[0-9a-f]{64}", sha or ""):
        die("--genesis-sha256 must be 64 lowercase hex characters")
    try:
        if os.path.getsize(path) > MAX_GENESIS:
            die(f"--genesis {path} is larger than {MAX_GENESIS} bytes (700 KiB)")
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        die(f"--genesis {path}: {e.strerror}")
    if hashlib.sha256(data).hexdigest() != sha:
        die("--genesis sha256 differs from --genesis-sha256")
    return data


def node_config(text, role, n, msp_id, ops_port):
    """The old node config with ONLY these lines changed: PartyID, General.ListenPort, General.LocalMSPID, Operations.ListenPort, Batcher.ShardID,
    and the prometheus client CA line removed. Every rule must hit exactly once, otherwise the template drifted: refuse."""
    shard = re.fullmatch(r"batcher(\d+)", role)
    rules = [("", r"PartyID: \d+", f"PartyID: {n}"), ("General", r"  ListenPort: \d+", f"  ListenPort: {PORT_PLAN[role]}"),
             ("General", r"  LocalMSPID: \S+", f"  LocalMSPID: {msp_id}"), ("Operations", r"  ListenPort: \d+", f"  ListenPort: {ops_port}"),
             ("Operations", r"      - /config/mtls/prometheus/ca\.crt", None)]
    if shard:
        rules.append(("Batcher", r"  ShardID: \d+", f"  ShardID: {shard.group(1)}"))
    hits, out, top = [0] * len(rules), [], ""
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\n")
        if re.match(r"[A-Za-z]", body):
            top = body.split(":")[0]
        for i, (sec, pat, new) in enumerate(rules):
            if (sec == "" or sec == top) and re.fullmatch(pat, body):
                hits[i] += 1
                line = None if new is None else new + "\n"
                break
        if line is not None:
            out.append(line)
    if hits != [1] * len(rules):
        die(f"node config template for {role} drifted: rule hits {hits}")
    return "".join(out)


def render(party, exchange, genesis, genesis_sha256, image=IMAGE, replicas=1, zone=None, storage_class=None, ips=None, msp_id_format="org{n}"):
    if party not in PARTY_N:
        die(f"party {party!r} unknown; use one of {', '.join(PARTY_N)}")
    if not isinstance(image, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}", image):
        die("--image must be pinned by digest (repo@sha256:<64 lowercase hex>)")
    if not isinstance(replicas, int) or replicas < 1:
        die("--replicas must be 1 or more (a render never starts nothing)")
    if "{n}" not in msp_id_format or not re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]*", msp_id_format.replace("{n}", "1")):
        die(f"--msp-id-format {msp_id_format!r} must contain {{n}} and give an MSP name")
    cluster = "cluster2" if party == "bank-c" else "cluster1"
    if party == "bank-c" and (zone is None or storage_class is None):
        die("bank-c is cluster 2: --zone and --storage-class are both required (never guessed)")
    zone = DEFAULT_ZONE if zone is None else zone
    storage_class = DEFAULT_SC if storage_class is None else storage_class
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", zone):
        die(f"zone {zone!r} is not a zone name")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", storage_class):
        die(f"storage class {storage_class!r} is not a name")
    table = load_ips(ips) if ips else IPS   # the built-in table is checked by test_arma
    n, ns = PARTY_N[party], f"rd-fabricx-{party}"
    tls_bundle, msp_ca = read_exchange(exchange, n)
    gen = read_genesis(genesis, genesis_sha256)
    msp_id = msp_id_format.replace("{n}", str(n))

    base = {"app.kubernetes.io/part-of": "rd-fabricx", "party": party}
    meta = lambda name, extra=None: {"name": name, "namespace": ns, "labels": {**base, **(extra or {})}}
    docs = [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta("genesis-block"), "binaryData": {"genesis.block": base64.b64encode(gen).decode()}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(f"arma-public-{n}"), "data": {"tls-ca-bundle.crt": tls_bundle, "msp-cacert.pem": msp_ca}},
    ]
    for i, role in enumerate(ROLES):
        with open(f"{HERE}/templates/{ID_ARG[role]}-1.yaml") as f:
            cfg = node_config(f.read(), role, n, msp_id, 7060 + i)
        docs.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(f"arma-config-{ID_ARG[role]}-{n}"), "data": {"node-config.yaml": cfg}})

    peers = ([{"namespaceSelector": {"matchLabels": {"part-of": "rd-fabricx"}}}] if cluster == "cluster1" else []) + [{"ipBlock": {"cidr": PEER_EGRESS[cluster]}}]
    docs.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta("allow-arma-peers"),
                 "spec": {"podSelector": {"matchLabels": {"rd-fabricx/arma-party": str(n)}}, "policyTypes": ["Ingress"],
                          # [unverified] that the Terway policy engine sees the preserved client source IP behind the CLB (externalTrafficPolicy Local)
                          "ingress": [{"from": peers, "ports": [{"protocol": "TCP", "port": p} for p in sorted(PORT_PLAN.values())]}]}})

    aliases = [{"ip": table[cluster][m], "hostnames": [HOST.format(role=r, n=m) for r in ROLES]} for m in (1, 2, 3, 4)]
    affinity = {"podAntiAffinity": {"preferredDuringSchedulingIgnoredDuringExecution": [{"weight": 100, "podAffinityTerm": {
        "topologyKey": "kubernetes.io/hostname", "labelSelector": {"matchLabels": {"rd-fabricx/arma-party": str(n)}}}}]}}
    if cluster == "cluster1":
        affinity["nodeAffinity"] = {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [
            {"key": "kubernetes.io/hostname", "operator": "NotIn", "values": AVOID_NODES}]}]}}
    for i, role in enumerate(ROLES):
        obj = ID_ARG[role]
        name = f"orderer-{obj}-{n}"
        labels = {**base, "app.kubernetes.io/name": name, "rd-fabricx/arma-party": str(n)}
        secret_keys = {"msp-keystore-priv_sk": "/config/msp/keystore/priv_sk", "msp-signcert.pem": f"/config/msp/signcerts/{role}-cert.pem",
                       "tls-server.key": "/config/tls/server.key", "tls-server.crt": "/config/tls/server.crt"}
        mount = lambda vol, path, sub: {"name": vol, "mountPath": path, "subPath": sub, "readOnly": True}
        item = lambda k: {"key": k, "path": k}
        mounts = [mount("secret", mp, k) for k, mp in secret_keys.items()] + [
            mount("public", "/config/tls/ca.crt", "tls-ca-bundle.crt"), mount("public", "/config/msp/cacerts/ca.pem", "msp-cacert.pem"),
            mount("genesis", "/config/genesis.block", "genesis.block"), mount("config", "/config/node_config.yaml", "node_config.yaml"),
            {"name": "data", "mountPath": "/data"}]
        volumes = [{"name": "secret", "secret": {"secretName": f"orderer-{SECRET_ROLE[role]}-{n}-secret", "defaultMode": 0o400, "items": [item(k) for k in secret_keys]}},
                   {"name": "public", "configMap": {"name": f"arma-public-{n}", "items": [item("tls-ca-bundle.crt"), item("msp-cacert.pem")]}},
                   {"name": "genesis", "configMap": {"name": "genesis-block", "items": [item("genesis.block")]}},
                   {"name": "config", "configMap": {"name": f"arma-config-{obj}-{n}", "items": [{"key": "node-config.yaml", "path": "node_config.yaml"}]}}]
        docs.append({
            "apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": meta(name, {"app.kubernetes.io/name": name, "rd-fabricx/arma-party": str(n)}),
            "spec": {"replicas": replicas, "serviceName": f"lb-{n}", "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
                     "template": {"metadata": {"labels": labels}, "spec": {
                         "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "seccompProfile": {"type": "RuntimeDefault"}, "fsGroup": UID},
                         "nodeSelector": {"topology.kubernetes.io/zone": zone}, "affinity": affinity, "hostAliases": aliases,
                         "containers": [{
                             "name": "orderer", "image": image, "args": [obj, "--config=/config/node_config.yaml"],
                             # S11 pod contract with lb-<N>: one NAMED port per role pod (the Service targetPort), plus ops on its own number
                             "ports": [{"name": role, "containerPort": PORT_PLAN[role]}, {"name": "ops", "containerPort": 7060 + i}],
                             "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                             "resources": RESOURCES, "volumeMounts": mounts}],
                         "volumes": volumes}},
                     "volumeClaimTemplates": [{"metadata": {"name": "data", "labels": base}, "spec": {
                         "accessModes": ["ReadWriteOnce"], "storageClassName": storage_class, "resources": {"requests": {"storage": "2Gi"}}}}]}})
    return yaml.safe_dump_all(docs, sort_keys=False)


if __name__ == "__main__":
    p = argparse.ArgumentParser(usage=__doc__, allow_abbrev=False)
    p.add_argument("party")
    for o in ("exchange", "genesis", "genesis-sha256", "zone", "storage-class", "ips"):
        p.add_argument(f"--{o}")
    p.add_argument("--image", default=IMAGE)
    p.add_argument("--replicas", type=int, default=1)
    p.add_argument("--msp-id-format", default="org{n}")
    a = p.parse_args()
    if not (a.exchange and a.genesis and a.genesis_sha256):
        sys.exit(__doc__)
    sys.stdout.write(render(a.party, a.exchange, a.genesis, a.genesis_sha256, a.image, a.replicas, a.zone, a.storage_class, a.ips, a.msp_id_format))
