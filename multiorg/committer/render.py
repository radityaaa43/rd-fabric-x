#!/usr/bin/env python3
"""Print one org's Fabric-X committer for its namespace (fabricx PLAN S12; stdout only, nothing is applied, no cluster).

usage: render.py bi|bank-a|bank-b|bank-c [--image repo@sha256:HEX] [--pg-image repo@sha256:HEX] [--zone Z] [--storage-class SC] [--ips FILE] [--msp-id-format org{n}]
bank-c is cluster 2: --storage-class is required (fabricx-essd); --zone is optional, none = no zone pin (as multiorg/arma/render.py since 043f3bc). Cluster 1 defaults: ap-southeast-5b, alicloud-essd-wffc.
Output (YAML documents, apply order): ConfigMaps committer-config-{verifier,vc,coordinator,sidecar,query} and committer-msp-config, NetworkPolicy committer-traffic,
Services committer-{db,verifier,vc,coordinator,sidecar,query-service} (all ClusterIP), StatefulSet committer-db (Postgres, TLS), Deployments committer-{verifier,vc,coordinator},
StatefulSet committer-sidecar, Deployment committer-query. No Secret: the names it references are listed in RUNBOOK-S12.md. See there for what is unverified.
"""
import argparse, copy, importlib.util, os, re, sys
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(HERE, "config")   # the old per-bank committer configs; each is changed only by RULES below

# The Arma render is the single source of the party plan, the name -> address table and the cluster defaults (same names, same addresses).
_spec = importlib.util.spec_from_file_location("arma_render", os.path.join(os.path.dirname(HERE), "arma", "render.py"))
arma = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(arma)

# committer 1.0.4 and postgres 17.10 as the cluster runs them today (panurus-itest/scripts/k8s.py:37-38)
COMMITTER_IMAGE = "docker.io/hyperledger/fabric-x-committer@sha256:b5bc4c6c010f54843dfb023cb1f18f56d4cd9b958565efd243e20a0a35b5a13d"
PG_IMAGE = "docker.io/library/postgres@sha256:7958605b474b3d264a969cb3a123d6aa00ad1e1fe9da8a69984dabb704d93317"
PG_UID, UID = 999, arma.UID   # postgres image user (k8s.py: runAsUser 999); committer image USER 10001 (upstream docker/images/release/Dockerfile:51)
# service -> (service port, monitoring port): the ports of the old configs (config/*.yaml)
SERVICES = {"verifier": (5110, 5210), "vc": (5100, 5200), "coordinator": (5120, 5220), "sidecar": (5130, 5230), "query": (5140, 5240)}
CONFIGS = list(SERVICES)
# [unverified] first-guess sizes, to be settled by the first run
RES_COMMITTER = {"requests": {"cpu": "50m", "memory": "64Mi", "ephemeral-storage": "64Mi"}, "limits": {"cpu": "1", "memory": "512Mi", "ephemeral-storage": "512Mi"}}
RES_DB = {"requests": {"cpu": "100m", "memory": "128Mi", "ephemeral-storage": "64Mi"}, "limits": {"cpu": "1", "memory": "1Gi", "ephemeral-storage": "512Mi"}}
ASSEMBLER_PORT = arma.PORT_PLAN["assembler"]

# Per config: (top-level section, whole-line regex, replacement). Every rule must hit exactly once, otherwise the template drifted: refuse.
DB_TLS = "  tls: {mode: tls, ca-cert-path: /config/db-tls/ca.crt}"   # upstream vc.yaml:62-67, docs/tls-configurations.md:129-136
RULES = {
    "verifier": [],
    "vc": [("", r"# The database is the bank's own Postgres on the compose network, without TLS \(not published to the host\);",
            "# The database is the org's own Postgres in this namespace (Service committer-db), with TLS: server authentication against the CA below;"),
           ("database", r"  endpoints: \[db:5432\]", "  endpoints: [committer-db:5432]"),
           ("database", r"  tls: \{mode: none\}", DB_TLS)],
    "query": [("database", r"  endpoints: \[db:5432\]", "  endpoints: [committer-db:5432]"),
              ("database", r"  tls: \{mode: none\}", DB_TLS)],
    "coordinator": [("verifier", r"  endpoints: \[verifier:5110\]", "  endpoints: [committer-verifier:5110]"),
                    ("validator-committer", r"  endpoints: \[vc:5100\]", "  endpoints: [committer-vc:5100]")],
    "sidecar": [("committer", r"  endpoint: coordinator:5120", "  endpoint: committer-coordinator:5120")],
}

yaml.add_representer(str, lambda d, s: d.represent_scalar("tag:yaml.org,2002:str", s, style="|" if "\n" in s else None), Dumper=yaml.SafeDumper)


def die(msg):
    sys.exit(f"render.py: {msg}")


def config_text(svc):
    """The old config with ONLY the RULES lines changed; a rule that does not hit exactly once means the template drifted: refuse."""
    try:
        with open(f"{CONFIG_DIR}/{svc}.yaml") as f:
            text = f.read()
    except OSError as e:
        die(f"config template {svc}.yaml: {e.strerror}")
    rules = RULES[svc]
    hits, out, top = [0] * len(rules), [], ""
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\n")
        if re.match(r"[A-Za-z]", body):
            top = body.split(":")[0]
        for i, (sec, pat, new) in enumerate(rules):
            if (sec == "" or sec == top) and re.fullmatch(pat, body):
                hits[i] += 1
                line = new + "\n"
                break
        out.append(line)
    if hits != [1] * len(rules):
        die(f"config template for {svc} drifted: rule hits {hits}")
    return "".join(out)


def render(party, image=COMMITTER_IMAGE, pg_image=PG_IMAGE, zone=None, storage_class=None, ips=None, msp_id_format="org{n}"):
    if party not in arma.PARTY_N:
        die(f"party {party!r} unknown; use one of {', '.join(arma.PARTY_N)}")
    for what, img in (("--image", image), ("--pg-image", pg_image)):
        if not isinstance(img, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}", img):
            die(f"{what} must be pinned by digest (repo@sha256:<64 lowercase hex>)")
    if not isinstance(msp_id_format, str) or "{n}" not in msp_id_format or not re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]*", msp_id_format.replace("{n}", "1")):
        die(f"--msp-id-format {msp_id_format!r} must contain {{n}} and give an MSP name")
    cluster = "cluster2" if party == "bank-c" else "cluster1"
    if party == "bank-c" and storage_class is None:
        die("bank-c is cluster 2: --storage-class is required (never guessed); --zone is optional (none = no zone pin)")
    if zone is None and party != "bank-c":
        zone = arma.DEFAULT_ZONE
    storage_class = arma.DEFAULT_SC if storage_class is None else storage_class
    if zone is not None and not re.fullmatch(r"[a-z0-9][a-z0-9-]*", zone):
        die(f"zone {zone!r} is not a zone name")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", storage_class):
        die(f"storage class {storage_class!r} is not a name")
    table = arma.load_ips(ips) if ips else arma.IPS
    n, ns = arma.PARTY_N[party], f"rd-fabricx-{party}"
    msp_id = msp_id_format.replace("{n}", str(n))
    configs = {svc: config_text(svc) for svc in CONFIGS}   # all refusals before any output

    base = {"app.kubernetes.io/part-of": "rd-fabricx", "party": party, "rd-fabricx/committer": "true"}
    meta = lambda name: {"name": name, "namespace": ns, "labels": dict(base)}
    item = lambda k, path=None: {"key": k, "path": path or k}
    mount = lambda vol, path, sub: {"name": vol, "mountPath": path, "subPath": sub, "readOnly": True}
    secret_vol = lambda name, secret, keys: {"name": name, "secret": {"secretName": secret, "defaultMode": 0o400, "items": [item(k) for k in keys]}}
    secret_ref = lambda name, key: {"secretKeyRef": {"name": name, "key": key}}

    docs = [{"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(f"committer-config-{svc}"), "data": {f"{svc}.yaml": configs[svc]}} for svc in CONFIGS]
    # the local MSP classifies identities by OU like the channel MSPs; fabric-ca-client writes no config.yaml (committer.sh:30-32, panurus-itest/scripts/k8s.py:131-135)
    ou = {f"{o.capitalize()}OUIdentifier": {"Certificate": "cacerts/ca.pem", "OrganizationalUnitIdentifier": o} for o in ("client", "peer", "admin", "orderer")}
    docs.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta("committer-msp-config"),
                 "data": {"config.yaml": yaml.safe_dump({"NodeOUs": {"Enable": True, **ou}}, sort_keys=False)}})

    # S12: only same-namespace traffic in; out to the same namespace, DNS, and the assemblers (hostAliases of the sidecar resolve the arma names to these addresses).
    # The four assemblers, not only the own one: BFT delivery runs header-only streams to the other parties' orderers (upstream utils/deliverorderer/config.go:55-60).
    docs.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta("committer-traffic"),
                 "spec": {"podSelector": {"matchLabels": {"rd-fabricx/committer": "true"}}, "policyTypes": ["Ingress", "Egress"],
                          "ingress": [{"from": [{"podSelector": {}}]}],
                          "egress": [{"to": [{"podSelector": {}}]},
                                     {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                                      "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
                                     {"to": [{"ipBlock": {"cidr": f"{table[cluster][m]}/32"}} for m in (1, 2, 3, 4)],
                                      "ports": [{"protocol": "TCP", "port": ASSEMBLER_PORT}]}]}})

    svc_of = {"db": ("committer-db", "pg", 5432)}
    svc_of.update({s: (f"committer-{s}" if s != "query" else "committer-query-service", s, SERVICES[s][0]) for s in SERVICES})
    for name, port_name, port in (svc_of[k] for k in ("db", "verifier", "vc", "coordinator", "sidecar", "query")):
        workload = "committer-query" if name == "committer-query-service" else name
        docs.append({"apiVersion": "v1", "kind": "Service", "metadata": meta(name),
                     "spec": {"type": "ClusterIP", "selector": {"app.kubernetes.io/name": workload},
                              "ports": [{"name": port_name, "port": port, "targetPort": port_name, "protocol": "TCP"}]}})

    place = {"nodeSelector": {"topology.kubernetes.io/zone": zone}} if zone else {}
    if cluster == "cluster1":
        place["affinity"] = {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [
            {"key": "kubernetes.io/hostname", "operator": "NotIn", "values": list(arma.AVOID_NODES)}]}]}}}

    def workload(kind, name, containers, volumes, uid, claims=None, extra_spec=None):
        labels = {**base, "app.kubernetes.io/name": name}
        spec = {"replicas": 1, "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
                "template": {"metadata": {"labels": labels}, "spec": {
                    "securityContext": {"runAsNonRoot": True, "runAsUser": uid, "fsGroup": uid, "seccompProfile": {"type": "RuntimeDefault"}},
                    **copy.deepcopy(place), **(extra_spec or {}), "containers": containers, "volumes": volumes}}}
        if kind == "StatefulSet":
            spec["serviceName"] = name
            spec["volumeClaimTemplates"] = [{"metadata": {"name": c, "labels": dict(base)}, "spec": {
                "accessModes": ["ReadWriteOnce"], "storageClassName": storage_class, "resources": {"requests": {"storage": size}}}} for c, size in claims]
        else:
            spec["strategy"] = {"type": "Recreate"}
        return {"apiVersion": "apps/v1", "kind": kind, "metadata": meta(name), "spec": spec}

    sec = lambda: {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}
    tls_keys = ("server.crt", "server.key", "ca.crt")

    def committer(svc, env=(), extra_vols=(), extra_mounts=(), claims=None):
        port, mon = SERVICES[svc]
        name = f"committer-{svc}"
        vols = [{"name": "config", "configMap": {"name": f"committer-config-{svc}", "items": [item(f"{svc}.yaml")]}},
                secret_vol("tls", "committer-tls", tls_keys), *extra_vols]
        mounts = [mount("config", f"/config/{svc}.yaml", f"{svc}.yaml")] + [mount("tls", f"/config/tls/{k}", k) for k in tls_keys] + list(extra_mounts)
        c = {"name": name, "image": image, "args": ["start", svc, f"--config=/config/{svc}.yaml"],
             "ports": [{"name": svc, "containerPort": port}, {"name": "mon", "containerPort": mon}],
             "securityContext": sec(), "resources": copy.deepcopy(RES_COMMITTER), "volumeMounts": mounts}
        if env:
            c["env"] = list(env)
        return name, c, vols

    db_vols = [secret_vol("db-tls", "committer-db-tls", ("ca.crt",))]
    db_mounts = [mount("db-tls", "/config/db-tls/ca.crt", "ca.crt")]

    # Postgres: server certificate and key from Secret committer-db-tls, ssl=on (the client side is DB_TLS above)
    db = {"name": "committer-db", "image": pg_image, "args": ["postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/tls/server.crt", "-c", "ssl_key_file=/tls/server.key"],
          "env": [{"name": "POSTGRES_USER", "value": "committer"}, {"name": "POSTGRES_DB", "value": "committer"},
                  {"name": "POSTGRES_PASSWORD", "valueFrom": secret_ref("committer-db-credentials", "password")},
                  {"name": "PGDATA", "value": "/var/lib/postgresql/data/pgdata"}],
          "ports": [{"name": "pg", "containerPort": 5432}], "securityContext": sec(), "resources": copy.deepcopy(RES_DB),
          "volumeMounts": [mount("tls", "/tls/server.crt", "server.crt"), mount("tls", "/tls/server.key", "server.key"),
                           {"name": "data", "mountPath": "/var/lib/postgresql/data"}]}
    docs.append(workload("StatefulSet", "committer-db", [db], [secret_vol("tls", "committer-db-tls", ("server.crt", "server.key"))], PG_UID, claims=[("data", "5Gi")]))

    for svc in ("verifier", "vc", "coordinator"):
        env = [{"name": "SC_VC_DATABASE_PASSWORD", "valueFrom": secret_ref("committer-db-credentials", "password")}] if svc == "vc" else []
        name, c, vols = committer(svc, env, db_vols if svc == "vc" else (), db_mounts if svc == "vc" else ())
        docs.append(workload("Deployment", name, [c], vols, UID))

    # sidecar: the config block (= genesis) names the orderers; the arma names resolve through hostAliases (same table as the arma pods)
    msp_keys = {"keystore-priv_sk": "/config/msp/keystore/priv_sk", "signcert.pem": "/config/msp/signcerts/cert.pem", "cacert.pem": "/config/msp/cacerts/ca.pem"}
    aliases = [{"ip": table[cluster][m], "hostnames": [arma.HOST.format(role=r, n=m) for r in arma.ROLES]} for m in (1, 2, 3, 4)]
    name, c, vols = committer(
        "sidecar", [{"name": "SC_SIDECAR_ORDERER_IDENTITY_MSP_ID", "value": msp_id}],
        [{"name": "config-block", "configMap": {"name": "genesis-block", "items": [item("genesis.block", "config-block.pb.bin")]}},
         secret_vol("msp", "committer-sidecar-msp", msp_keys),
         {"name": "msp-config", "configMap": {"name": "committer-msp-config", "items": [item("config.yaml")]}}],
        [mount("config-block", "/config/config-block.pb.bin", "config-block.pb.bin")] + [mount("msp", p, k) for k, p in msp_keys.items()]
        + [mount("msp-config", "/config/msp/config.yaml", "config.yaml"), {"name": "ledger", "mountPath": "/data"}])
    docs.append(workload("StatefulSet", name, [c], vols, UID, claims=[("ledger", "2Gi")], extra_spec={"hostAliases": aliases}))

    name, c, vols = committer("query", [{"name": "SC_QUERY_DATABASE_PASSWORD", "valueFrom": secret_ref("committer-db-credentials", "password")}], db_vols, db_mounts)
    docs.append(workload("Deployment", name, [c], vols, UID))
    return yaml.safe_dump_all(docs, sort_keys=False)


if __name__ == "__main__":
    p = argparse.ArgumentParser(usage=__doc__, allow_abbrev=False)
    p.add_argument("party")
    for o in ("zone", "storage-class", "ips"):
        p.add_argument(f"--{o}")
    p.add_argument("--image", default=COMMITTER_IMAGE)
    p.add_argument("--pg-image", default=PG_IMAGE)
    p.add_argument("--msp-id-format", default="org{n}")
    a = p.parse_args()
    sys.stdout.write(render(a.party, a.image, a.pg_image, a.zone, a.storage_class, a.ips, a.msp_id_format))
