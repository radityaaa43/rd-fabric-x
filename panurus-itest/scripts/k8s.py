#!/usr/bin/env python3
"""Run the token nodes and the banks' committers in the cluster (namespace fabricx), one pod per institution.

  rdbi-bi     issuer, endorser-1                       reads BI's committer (committer-sidecar, -query-service)
  rdbi-bank2  bank2, endorser-2 and Bank A's committer  (sidecar, coordinator, vc, verifier, query, Postgres)
  rdbi-bank3  bank3, endorser-3 and Bank B's committer;  rdbi-bank4  bank4, endorser-4 and Bank C's committer
  rdbi-driver rdbi-driver for tests (kubectl exec); holds the view-client keys of every node
Every node gets a Service named after it (issuer, bank2, endorser-1, ...), the name its TLS certificate carries.

Each institution pod has one PVC (alicloud-essd-wffc, 2Gi) for its node stores, sidecar ledger and Postgres
(subPaths). Configs come from this host's live configs (make live-assemble): paths under $RDBI_HOME become
$HOME/.fabricx-token in the container, loopback addresses become the pods' Services, and the files they reference
are packed into one Secret per pod (sent to kubectl on stdin, never written to disk), unpacked by an init container.

usage: k8s.py apply [replicas]   Secrets, PVCs, Services, Deployments (replicas default 1)
       k8s.py seed               copy this host's node stores into the PVCs (Deployments at 0, local nodes stopped)
Env: IMAGE (rdbi image), RDBI_HOME (default ~/.fabricx-token), KUBECONFIG.
"""
import base64, glob, io, json, os, re, secrets, subprocess, sys, tarfile
import yaml

H = os.environ.get("RDBI_HOME", os.path.expanduser("~/.fabricx-token"))
T = "/home/rdbi/.fabricx-token"
NS = "fabricx"
IMAGE = os.environ["IMAGE"]
COMMITTER_IMAGE = "docker.io/hyperledger/fabric-x-committer:1.0.4"
PG_IMAGE = "docker.io/library/postgres:17.10"
COMMITTER_CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "multiorg", "committer", "config")
PODS = {"rdbi-bi": ["issuer", "endorser-1"], "rdbi-bank2": ["bank2", "endorser-2"],
        "rdbi-bank3": ["bank3", "endorser-3"], "rdbi-bank4": ["bank4", "endorser-4"]}
POD_OF = {n: p for p, nodes in PODS.items() for n in nodes}
BANK = {"rdbi-bank2": ("bank2", "OrdererOrg2MSP", "fca-orderer-org2"),
        "rdbi-bank3": ("bank3", "OrdererOrg3MSP", "fca-orderer-org3"),
        "rdbi-bank4": ("bank4", "OrdererOrg4MSP", "fca-orderer-org4")}
BI_COMMITTER = ("committer-sidecar.fabricx.svc.cluster.local:5130", "committer-query-service.fabricx.svc.cluster.local:5140")
OWN_COMMITTER = ("localhost:6130", "localhost:6140")
LABELS = {"app.kubernetes.io/part-of": "rdbi"}
# the member nodes (free disk and pod slots) are in zone 5b; a disk binds to the zone of its first pod
ZONE = {"topology.kubernetes.io/zone": "ap-southeast-5b"}


def kubectl(*args, stdin=None):
    return subprocess.run(["kubectl", "-n", NS, *args], input=stdin, check=True, capture_output=True).stdout


def rewrite(o, files):
    """Host paths under $RDBI_HOME -> container paths; remembers the host paths in files."""
    if isinstance(o, dict):
        return {k: rewrite(v, files) for k, v in o.items()}
    if isinstance(o, list):
        return [rewrite(v, files) for v in o]
    if isinstance(o, str) and o.startswith(H + "/"):
        files.add(o)
        return T + o[len(H):]
    return o


def port(addr):
    return int(addr.rsplit(":", 1)[-1].rsplit("/", 1)[-1])


def node_config(n, files):
    core = yaml.safe_load(open(f"{H}/live/{n}/core.yaml"))
    f = core["fsc"]
    f["grpc"]["address"] = f"0.0.0.0:{port(f['grpc']['address'])}"  # the driver pod calls the view service
    # one Service per node, named after it: the node TLS certificates carry the node name, not the pod name
    for r in f["endpoint"]["resolvers"]:
        if r["name"] in POD_OF and (r.get("addresses") or {}).get("P2P"):
            r["addresses"]["P2P"] = f"{r['name']}:{port(r['addresses']['P2P'])}"
    d = core["fabric"]["default"]
    sidecar, query = BI_COMMITTER if POD_OF[n] == "rdbi-bi" else OWN_COMMITTER
    d["peers"][0]["address"] = d["notificationService"]["endpoints"][0]["address"] = sidecar
    d["queryService"]["endpoints"][0]["address"] = query
    ports = {"grpc": port(f["grpc"]["address"]), "p2p": port(f["p2p"]["listenAddress"]), "web": port(f["web"]["address"])}
    return rewrite(core, files), ports, query


def pack(files, extra):
    """tar.gz of the host files (relative to $RDBI_HOME) plus generated files; node stores are left out."""
    buf, seen = io.BytesIO(), set()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        def add(p):
            arc = os.path.relpath(p, H)
            if arc in seen or (arc.startswith("live/") and "/data" in arc):
                return
            seen.add(arc)
            t.add(p, arcname=arc, recursive=False)
        for p in sorted(files):
            if os.path.isdir(p):
                for root, _, names in os.walk(p):
                    for name in names:
                        add(os.path.join(root, name))
            elif os.path.exists(p):  # e.g. trace.out does not exist yet
                add(p)
        for arc, data in sorted(extra.items()):
            ti = tarfile.TarInfo(arc)
            ti.size, ti.mode = len(data), 0o600
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def committer_files(pod):
    bank, _, ca = BANK[pod]
    ident = f"{H}/ids/committer-{bank}"
    out = {}
    for f in glob.glob(os.path.join(COMMITTER_CFG, "*.yaml")):
        s = open(f).read()
        # one pod: the components talk over localhost (host:port only, not the YAML keys such as "verifier:")
        s = re.sub(r"\b(coordinator|verifier|vc|db):(\d+)", r"localhost:\2", s)
        # the FSC nodes in the pod use 5100..5125, so the committer moves from 51xx/52xx to 61xx/62xx
        s = re.sub(r":5([12]\d0)\b", r":6\1", s)
        out[f"committer/{os.path.basename(f)}"] = s.encode()
    out["committer/tls/server.crt"] = open(f"{ident}/tls/signcerts/cert.pem", "rb").read()
    out["committer/tls/server.key"] = open(glob.glob(f"{ident}/tls/keystore/*")[0], "rb").read()
    out["committer/tls/ca.crt"] = open(f"{H}/{ca}-ca.pem", "rb").read()
    out["committer/config-block.pb.bin"] = open(f"{H}/multiorg/genesis-multiorg.block", "rb").read()
    for root, _, names in os.walk(f"{ident}/msp"):
        for name in names:
            p = os.path.join(root, name)
            out["committer/msp/" + os.path.relpath(p, f"{ident}/msp")] = open(p, "rb").read()
    # the local MSP classifies identities by OU like the channel MSPs; fabric-ca-client writes no config.yaml
    cacert = "cacerts/" + sorted(os.listdir(f"{ident}/msp/cacerts"))[0]
    out["committer/msp/config.yaml"] = yaml.safe_dump({"NodeOUs": {"Enable": True, **{
        f"{ou.capitalize()}OUIdentifier": {"Certificate": cacert, "OrganizationalUnitIdentifier": ou}
        for ou in ("client", "peer", "admin", "orderer")}}}).encode()
    return out


def db_password(pod):
    p = f"{H}/k8s/{pod}.db-password"  # Postgres keeps the password of its first start
    if not os.path.exists(p):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(os.open(p, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write(secrets.token_hex(24))
    return open(p).read().strip()


def env_file(p):
    return [{"name": k, "value": v} for k, v in (l.strip().split("=", 1) for l in open(p) if "=" in l)] if os.path.exists(p) else []


def resources(mem="64Mi", limit="512Mi"):
    return {"requests": {"cpu": "20m", "memory": mem}, "limits": {"memory": limit}}


def secret(name, data):
    return {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": NS, "labels": LABELS},
            "type": "Opaque", "data": {k: base64.b64encode(v).decode() for k, v in data.items()}}


def deployment(pod, replicas, init, containers, volumes):
    labels = {**LABELS, "app.kubernetes.io/name": pod}
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": pod, "namespace": NS, "labels": labels},
            "spec": {"replicas": replicas, "strategy": {"type": "Recreate"},
                     "selector": {"matchLabels": {"app.kubernetes.io/name": pod}},
                     "template": {"metadata": {"labels": labels}, "spec": {
                         "imagePullSecrets": [{"name": "ghcr-pull"}], "nodeSelector": ZONE,
                         "initContainers": [{"name": "unpack", "image": IMAGE, "securityContext": {"runAsUser": 0},
                                             "command": ["sh", "-c", init], "resources": resources("16Mi", "128Mi"),
                                             "volumeMounts": [{"name": "files", "mountPath": "/secret"},
                                                              {"name": "rdbi", "mountPath": "/rdbi"}] +
                                             ([{"name": "state", "mountPath": "/state"}] if any(v["name"] == "state" for v in volumes) else [])}],
                         "containers": containers, "volumes": volumes}}}}


def institution(pod, replicas):
    docs, files, extra = [], set(), {}
    containers, init = [], "set -e; tar xzf /secret/rdbi.tgz -C /rdbi; chown -R 10001:10001 /rdbi"
    for n in PODS[pod]:
        core, p, query = node_config(n, files)
        extra[f"live/{n}/core.yaml"] = yaml.safe_dump(core, sort_keys=False, width=200).encode()
        docs.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": n, "namespace": NS, "labels": LABELS},
                     "spec": {"selector": {"app.kubernetes.io/name": pod},
                              "ports": [{"name": k, "port": v, "targetPort": v} for k, v in p.items()]}})
        init += f"; mkdir -p /state/{n}; chown -R 10001:10001 /state/{n}"
        wait = "; ".join(f"until (: >/dev/tcp/{h}/{p}) 2>/dev/null; do sleep 2; done"
                         for h, p in (a.rsplit(":", 1) for a in (core["fabric"]["default"]["peers"][0]["address"], query)))
        containers.append({
            "name": n, "image": IMAGE, "securityContext": {"runAsUser": 10001},
            # a node exits if its sidecar or query service is down at start: wait for the committer first
            "command": ["bash", "-c", f"{wait}; exec rdbi-node node start"],
            "env": [{"name": "FSCNODE_CFG_PATH", "value": f"{T}/live/{n}"},
                    {"name": "RDBI_ROLE", "value": open(f"{H}/live/{n}/role").read().strip()}] + env_file(f"{H}/live/{n}/policy.env"),
            "volumeMounts": [{"name": "rdbi", "mountPath": T},
                             {"name": "state", "mountPath": f"{T}/live/{n}/data", "subPath": n}],
            "resources": resources()})
    data = {}
    if pod in BANK:
        extra.update(committer_files(pod))
        data["db-password"] = db_password(pod).encode()
        init += "; mkdir -p /state/ledger /state/pgdata; chown 10001:10001 /state/ledger; chown 999:999 /state/pgdata; chmod 700 /state/pgdata"
        pw = lambda var: {"name": var, "valueFrom": {"secretKeyRef": {"name": f"{pod}-files", "key": "db-password"}}}
        cfg = {"name": "rdbi", "mountPath": "/config", "subPath": "committer"}
        for svc in ("verifier", "vc", "coordinator", "sidecar", "query"):
            env = {"vc": [pw("SC_VC_DATABASE_PASSWORD")], "query": [pw("SC_QUERY_DATABASE_PASSWORD")],
                   "sidecar": [{"name": "SC_SIDECAR_ORDERER_IDENTITY_MSP_ID", "value": BANK[pod][1]}]}.get(svc, [])
            mounts = [cfg] + ([{"name": "state", "mountPath": "/data/ledger", "subPath": "ledger"}] if svc == "sidecar" else [])
            containers.append({"name": f"committer-{svc}", "image": COMMITTER_IMAGE, "securityContext": {"runAsUser": 10001},
                               "args": ["start", svc, f"--config=/config/{svc}.yaml"], "env": env,
                               "volumeMounts": mounts, "resources": resources("32Mi", "256Mi")})
        containers.append({"name": "db", "image": PG_IMAGE,
                           "env": [{"name": "POSTGRES_USER", "value": "committer"}, {"name": "POSTGRES_DB", "value": "committer"},
                                   pw("POSTGRES_PASSWORD")],
                           "volumeMounts": [{"name": "state", "mountPath": "/var/lib/postgresql/data", "subPath": "pgdata"}],
                           "resources": resources()})
    data["rdbi.tgz"] = pack(files, extra)
    assert len(data["rdbi.tgz"]) < 900_000, f"{pod}: secret too large ({len(data['rdbi.tgz'])} bytes)"
    docs.append(secret(f"{pod}-files", data))
    docs.append({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": f"{pod}-state", "namespace": NS, "labels": LABELS},
                 "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "alicloud-essd-wffc", "resources": {"requests": {"storage": "2Gi"}}}})
    volumes = [{"name": "files", "secret": {"secretName": f"{pod}-files", "defaultMode": 0o400}},
               {"name": "rdbi", "emptyDir": {}},
               {"name": "state", "persistentVolumeClaim": {"claimName": f"{pod}-state"}}]
    docs.append(deployment(pod, replicas, init, containers, volumes))
    return docs


def driver(replicas):
    files, extra = set(), {}
    for n in POD_OF:
        cc = yaml.safe_load(open(f"{H}/live/{n}/client-config.yaml"))
        cc["address"] = f"{n}:{port(cc['address'])}"
        extra[f"live/{n}/client-config.yaml"] = yaml.safe_dump(rewrite(cc, files), sort_keys=False).encode()
    core = yaml.safe_load(open(f"{H}/live/issuer/core.yaml"))  # the driver reads the issuer wallet from it
    for t in core["token"]["tms"].values():
        for w in t["wallets"]["issuers"]:
            files.add(w["path"])
    extra["live/issuer/core.yaml"] = yaml.safe_dump(rewrite(core, set()), sort_keys=False, width=200).encode()
    files.add(f"{H}/live/public-params.bin")
    data = {"rdbi.tgz": pack(files, extra)}
    container = {"name": "driver", "image": IMAGE, "command": ["sleep", "infinity"], "securityContext": {"runAsUser": 10001},
                 "volumeMounts": [{"name": "rdbi", "mountPath": T}], "resources": resources("16Mi")}
    volumes = [{"name": "files", "secret": {"secretName": "rdbi-driver-files", "defaultMode": 0o400}}, {"name": "rdbi", "emptyDir": {}}]
    return [secret("rdbi-driver-files", data),
            deployment("rdbi-driver", replicas, "set -e; tar xzf /secret/rdbi.tgz -C /rdbi; chown -R 10001:10001 /rdbi", [container], volumes)]


def apply(replicas):
    try:
        kubectl("get", "secret", "ghcr-pull")
    except subprocess.CalledProcessError:  # the image pull secret lives in namespace dfabi
        s = json.loads(subprocess.check_output(["kubectl", "-n", "dfabi", "get", "secret", "ghcr-pull", "-o", "json"]))
        s["metadata"] = {"name": "ghcr-pull", "namespace": NS}
        kubectl("apply", "-f", "-", stdin=json.dumps(s).encode())
    docs = [d for pod in PODS for d in institution(pod, replicas)] + driver(replicas)
    print(kubectl("apply", "-f", "-", stdin=yaml.safe_dump_all(docs).encode()).decode(), end="")


def seed():
    for pod, nodes in PODS.items():
        if kubectl("get", "deploy", pod, "-o", "jsonpath={.spec.replicas}").decode() != "0":
            sys.exit(f"{pod} must be scaled to 0 before seeding")
        name = f"seed-{pod}"
        kubectl("apply", "-f", "-", stdin=json.dumps({
            "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": NS, "labels": LABELS},
            "spec": {"imagePullSecrets": [{"name": "ghcr-pull"}], "restartPolicy": "Never", "nodeSelector": ZONE,
                     "containers": [{"name": "seed", "image": IMAGE, "securityContext": {"runAsUser": 0},
                                     "command": ["sleep", "3600"], "volumeMounts": [{"name": "state", "mountPath": "/state"}]}],
                     "volumes": [{"name": "state", "persistentVolumeClaim": {"claimName": f"{pod}-state"}}]}}).encode())
        kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=600s")
        for n in nodes:
            src = f"{H}/live/{n}/data"
            tgz = subprocess.check_output(["tar", "czf", "-", "-C", src, "."])
            kubectl("exec", "-i", name, "--", "sh", "-c",
                    f"rm -rf /state/{n} && mkdir -p /state/{n} && tar xzf - -C /state/{n} && chown -R 10001:10001 /state/{n}", stdin=tgz)
            got = kubectl("exec", name, "--", "sh", "-c", f"cd /state/{n} && find . -type f | sort | xargs md5sum").decode()
            want = subprocess.check_output(["sh", "-c", "find . -type f | sort | xargs md5sum"], cwd=src).decode()
            assert got == want, f"{n}: copy differs"
            print(f"seeded {pod}/{n}: {len(got.splitlines())} files, checksums match")
        kubectl("delete", "pod", name, "--wait=true")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "apply":
        apply(int(sys.argv[2]) if len(sys.argv) > 2 else 1)
    elif cmd == "seed":
        seed()
    else:
        sys.exit(__doc__)
