#!/usr/bin/env python3
"""Turn the NWO-generated node configs (RDBI_GENERATE output) into configs for the live Fabric-X network.

Everything the token layer needs (FSC identities, Idemix credentials, issuer/auditor wallets, public
parameters) is taken unchanged from the generated tree. Only the ledger side is replaced:
  - fabric.default points at the sidecar / query service NodePorts of the existing network,
    channel arma, mTLS with the node's own identity from its organisation's CA (see enroll_ids.py);
  - token.tms uses namespace rd_dfabi on channel arma;
  - the fabric identity resolvers map every node name to that identity and MSP.
Env: RDBI_HOME (default ~/.fabricx-token), CLUSTER_HOST (default 172.24.11.197),
SIDECAR_PORT/QUERY_PORT (30560/30580), ROUTER_PORTS (30050,30150,30250,30350), NAMESPACE (rd_dfabi).
"""
import json, os, re, shutil, subprocess, sys, glob
import yaml

H = os.environ.get("RDBI_HOME", os.path.expanduser("~/.fabricx-token"))
GEN = os.path.join(H, "livegen")
LIVE = os.path.join(H, "live")
HOST = os.environ.get("CLUSTER_HOST", "172.24.11.197")
SIDECAR = f"{HOST}:{os.environ.get('SIDECAR_PORT', '30560')}"
QUERY = f"{HOST}:{os.environ.get('QUERY_PORT', '30580')}"
ROUTER_PORTS = os.environ.get("ROUTER_PORTS", "30050,30150,30250,30350").split(",")
ASSEMBLER_PORTS = os.environ.get("ASSEMBLER_PORTS", "30052,30152,30252,30352").split(",")  # ../multiorg/committer
DOCKER_GW = os.environ.get("DOCKER_GW", "172.17.0.1")
NS = os.environ.get("NAMESPACE", "rd_dfabi")
CHANNEL = "arma"
NODES = {"issuer": "issuer", "bank2": "bank", "bank3": "bank", "bank4": "bank",
         "endorser-1": "endorser", "endorser-2": "endorser", "endorser-3": "endorser", "endorser-4": "endorser"}
msp_of = lambda n: open(os.path.join(H, "ids", n, "mspid")).read().strip()  # written by enroll_ids.py
# Every institution reads the ledger from its own committer: BI's runs in the cluster, each bank's on this host
# (../multiorg/committer, sidecar on <prefix>130, query service on <prefix>140). BANK_COMMITTERS=0 points all
# nodes at BI's committer.
BANK_COMMITTER = {"OrdererOrg2MSP": 25, "OrdererOrg3MSP": 35, "OrdererOrg4MSP": 45}
if os.environ.get("BANK_COMMITTERS", "1") == "0":
    BANK_COMMITTER = {}


def committer_of(node):
    p = BANK_COMMITTER.get(msp_of(node))
    return (SIDECAR, QUERY) if p is None else (f"127.0.0.1:{p}130", f"127.0.0.1:{p}140")

os.umask(0o077)
os.makedirs(LIVE, exist_ok=True)


def key_of(msp_dir):
    return glob.glob(os.path.join(msp_dir, "keystore", "*"))[0]


def bccsp():
    return {"BCCSP": {"Default": "SW", "SW": {"Hash": "SHA2", "Security": 256}}}


# CA bundle: cluster Org1 CA + the four orderer-org CAs (read from the existing secrets, public certs only)
def secret(name, key):
    import base64
    d = json.loads(subprocess.check_output(["kubectl", "-n", "fabricx", "get", "secret", name, "-o", "json"]))["data"][key]
    return base64.b64decode(d).decode()

bundle = secret("committer-sidecar-secret", "tls-ca.crt")
for i in range(1, 5):
    bundle += secret(f"orderer-router-{i}-secret", "tls-ca.crt")
bundle_path = os.path.join(LIVE, "ca-bundle.pem")
open(bundle_path, "w").write(bundle)

tls_of = lambda n: {
    "enabled": True, "clientAuthEnabled": True,
    "clientCert": {"file": os.path.join(H, "ids", n, "tls", "signcerts", "cert.pem")},
    "clientKey": {"file": key_of(os.path.join(H, "ids", n, "tls"))},
    "rootCAs": {"files": [bundle_path]},
}

for node, role in NODES.items():
    src = os.path.join(GEN, "fsc", "nodes", f"{node}.0")
    cfg = yaml.safe_load(open(os.path.join(src, "core.yaml")))
    out = os.path.join(LIVE, node)
    os.makedirs(os.path.join(out, "data"), exist_ok=True)  # keep node data (vault, token openings) across re-assembly

    # --- FSC side: local-only gRPC, data and traces under the live dir
    f = cfg["fsc"]
    f["grpc"]["address"] = re.sub(r"^0\.0\.0\.0", "127.0.0.1", f["grpc"]["address"])
    f["persistences"]["default"]["opts"]["dataSource"] = os.path.join(out, "data", "default.sqlite")
    f.get("tracing", {}).get("file", {}).update({"path": os.path.join(out, "trace.out")})

    # --- ledger side: the existing Fabric-X network
    d = cfg["fabric"]["default"]
    chan = d["channels"][0]
    chan["name"] = CHANNEL
    # Panurus asks for the identity labelled "idemix" as the anonymous creator of ledger transactions, and the
    # endorser checks that creator against the MSPs of the channel. This channel has no IdemixOrgMSP, so the
    # label is mapped to ONE shared Org1MSP identity (ids/anon) that every node uses. The ledger then shows the
    # same creator for every transaction, so the submitting bank/BI node stays indistinguishable.
    # (With an IdemixOrgMSP in the channel config the generated idemix MSP could be kept instead.)
    anon = [m for m in d["msps"] if m["mspType"] == "idemix"]
    assert len(anon) <= 1, "expected at most one idemix MSP in the generated config"
    d["msps"] = [{"cacheSize": 0, "id": node, "mspID": msp_of(node), "mspType": "bccsp", "opts": bccsp(),
                  "path": os.path.join(H, "ids", node, "msp")}]
    if anon:
        d["msps"].insert(0, {"cacheSize": 0, "id": "idemix", "mspID": "Org1MSP", "mspType": "bccsp", "opts": bccsp(),
                             "path": os.path.join(H, "ids", "anon", "msp")})
    d["defaultMSP"] = node
    sidecar, query = committer_of(node)
    d["peers"] = [{"address": sidecar, "connectionTimeout": "10s"}]
    d["notificationService"] = {"endpoints": [{"address": sidecar, "connectionTimeout": "5s", "tls": tls_of(node)}], "requestTimeout": "10s"}
    d["queryService"] = {"endpoints": [{"address": query, "connectionTimeout": "5s", "tls": tls_of(node)}], "requestTimeout": "10s"}
    d["tls"] = tls_of(node)
    for r in d.get("endpoint", {}).get("resolvers", []):
        n = r["name"]
        if n in NODES:
            r["identity"] = {"mspID": msp_of(n), "path": os.path.join(H, "ids", n, "msp")}

    # --- token side: namespace rd_dfabi on channel arma
    tms = cfg["token"]["tms"]
    (old_key, t), = tms.items()
    t["channel"], t["namespace"], t["network"] = CHANNEL, NS, "default"
    cfg["token"]["tms"] = {f"default-{CHANNEL}-{NS}": t}

    yaml.safe_dump(cfg, open(os.path.join(out, "core.yaml"), "w"), sort_keys=False, width=200)
    shutil.copy(os.path.join(src, "client-config.yaml"), os.path.join(out, "client-config.yaml"))
    open(os.path.join(out, "role"), "w").write(role)
    if role in ("issuer", "bank") and not os.path.exists(os.path.join(out, "policy.env")):
        # Holding limit per enrollment id and token type that a node enforces on what it receives (accept.go).
        # Upstream's demo value is 3000, which blocks any realistic RD amount, so the default is "effectively
        # unlimited". Edit a node's policy.env and restart it to change.
        open(os.path.join(out, "policy.env"), "w").write(
            "RDBI_PAYMENT_LIMIT=1000000000000\nRDBI_CUMULATIVE_LIMIT=1000000000000\nRDBI_HOLDING_LIMIT=1000000000000\n")

# --- network shim files (see cmd/node/netshim.go)
hosts = {f"orderer-router-{i}.fabricx.svc.cluster.local": "127.0.0.1" for i in range(1, 5)}
forwards = [{"listen": f"127.0.0.1:{7050 + 100 * (i - 1)}", "target": f"{HOST}:{p}"} for i, p in enumerate(ROUTER_PORTS, 1)]
# the banks' committers (docker) reach the assemblers through the docker bridge gateway (compose extra_hosts)
forwards += [{"listen": f"{DOCKER_GW}:{7052 + 100 * (i - 1)}", "target": f"{HOST}:{p}"} for i, p in enumerate(ASSEMBLER_PORTS, 1)]
json.dump({"hosts": hosts}, open(os.path.join(LIVE, "netshim-dns.json"), "w"), indent=1)
json.dump({"forwards": forwards}, open(os.path.join(LIVE, "netshim-forward.json"), "w"), indent=1)

# --- public parameters, as produced by tokengen inside the generated tree
pp = glob.glob(os.path.join(GEN, "token", "crypto", "pp", "*"))
assert len(pp) == 1, pp
shutil.copy(pp[0], os.path.join(LIVE, "public-params.bin"))
print("assembled", sorted(NODES), "namespace", NS, "channel", CHANNEL, "pp", os.path.getsize(pp[0]), "bytes")
