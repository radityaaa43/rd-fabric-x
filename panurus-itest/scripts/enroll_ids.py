#!/usr/bin/env python3
"""Register and enroll one ledger identity per token node at the CA of the node's organisation.

BI's nodes (issuer, endorser-1, anon) belong to Org1MSP (CA fca-org1). Bank A/B/C are the organisations of
orderer parties 2..4 (OrdererOrg2..4MSP, CAs fca-orderer-org2..4): bank2/endorser-2, bank3/endorser-3,
bank4/endorser-4. Reads each registrar password from the in-cluster ConfigMap (never printed or stored),
writes keys under $RDBI_HOME/ids/<node>/{msp,tls,secret} (mode 0700/0600). Re-runnable: existing ids are kept.
Env: KUBECONFIG, RDBI_HOME (default ~/.fabricx-token), CLUSTER_HOST (default 172.24.11.197),
FABRIC_CA_CLIENT (path to the binary).
"""
import base64, json, os, re, secrets, subprocess, sys

H = os.environ.get("RDBI_HOME", os.path.expanduser("~/.fabricx-token"))
HOST = os.environ.get("CLUSTER_HOST", "172.24.11.197")
BIN = os.environ["FABRIC_CA_CLIENT"]
# organisation -> (CA name in the cluster, CA NodePort, nodes)
ORGS = {
    "Org1MSP": ("fca-org1", 30969, ["issuer", "endorser-1", "anon"]),  # anon: shared creator identity
    "OrdererOrg2MSP": ("fca-orderer-org2", 30929, ["bank2", "endorser-2", "committer-bank2"]),
    "OrdererOrg3MSP": ("fca-orderer-org3", 30939, ["bank3", "endorser-3", "committer-bank3"]),
    "OrdererOrg4MSP": ("fca-orderer-org4", 30949, ["bank4", "endorser-4", "committer-bank4"]),
}
# committer-<bank>: the bank's own committer (../multiorg/committer); one TLS certificate for all its components
COMMITTER_HOSTS = "localhost,127.0.0.1,sidecar,coordinator,vc,verifier,query"
ONLY = set(sys.argv[1:])
umask = os.umask(0o077)


def kubectl_json(kind, name):
    return json.loads(subprocess.check_output(["kubectl", "-n", "fabricx", "get", kind, name, "-o", "json"]))


for msp_id, (ca, port, nodes) in ORGS.items():
    nodes = [n for n in nodes if not ONLY or n in ONLY]
    if not nodes:
        continue
    cm = kubectl_json("cm", ca)["data"]["fabric-ca-server-config.yaml"]
    admin_pw = re.search(r'name:\s*"admin"\s*\n\s*pass:\s*"?([^"\n]+)"?', cm).group(1)
    cert = os.path.join(H, f"{ca}-ca.pem")  # the CA's root certificate also signs its TLS certificate
    if not os.path.exists(cert):
        with open(cert, "wb") as f:
            f.write(base64.b64decode(kubectl_json("secret", ca)["data"]["ca-certificate"]))
    addr = f"{HOST}:{port}"

    def run(args, home, mask=()):
        p = subprocess.run([BIN] + args, env=dict(os.environ, FABRIC_CA_CLIENT_HOME=home), capture_output=True, text=True)
        out = p.stdout + p.stderr
        for m in (admin_pw,) + tuple(mask):
            out = out.replace(m, "***")
        return p.returncode, out

    admin_home = os.path.join(H, "admin" if ca == "fca-org1" else f"admin-{ca}")
    if not os.path.exists(os.path.join(admin_home, "msp", "signcerts", "cert.pem")):
        rc, out = run(["enroll", "-u", f"https://admin:{admin_pw}@{addr}", "--tls.certfiles", cert, "-M", admin_home + "/msp"], admin_home)
        assert rc == 0, out

    for n in nodes:
        d = os.path.join(H, "ids", n)
        os.makedirs(d, exist_ok=True)
        spath = os.path.join(d, "secret")
        name = f"tok-{n}"
        if not os.path.exists(spath):
            pw = secrets.token_urlsafe(18)
            rc, out = run(["register", "-u", f"https://{addr}", "--tls.certfiles", cert, "--id.name", name, "--id.secret", pw,
                           "--id.type", "client", "--id.maxenrollments", "10", "-M", admin_home + "/msp"], admin_home, (pw,))
            if rc != 0 and "already registered" not in out:
                sys.exit(f"register {name} at {ca} failed: {out[-300:]}")
            with open(spath, "w") as f:
                f.write(pw)
            os.chmod(spath, 0o600)
        pw = open(spath).read().strip()
        url = f"https://{name}:{pw}@{addr}"
        hosts = COMMITTER_HOSTS if n.startswith("committer-") else "localhost,127.0.0.1"
        for kind, extra in (("msp", []), ("tls", ["--enrollment.profile", "tls", "--csr.hosts", hosts])):
            if os.path.exists(os.path.join(d, kind, "signcerts", "cert.pem")):
                continue
            rc, out = run(["enroll", "-u", url, "--tls.certfiles", cert, "-M", os.path.join(d, kind)] + extra, d, (pw,))
            assert rc == 0, f"enroll {name} {kind} at {ca}: {out[-300:]}"
        with open(os.path.join(d, "mspid"), "w") as f:
            f.write(msp_id)
        print(f"ok {name} {msp_id}")
os.umask(umask)
