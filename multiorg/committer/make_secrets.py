#!/usr/bin/env python3
"""Make the four Secret sets of one org's committer (fabricx S12 custody). Keys exist only in /dev/shm and in the Secrets.

usage: make_secrets.py <party> rd-fabricx-<party> --kubeconfig K --ca-url http://localhost:7054 --work W --exchange <dir with org1..org4> [--generation TAG]
One org at a time per port; W under /dev/shm only, holding admin.pass of the org's CA (made by `enroll.py init`); needs the same port-forward to svc/fca-org<N>.
Secrets (created with `kubectl create`, never applied; names and keys are what multiorg/committer/render.py references):
  committer-tls          server.crt server.key ca.crt   cert from the org's OWN TLS CA (client identity committer-<N>[-TAG]) with the SANs of the five committer
                         Services (short and .<ns>.svc.cluster.local); ca.crt = the TLS CAs of all four orgs (the orderers trust the genesis TLS CAs)
  committer-sidecar-msp  keystore-priv_sk signcert.pem cacert.pem   the same identity's MSP enrollment at the org CA
  committer-db-tls       server.crt server.key ca.crt   a THROWAWAY CA made here signs the Postgres server cert (SAN committer-db); its key is never stored
  committer-db-credentials  password                    random, used by Postgres, vc and query
Credentials travel only in the environment/stdin (as enroll.py). Every certificate is checked (chain to its CA, SANs) BEFORE the first Secret is created.
"""
import os, subprocess, sys, tempfile
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "fca"))
import enroll

SVCS = ("committer-verifier", "committer-vc", "committer-coordinator", "committer-sidecar", "committer-query-service")


def pem_bundle(exchange):
    out = ""
    for n in (1, 2, 3, 4):
        found = sorted(__import__("glob").glob(f"{exchange}/org{n}/msp/tlscacerts/*.pem"))
        if not found:
            sys.exit(f"make_secrets.py: {exchange}/org{n}/msp/tlscacerts/*.pem is missing: the exchange tree needs the TLS CA of all four orgs")
        for p in found:
            t = enroll.read(p)
            out += t if t.endswith("\n") else t + "\n"
    return out


def verify_chain(cert, ca, names):
    """cert must chain to ca and carry every DNS name in `names` as a SAN; else exit."""
    d = tempfile.mkdtemp(dir="/dev/shm")
    try:
        for name, text in (("cert.pem", cert), ("ca.pem", ca)):
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        v = subprocess.run(["openssl", "verify", "-CAfile", f"{d}/ca.pem", f"{d}/cert.pem"], capture_output=True, text=True)
        if v.returncode:
            sys.exit(f"make_secrets.py: certificate does not chain to its CA: {(v.stdout + v.stderr).strip()[-200:]}")
        san = subprocess.run(["openssl", "x509", "-in", f"{d}/cert.pem", "-noout", "-ext", "subjectAltName"], capture_output=True, text=True).stdout
        missing = [x for x in names if f"DNS:{x}" not in san]
        if missing:
            sys.exit(f"make_secrets.py: certificate lacks the SANs {', '.join(missing)}")
    finally:
        enroll.destroy(d)


def db_material(work, ns):
    """throwaway CA -> Postgres server cert; returns (server.crt, server.key, ca.crt). The CA key is destroyed with `work`."""
    d = f"{work}/db"
    os.makedirs(d, mode=0o700)
    names = ["committer-db", f"committer-db.{ns}.svc.cluster.local"]
    ex = f"{d}/ext.cnf"
    with open(ex, "w") as f:
        f.write("keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=" + ",".join(f"DNS:{x}" for x in names) + "\n")
    run = lambda *a: enroll.sh(*a)
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{d}/ca.key", "-subj", f"/CN=committer-db-ca-{ns}",
        "-days", "3650", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", f"{d}/ca.pem")
    run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", f"{d}/server.key")
    run("openssl", "req", "-new", "-key", f"{d}/server.key", "-subj", "/CN=committer-db", "-out", f"{d}/server.csr")
    run("openssl", "x509", "-req", "-in", f"{d}/server.csr", "-CA", f"{d}/ca.pem", "-CAkey", f"{d}/ca.key", "-CAcreateserial", "-days", "3650", "-extfile", ex, "-out", f"{d}/server.pem")
    return enroll.read(f"{d}/server.pem"), enroll.read(f"{d}/server.key"), enroll.read(f"{d}/ca.pem"), names


def secret(name, ns, data):
    return {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": {"name": name, "namespace": ns}, "stringData": data}


def make(party, ns, kubeconfig, ca_url, work, exchange, generation=""):
    work = enroll.check_work(work)   # path guard first: destroy() below only ever touches a /dev/shm path
    secrets = []
    try:
        n = enroll.check_target(party, ns)
        gen = enroll.check_generation(generation) if generation else ""
        bundle = pem_bundle(exchange)   # before any CA call
        pw = enroll.read(f"{work}/admin.pass").strip()
        secrets.append(pw)
        base_env = {**os.environ, "FABRIC_CA_CLIENT_HOME": f"{work}/client"}
        creds = lambda who, secret_: {**base_env, "FABRIC_CA_CLIENT_URL": ca_url.replace("://", f"://{who}:{secret_}@")}
        adminmsp = f"{work}/admin-msp"
        enroll.sh("fabric-ca-client", "enroll", "-M", adminmsp, env=creds("admin", pw), secrets=secrets)
        who = f"committer-{n}" + (f"-{gen}" if gen else "")
        reg = enroll.sh("fabric-ca-client", "register", "-u", ca_url, "-M", adminmsp, "--id.name", who, "--id.type", "client", env=base_env, secrets=secrets)
        m = __import__("re").search(r"Password:\s*(\S+)", reg)
        if not m:
            sys.exit(f"make_secrets.py: register of {who} printed no generated password")
        secrets.append(m.group(1))
        hosts = [h for s in SVCS for h in (s, f"{s}.{ns}.svc.cluster.local")]
        enroll.sh("fabric-ca-client", "enroll", "-M", f"{work}/ident/msp", env=creds(who, m.group(1)), secrets=secrets)
        enroll.sh("fabric-ca-client", "enroll", "-M", f"{work}/ident/tls", "--enrollment.profile", "tls", "--csr.hosts", ",".join(hosts), env=creds(who, m.group(1)), secrets=secrets)
        tls_crt, tls_key = enroll.read(enroll.first(f"{work}/ident/tls/signcerts/*.pem")), enroll.read(enroll.first(f"{work}/ident/tls/keystore/*_sk"))
        tlsca = enroll.read(enroll.first(f"{work}/ident/tls/tlscacerts/*.pem"))
        msp_crt, msp_key = enroll.read(enroll.first(f"{work}/ident/msp/signcerts/*.pem")), enroll.read(enroll.first(f"{work}/ident/msp/keystore/*_sk"))
        msp_ca = enroll.read(enroll.first(f"{work}/ident/msp/cacerts/*.pem"))
        db_crt, db_key, db_ca, db_names = db_material(work, ns)
        db_pw = os.urandom(18).hex()
        secrets.append(db_pw)
        verify_chain(tls_crt, tlsca, hosts)
        verify_chain(db_crt, db_ca, db_names)
        for s in (secret("committer-tls", ns, {"server.crt": tls_crt, "server.key": tls_key, "ca.crt": bundle}),
                  secret("committer-sidecar-msp", ns, {"keystore-priv_sk": msp_key, "signcert.pem": msp_crt, "cacert.pem": msp_ca}),
                  secret("committer-db-tls", ns, {"server.crt": db_crt, "server.key": db_key, "ca.crt": db_ca}),
                  secret("committer-db-credentials", ns, {"password": db_pw})):
            enroll.sh("kubectl", "--kubeconfig", kubeconfig, "create", "-f", "-", stdin=yaml.safe_dump(s), secrets=secrets)
    finally:  # keys never stay in /dev/shm, also on error
        enroll.destroy(work)


if __name__ == "__main__":
    a = sys.argv[1:]
    try:
        party, ns = a[0], a[1]
        opt = dict(zip(a[2::2], a[3::2]))
        make(party, ns, opt["--kubeconfig"], opt["--ca-url"], opt["--work"], opt["--exchange"], opt.get("--generation", ""))
    except (IndexError, KeyError):
        sys.exit(__doc__)
