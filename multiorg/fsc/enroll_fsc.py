#!/usr/bin/env python3
"""Per-org FSC identities (fabricx S13 custody): every private key of an org's FSC nodes is made at the org's OWN CA and lives only in its own Secret.

usage: enroll_fsc.py <party> rd-fabricx-<party> --kubeconfig K --ca-url http://localhost:7054 --work W --exchange <dir with org<N>/msp/{cacerts,knowncerts}> --out <new dir>/org<N> [--generation TAG]
W under /dev/shm only (umask 077) holding admin.pass of the org's CA (as for enroll.py); needs the port-forward to svc/fca-org<N>. Credentials only in env/stdin.
Nodes of the org (one pod, as panurus-itest/scripts/k8s.py PODS): bi = issuer + endorser-1, bank-a = bank2 + endorser-2, bank-b = bank3 + endorser-3, bank-c = bank4 + endorser-4.
Identities (all type client, registered at fca-org<N>; they cannot be removed afterwards):
  <node>-fsc    msp enrol -> fsc.identity cert/key; tls-profile enrol (SAN <node> and <node>.<ns>.svc.cluster.local) -> fsc.tls cert/key/ca
  <node>-admin  msp enrol -> only its CERT is kept (fsc.client.certs; replaced by the org's fx-gw client cert in S16); the key is never stored or used
  <node>-id     (issuer, bankN) msp enrol -> ids/<node>/msp; tls enrol -> fabric.default.tls client cert/key
  endorser-<N>-tls  (endorsers) tls enrol only: ids/endorser-<N>/msp is the EXISTING Secret fsc-endorser-<N>-secret (the genesis known_certs identity; its CA password
                    was never stored), mounted by the render, so it is neither re-registered nor copied here
Output: ONE Secret rdbi-<pod>-files (kubectl create; keys = pod paths under own/<node>/ with "/" written "__", see secret_key()), and a PUBLIC tree --out
(fsc/<node>.pem, admin/<node>-admin.pem, ids/<node>/msp/{signcerts,cacerts}, MANIFEST.sha256) that the other orgs' ConfigMap is built from. No Secret and no public file
is written until every enrolment succeeded. ids/anon, the Idemix owner wallet and the issuer wallet stay central until S15 (own-only import, separate step).
"""
import glob, hashlib, os, re, shutil, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fca"))
import enroll
import yaml

NODES = {"bi": ("bi", ["issuer", "endorser-1"]), "bank-a": ("bank2", ["bank2", "endorser-2"]),
         "bank-b": ("bank3", ["bank3", "endorser-3"]), "bank-c": ("bank4", ["bank4", "endorser-4"])}


def secret_key(rel):
    return rel.replace("/", "__")


def secret_path(key):
    return key.replace("__", "/")


def make(party, ns, kubeconfig, ca_url, work, exchange, out, generation=""):
    work = enroll.check_work(work)   # path guard first: destroy() below only ever touches a /dev/shm path
    secrets = []
    published = False
    try:
        n = enroll.check_target(party, ns)
        gen = enroll.check_generation(generation) if generation else ""
        sfx = f"-{gen}" if gen else ""
        pod, nodes = NODES[party]
        if os.path.exists(out):
            sys.exit(f"enroll_fsc.py: {out} must be a new directory")
        cacert = enroll.first(f"{exchange}/org{n}/msp/cacerts/*.pem") if glob.glob(f"{exchange}/org{n}/msp/cacerts/*.pem") else None
        known = f"{exchange}/org{n}/msp/knowncerts/endorser-{n}-cert.pem"
        if cacert is None or not os.path.exists(known):
            sys.exit(f"enroll_fsc.py: {exchange}/org{n}/msp needs cacerts/*.pem and knowncerts/endorser-{n}-cert.pem (the S8 endorser identity)")
        pw = enroll.read(f"{work}/admin.pass").strip()
        secrets.append(pw)
        base_env = {**os.environ, "FABRIC_CA_CLIENT_HOME": f"{work}/client"}
        creds = lambda who, s: {**base_env, "FABRIC_CA_CLIENT_URL": ca_url.replace("://", f"://{who}:{s}@")}
        adminmsp = f"{work}/admin-msp"
        enroll.sh("fabric-ca-client", "enroll", "-M", adminmsp, env=creds("admin", pw), secrets=secrets)

        def register(who):
            reg = enroll.sh("fabric-ca-client", "register", "-u", ca_url, "-M", adminmsp, "--id.name", who, "--id.type", "client", env=base_env, secrets=secrets)
            m = re.search(r"Password:\s*(\S+)", reg)
            if not m:
                sys.exit(f"enroll_fsc.py: register of {who} printed no generated password")
            secrets.append(m.group(1))
            return m.group(1)

        def msp(who, pwd, d):
            enroll.sh("fabric-ca-client", "enroll", "-M", d, env=creds(who, pwd), secrets=secrets)
            return (enroll.read(enroll.first(f"{d}/signcerts/*.pem")), enroll.read(enroll.first(f"{d}/keystore/*_sk")), enroll.read(enroll.first(f"{d}/cacerts/*.pem")))

        def tls(who, pwd, d, host):
            enroll.sh("fabric-ca-client", "enroll", "-M", d, "--enrollment.profile", "tls", "--csr.hosts", host, env=creds(who, pwd), secrets=secrets)
            return (enroll.read(enroll.first(f"{d}/signcerts/*.pem")), enroll.read(enroll.first(f"{d}/keystore/*_sk")), enroll.read(enroll.first(f"{d}/tlscacerts/*.pem")))

        own, public = {}, {}
        for node in nodes:
            host = f"{node},{node}.{ns}.svc.cluster.local"
            o = f"own/{node}"
            w = f"{work}/{node}"
            who = f"{node}-fsc{sfx}"
            pwd = register(who)
            cert, key, _ = msp(who, pwd, f"{w}/fsc/msp")
            own[f"{o}/fsc/cert.pem"], own[f"{o}/fsc/key.pem"] = cert, key
            public[f"fsc/{node}.pem"] = cert
            cert, key, ca = tls(who, pwd, f"{w}/fsc/tls", host)
            own[f"{o}/fsc/tls.crt"], own[f"{o}/fsc/tls.key"], own[f"{o}/fsc/tls-ca.crt"] = cert, key, ca
            who = f"{node}-admin{sfx}"
            cert, _, _ = msp(who, register(who), f"{w}/admin/msp")   # the key is dropped here
            own[f"{o}/fsc/admin.pem"] = cert
            public[f"admin/{node}-admin.pem"] = cert
            if node.startswith("endorser-"):
                who = f"{node}-tls{sfx}"
                cert, key, _ = tls(who, register(who), f"{w}/id/tls", host)
                public[f"ids/{node}/msp/signcerts/cert.pem"] = enroll.read(known)
                public[f"ids/{node}/msp/cacerts/ca.pem"] = enroll.read(cacert)
            else:
                who = f"{node}-id{sfx}"
                pwd = register(who)
                cert, key, ca = msp(who, pwd, f"{w}/id/msp")
                own[f"{o}/ids/{node}/msp/signcerts/cert.pem"], own[f"{o}/ids/{node}/msp/keystore/priv_sk"], own[f"{o}/ids/{node}/msp/cacerts/ca.pem"] = cert, key, ca
                public[f"ids/{node}/msp/signcerts/cert.pem"], public[f"ids/{node}/msp/cacerts/ca.pem"] = cert, ca
                cert, key, _ = tls(who, pwd, f"{w}/id/tls", host)
            own[f"{o}/tls/cert.pem"], own[f"{o}/tls/key.pem"] = cert, key
        for rel, text in public.items():
            enroll.write(f"{out}/{rel}", text)
        published = True
        def sha(p):
            with open(p, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        lines = sorted(f"{sha(p)}  {os.path.relpath(p, out)}\n" for d, _, names in os.walk(out) for x in names for p in [os.path.join(d, x)])
        enroll.write(f"{out}/MANIFEST.sha256", "".join(lines))
        s = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": {"name": f"rdbi-{pod}-files", "namespace": ns},
             "stringData": {secret_key(rel): text for rel, text in own.items()}}
        enroll.sh("kubectl", "--kubeconfig", kubeconfig, "create", "-f", "-", stdin=yaml.safe_dump(s), secrets=secrets)
    except BaseException:
        if published:
            shutil.rmtree(out, ignore_errors=True)
        raise
    finally:  # keys never stay in /dev/shm, also on error
        enroll.destroy(work)


if __name__ == "__main__":
    a = sys.argv[1:]
    try:
        party, ns = a[0], a[1]
        opt = dict(zip(a[2::2], a[3::2]))
        make(party, ns, opt["--kubeconfig"], opt["--ca-url"], opt["--work"], opt["--exchange"], opt["--out"], opt.get("--generation", ""))
    except (IndexError, KeyError):
        sys.exit(__doc__)
