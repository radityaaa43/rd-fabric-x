#!/usr/bin/env python3
"""Gateway identities and Secrets of one org (fabricx S16 custody): every private key is made at the org's OWN CA and lives only in its own Secret.

usage: enroll_gw.py <party> rd-fabricx-<party> --kubeconfig K --ca-url http://localhost:7054 --work W --tls-exchange <dir with org1..org4/msp/tlscacerts>
                    --lensa-ca <public CA cert FILE of bank-gw-ca-<N>> --out <new dir>/org<N> [--generation TAG]
W under /dev/shm only (umask 077) holding admin.pass of the org's CA (as for enroll.py); needs the port-forward to svc/fca-org<N>. Credentials only in env/stdin.
Identities (all type client, registered at fca-org<N>; they cannot be removed afterwards):
  fx-gw-<N>       tls enrol (SAN fx-gw-<N> and fx-gw-<N>.<ns>.svc.cluster.local) -> Secret fx-gw-<N>-server {tls.crt, tls.key}: the gateway's server certificate
  fx-gw-<N>-peer  tls enrol (same SANs) -> Secret fx-gw-<N>-peer {tls.crt, tls.key}: what fxapi presents to the other gateways (FXGW_TLS=/peer)
  <node>-gw       msp enrol -> Secret fx-gw-<N>-client {gw.key}: the key fxapi signs view calls with; its CERT is public (--out gw/<node>-gw.pem; render --gw-cert, and the
                  fsc.client.certs swap of the node core in a later, separate field change)
Secret fx-gw-<N>-client-ca {ca.crt} = the Lensa CA (public file) + the 4 orgs' public TLS CAs (the peer gateways); no CA key is read or moved.
Output: ONE kubectl create of the four Secrets, and a PUBLIC tree --out (gw/<node>-gw.pem, gw/fx-gw-<N>.pem, gw/fx-gw-<N>-peer.pem, MANIFEST.sha256). No Secret and no public
file is written until every enrolment succeeded.
"""
import glob, hashlib, os, re, shutil, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fca"))
import enroll
import yaml

NODE = {"bi": "issuer", "bank-a": "bank2", "bank-b": "bank3", "bank-c": "bank4"}


def die(msg):
    sys.exit(f"enroll_gw.py: {msg}")


def make(party, ns, kubeconfig, ca_url, work, tls_exchange, lensa_ca, out, generation=""):
    work = enroll.check_work(work)   # path guard first: destroy() below only ever touches a /dev/shm path
    secrets = []
    published = False
    try:
        n = enroll.check_target(party, ns)
        gen = enroll.check_generation(generation) if generation else ""
        sfx = f"-{gen}" if gen else ""
        node, gw = NODE[party], f"fx-gw-{n}"
        if os.path.exists(out):
            die(f"{out} must be a new directory")
        if not os.path.isfile(lensa_ca):
            die(f"--lensa-ca {lensa_ca} is not a file")
        lensa = enroll.read(lensa_ca)
        if "PRIVATE KEY" in lensa or "BEGIN CERTIFICATE" not in lensa:
            die(f"{lensa_ca} must be a PUBLIC CA certificate (no private key)")
        bundle = lensa if lensa.endswith("\n") else lensa + "\n"
        seen = {lensa.strip()}
        for m in (1, 2, 3, 4):
            files = sorted(glob.glob(f"{tls_exchange}/org{m}/msp/tlscacerts/*.pem"))
            if not files:
                die(f"{tls_exchange}/org{m}/msp/tlscacerts/*.pem is missing: the client CA bundle needs all four orgs' TLS CAs")
            for p in files:
                t = enroll.read(p)
                if "PRIVATE KEY" in t:
                    die(f"{p} holds a private key")
                if t.strip() not in seen:
                    seen.add(t.strip())
                    bundle += t if t.endswith("\n") else t + "\n"
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
                die(f"register of {who} printed no generated password")
            secrets.append(m.group(1))
            return m.group(1)

        def msp(who, pwd, d):
            enroll.sh("fabric-ca-client", "enroll", "-M", d, env=creds(who, pwd), secrets=secrets)
            return enroll.read(enroll.first(f"{d}/signcerts/*.pem")), enroll.read(enroll.first(f"{d}/keystore/*_sk"))

        def tls(who, pwd, d):
            enroll.sh("fabric-ca-client", "enroll", "-M", d, "--enrollment.profile", "tls", "--csr.hosts", f"{gw},{gw}.{ns}.svc.cluster.local", env=creds(who, pwd), secrets=secrets)
            return enroll.read(enroll.first(f"{d}/signcerts/*.pem")), enroll.read(enroll.first(f"{d}/keystore/*_sk"))

        who = f"{gw}{sfx}"
        srv_crt, srv_key = tls(who, register(who), f"{work}/ids/{who}/tls")
        who = f"{gw}-peer{sfx}"
        peer_crt, peer_key = tls(who, register(who), f"{work}/ids/{who}/tls")
        who = f"{node}-gw{sfx}"
        gw_crt, gw_key = msp(who, register(who), f"{work}/ids/{who}/msp")

        public = {f"gw/{gw}.pem": srv_crt, f"gw/{gw}-peer.pem": peer_crt, f"gw/{node}-gw.pem": gw_crt}
        for rel, text in public.items():
            enroll.write(f"{out}/{rel}", text)
        published = True

        def sha(p):
            with open(p, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        lines = sorted(f"{sha(p)}  {os.path.relpath(p, out)}\n" for d, _, names in os.walk(out) for x in names for p in [os.path.join(d, x)])
        enroll.write(f"{out}/MANIFEST.sha256", "".join(lines))
        sec = lambda name, data: {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": {"name": name, "namespace": ns}, "stringData": data}
        lst = {"apiVersion": "v1", "kind": "List", "items": [
            sec(f"{gw}-server", {"tls.crt": srv_crt, "tls.key": srv_key}), sec(f"{gw}-peer", {"tls.crt": peer_crt, "tls.key": peer_key}),
            sec(f"{gw}-client", {"gw.key": gw_key}), sec(f"{gw}-client-ca", {"ca.crt": bundle})]}
        enroll.sh("kubectl", "--kubeconfig", kubeconfig, "create", "-f", "-", stdin=yaml.safe_dump(lst), secrets=secrets)
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
        make(party, ns, opt["--kubeconfig"], opt["--ca-url"], opt["--work"], opt["--tls-exchange"], opt["--lensa-ca"], opt["--out"], opt.get("--generation", ""))
    except (IndexError, KeyError):
        sys.exit(__doc__)
