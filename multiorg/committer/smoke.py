#!/usr/bin/env python3
"""Offline smoke for multiorg/committer/render.py: start the PINNED upstream committer (fabric-x-committer v1.0.4) on the RENDERED args and mount layout.

usage: smoke.py --committer BIN --armageddon BIN --sample-config DIR --cfgupdate BIN [--seconds 8] [--keep]
BIN committer = `go build ./cmd/committer` of hyperledger/fabric-x-committer v1.0.4; the other three are as in multiorg/arma/smoke.py.
Throwaway material only (openssl CAs/keys; a real genesis block built by our own tools). Per party: render, lay each workload's volumes out like the
kubelet (multiorg/arma/smoke.py layout()), run `committer <rendered args>` for verifier, vc, coordinator, sidecar and query.
There is no Postgres and no orderer here, so the verdict is about START-UP ONLY: a service must still be running after --seconds, OR have exited
only because it could not reach a peer / the database (connection refused, no such host, lookup, dial, i/o timeout, EOF). Any `panic`, missing file,
bad config key, TLS certificate/key load error or unknown command FAILS. Run it before every apply of a changed committer render.
"""
import argparse, hashlib, importlib.util, json, os, re, shutil, subprocess, sys, tempfile, time
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
MULTIORG = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import render

_spec = importlib.util.spec_from_file_location("arma_smoke", os.path.join(MULTIORG, "arma", "smoke.py"))
arma_smoke = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(arma_smoke)

PARTIES = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
BAD = re.compile(r"panic|no such file|failed to (load|read|parse|open)|unknown (flag|command)|unmarshal|invalid config|x509|tls: (failed|bad|private)|expected command|cannot unmarshal|unable to", re.I)
PEER = re.compile(r"connection refused|no such host|lookup |dial|i/o timeout|EOF|unavailable|context deadline|failed to connect|connect:", re.I)


def sh(*a):
    r = subprocess.run(a, capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"smoke.py: {' '.join(map(str, a[:3]))}... rc={r.returncode}: {(r.stderr or r.stdout)[-500:]}")
    return r.stdout


def ca(root, name):
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{root}/{name}.key", "-subj", f"/CN={name}", "-days", "2",
       "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", f"{root}/{name}.pem")


def leaf(root, cafile, cn, sans, prefix):
    sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", f"{root}/{prefix}.key")
    sh("openssl", "req", "-new", "-key", f"{root}/{prefix}.key", "-subj", f"/CN={cn}", "-out", f"{root}/{prefix}.csr")
    open(f"{root}/{prefix}.ext", "w").write("keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth,serverAuth\n" + (f"subjectAltName={sans}\n" if sans else ""))
    sh("openssl", "x509", "-req", "-in", f"{root}/{prefix}.csr", "-CA", f"{root}/{cafile}.pem", "-CAkey", f"{root}/{cafile}.key", "-CAcreateserial", "-days", "2", "-extfile", f"{root}/{prefix}.ext", "-out", f"{root}/{prefix}.pem")


def secrets_for(work, org_ca_pem, org_ca_key):
    rd = lambda p: open(p).read()
    m = f"{work}/mat"
    os.makedirs(m)
    ca(m, "ccommitter"); ca(m, "cdb")
    sans = ",".join(f"DNS:committer-{s}" for s in ("verifier", "vc", "coordinator", "sidecar", "query-service")) + ",DNS:localhost"
    leaf(m, "ccommitter", "committer", sans, "tls")
    leaf(m, "cdb", "committer-db", "DNS:committer-db", "dbtls")
    shutil.copy(org_ca_pem, f"{m}/orgca.pem"); shutil.copy(org_ca_key, f"{m}/orgca.key")
    leaf(m, "orgca", "committer-1", None, "id")
    return {"committer-tls": {"server.crt": rd(f"{m}/tls.pem"), "server.key": rd(f"{m}/tls.key"), "ca.crt": rd(f"{m}/ccommitter.pem")},
            "committer-db-tls": {"server.crt": rd(f"{m}/dbtls.pem"), "server.key": rd(f"{m}/dbtls.key"), "ca.crt": rd(f"{m}/cdb.pem")},
            "committer-db-credentials": {"password": "smoke-throwaway"},
            "committer-sidecar-msp": {"keystore-priv_sk": rd(f"{m}/id.key"), "signcert.pem": rd(f"{m}/id.pem"), "cacert.pem": rd(f"{m}/orgca.pem")}}


def env_of(c, secrets):
    out = {}
    for e in c.get("env", []):
        if "value" in e:
            out[e["name"]] = e["value"]
        else:
            ref = e["valueFrom"]["secretKeyRef"]
            out[e["name"]] = secrets[ref["name"]][ref["key"]]
    return out


def main():
    p = argparse.ArgumentParser(usage=__doc__)
    for o in ("committer", "armageddon", "sample-config", "cfgupdate"):
        p.add_argument(f"--{o}", required=True)
    p.add_argument("--seconds", type=float, default=8)
    p.add_argument("--keep", action="store_true")
    a = p.parse_args()
    work = tempfile.mkdtemp(prefix="committer-smoke-")
    bad = []
    try:
        tree = f"{work}/t"
        heads = sh(sys.executable, "-I", f"{MULTIORG}/cfgupdate/rehearse/make_trees.py", tree).strip()
        built = json.loads(sh(sys.executable, "-I", f"{MULTIORG}/s10/build_genesis.py", "--exchange", f"{tree}/exchange", "--armageddon", a.armageddon,
                              "--sample-config", getattr(a, "sample_config"), "--out", f"{work}/g", "--heads", heads))
        genesis = f"{work}/genesis.block"
        sh(a.cfgupdate, "finalize", "-block", built["block"], "-out", genesis, "-bank-ids", "org1,org2,org3,org4", "-threshold", "3", "-channel-capability", "V3_0")
        gen_bytes = open(genesis, "rb").read()
        secrets = secrets_for(work, f"{tree}/keys/ca1.pem", f"{tree}/keys/ca1.key")
        for party, n in PARTIES.items():
            kw = dict(storage_class="fabricx-essd") if party == "bank-c" else {}
            docs = list(yaml.safe_load_all(render.render(party, **kw)))
            # the genesis ConfigMap comes from the arma render; the committer mounts it as the config block
            docs.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "genesis-block"}, "binaryData": {"genesis.block": __import__("base64").b64encode(gen_bytes).decode()}})
            procs = []
            for w in [d for d in docs if d["kind"] in ("Deployment", "StatefulSet") and d["metadata"]["name"] != "committer-db"]:
                name = w["metadata"]["name"]
                base = f"{work}/run/{party}/{name}"
                os.makedirs(base)
                args = arma_smoke.layout(w, docs, secrets, base)
                c = w["spec"]["template"]["spec"]["containers"][0]
                log = open(f"{base}.log", "w")
                procs.append((name, subprocess.Popen([a.committer] + args, stdout=log, stderr=subprocess.STDOUT, cwd=work, env={**os.environ, **env_of(c, secrets)}), f"{base}.log"))
            time.sleep(a.seconds)
            for name, pr, logf in procs:
                alive = pr.poll() is None
                if alive:
                    pr.terminate()
                    pr.wait(10)
                text = open(logf, errors="replace").read()
                err = [l for l in text.splitlines() if BAD.search(l)]
                ok = not err and (alive or PEER.search(text))
                state = "running" if alive else f"exited rc={pr.returncode} (peer/db unreachable)" if ok else f"exited rc={pr.returncode}"
                print(f"{'OK' if ok else 'FAIL'} {party} {name}: {state}")
                if not ok:
                    bad.append(f"{party}/{name}")
                    why = err[:2] or [l for l in text.splitlines() if l.strip()][-2:]
                    print("   " + "\n   ".join(l[:300] for l in why))
    finally:
        if a.keep:
            print(f"kept {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
