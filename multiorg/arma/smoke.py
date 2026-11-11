#!/usr/bin/env python3
"""Offline smoke for multiorg/arma/render.py: start the PINNED upstream `arma` binary on the RENDERED args and mount layout (no cluster, no network).

usage: smoke.py --arma BIN --armageddon BIN --sample-config DIR --cfgupdate BIN [--seconds 8] [--keep]
BIN files are built from hyperledger/fabric-x-orderer@dd296e3 (arma = ./cmd/arma, armageddon as for build_genesis.py) and multiorg/cfgupdate.
Steps (all throwaway: openssl CAs and keys from cfgupdate/rehearse/make_trees.py, a real genesis block built and finalized by our own tools):
  render every party -> lay each StatefulSet's volumes out exactly as the kubelet would (secret/configMap items + subPath mounts) under a scratch dir,
  paths /config and /data rewritten into that dir -> run `arma <rendered args>` for each role -> PASS only if every process is still running after
  --seconds with no `panic` in its log. It fails on the two start-up panics seen on the cluster (2026-11-11): `administrators must be declared when no
  admin ou classification is set` (local MSP without admincerts) and `expected command but got "consenter"` (wrong CLI command).
The processes try to reach their peers by name and keep retrying; that is not a failure here (config load, local MSP and listeners only).
"""
import argparse, base64, json, os, shutil, subprocess, sys, tempfile, time
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
MULTIORG = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import render

PARTIES = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}


def run(*a, **k):
    r = subprocess.run(a, capture_output=True, text=True, **k)
    if r.returncode:
        sys.exit(f"smoke.py: {' '.join(map(str, a[:3]))}... failed rc={r.returncode}: {(r.stderr or r.stdout)[-600:]}")
    return r.stdout


def secrets_for(tree, keys, n):
    """The node Secrets enroll.py makes (names and keys), from the throwaway material."""
    rd = lambda p: open(p).read()
    out = {}
    for role in render.ROLES:
        crt = f"{tree}/exchange/org{n}/orderers/party{n}/{role}/msp/signcerts/{role}-cert.pem"
        if not os.path.exists(crt):
            crt = f"{keys}/org{n}-{role}-msp.pem"
        out[f"orderer-{render.SECRET_ROLE[role]}-{n}-secret"] = {
            "msp-keystore-priv_sk": rd(f"{keys}/org{n}-{role}-msp.key"), "msp-signcert.pem": rd(crt),
            "tls-server.key": rd(f"{keys}/org{n}-{role}-tls.key"), "tls-server.crt": rd(f"{tree}/exchange/org{n}/orderers/party{n}/{role}/tls/server.crt")}
    return out


def layout(sts, docs, secrets, base):
    """Write the files the pod would see. Returns the container args with /config rewritten into base."""
    spec = sts["spec"]["template"]["spec"]
    c = spec["containers"][0]
    cms = {d["metadata"]["name"]: {**{k: v.encode() for k, v in d.get("data", {}).items()}, **{k: base64.b64decode(v) for k, v in d.get("binaryData", {}).items()}}
           for d in docs if d["kind"] == "ConfigMap"}
    vols = {v["name"]: v for v in spec["volumes"]}
    for m in c["volumeMounts"]:
        dest = base + m["mountPath"]
        if m["name"] not in vols or "secret" not in vols[m["name"]] and "configMap" not in vols[m["name"]]:   # claim templates / emptyDir: a plain directory
            os.makedirs(dest, exist_ok=True)
            continue
        v = vols[m["name"]]
        if "secret" in v:
            src, items = {k: x.encode() for k, x in secrets[v["secret"]["secretName"]].items()}, v["secret"]["items"]
        else:
            src, items = cms[v["configMap"]["name"]], v["configMap"]["items"]
        key = next(i["key"] for i in items if i["path"] == m["subPath"])
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            f.write(src[key])
    os.makedirs(base + "/data", exist_ok=True)
    cfg = base + next(x.split("=", 1)[1] for x in c["args"] if x.startswith("--config="))   # the file the container is told to load
    text = open(cfg).read().replace("/config/", base + "/config/").replace("/data/", base + "/data/")
    open(cfg, "w").write(text)
    return [a.replace("/config/", base + "/config/") for a in c["args"]]


def main():
    p = argparse.ArgumentParser(usage=__doc__)
    for o in ("arma", "armageddon", "sample-config", "cfgupdate"):
        p.add_argument(f"--{o}", required=True)
    p.add_argument("--seconds", type=float, default=8)
    p.add_argument("--keep", action="store_true")
    a = p.parse_args()
    work = tempfile.mkdtemp(prefix="arma-smoke-")
    bad = []
    try:
        tree, keys = f"{work}/t", f"{work}/t/keys"
        heads = run(sys.executable, "-I", f"{MULTIORG}/cfgupdate/rehearse/make_trees.py", tree).strip()
        built = json.loads(run(sys.executable, "-I", f"{MULTIORG}/s10/build_genesis.py", "--exchange", f"{tree}/exchange", "--armageddon", a.armageddon,
                               "--sample-config", getattr(a, "sample_config"), "--out", f"{work}/g", "--heads", heads))
        genesis = f"{work}/genesis.block"
        run(a.cfgupdate, "finalize", "-block", built["block"], "-out", genesis, "-bank-ids", "org1,org2,org3,org4", "-threshold", "3", "-channel-capability", "V3_0")
        sha = __import__("hashlib").sha256(open(genesis, "rb").read()).hexdigest()
        for party, n in PARTIES.items():
            kw = dict(zone="ap-southeast-1a", storage_class="fabricx-essd") if party == "bank-c" else {}
            docs = list(yaml.safe_load_all(render.render(party, f"{tree}/exchange", genesis, sha, **kw)))
            secrets = secrets_for(tree, keys, n)
            procs = []
            for sts in [d for d in docs if d["kind"] == "StatefulSet"]:
                name = sts["metadata"]["name"]
                base = f"{work}/run/{name}"
                args = layout(sts, docs, secrets, base)
                log = open(f"{base}.log", "w")
                procs.append((name, subprocess.Popen([a.arma] + args, stdout=log, stderr=subprocess.STDOUT, cwd=work), f"{base}.log"))
            time.sleep(a.seconds)
            for name, pr, logf in procs:
                alive = pr.poll() is None
                if alive:
                    pr.terminate()
                    pr.wait(10)
                text = open(logf).read()
                verdict = "OK" if alive and "panic" not in text.lower() else "FAIL"
                print(f"{verdict} {name}: {'running' if alive else f'exited rc={pr.returncode}'}")
                if verdict == "FAIL":
                    bad.append(name)
                    why = [l for l in text.splitlines() if "panic" in l.lower() or "error" in l.lower() or "fatal" in l.lower()] or [l for l in text.splitlines() if l.strip()][-2:]
                    print("   " + "\n   ".join(l[:300] for l in why[:2]))
    finally:
        if a.keep:
            print(f"kept {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
