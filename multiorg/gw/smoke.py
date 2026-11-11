#!/usr/bin/env python3
"""Smoke of the gateway render with the PINNED images (docker, no cluster): envoy --mode validate on the rendered envoy.yaml, and OPA started with the rendered args + config.
OPA must come up (its bundle pull fails: no bundle-server here, that is expected); a config or flag error in the first seconds fails the smoke.

  python3 -I multiorg/gw/smoke.py --templates DIR --opa-config FILE --gw-ips FILE --tls-exchange DIR --envoy-image repo@sha256:HEX --opa-image repo@sha256:HEX [--image repo@sha256:HEX]
"""
import argparse, importlib.util, os, subprocess, sys, tempfile
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("gw_render", os.path.join(HERE, "render.py"))
gw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gw)


def run(cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def main():
    ap = argparse.ArgumentParser()
    for o in ("templates", "opa-config", "gw-ips", "tls-exchange", "envoy-image", "opa-image"):
        ap.add_argument(f"--{o}", required=True)
    ap.add_argument("--image", default="example.io/rdbi@sha256:" + "d" * 64)
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as d:
        os.chmod(d, 0o755)
        cert = f"{d}/gw.pem"
        open(cert, "w").write("-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n")
        for sub in ("mtls", "ca"):
            os.makedirs(f"{d}/{sub}")
        r = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{d}/mtls/tls.key", "-out", f"{d}/mtls/tls.crt", "-days", "1", "-subj", "/CN=fx-gw-1"])
        if r.returncode:
            sys.exit("openssl failed: " + r.stderr[:200])
        open(f"{d}/ca/ca.crt", "w").write(open(f"{d}/mtls/tls.crt").read())
        subprocess.run(["chmod", "-R", "a+rX", d])
        docs = list(yaml.safe_load_all(gw.render("bi", a.templates, a.image, a.envoy_image, a.opa_image, a.opa_config, cert, a.gw_ips, a.tls_exchange)))
        cm = {x["metadata"]["name"]: x for x in docs if x["kind"] == "ConfigMap"}
        open(f"{d}/envoy.yaml", "w").write(cm["fx-gw-1-envoy"]["data"]["envoy.yaml"])
        open(f"{d}/opa.yaml", "w").write(cm["fx-gw-1-opa"]["data"]["opa.yaml"])
        dep = [x for x in docs if x["kind"] == "Deployment"][0]
        opa_args = [c for c in dep["spec"]["template"]["spec"]["containers"] if c["name"] == "opa"][0]["args"]
        subprocess.run(["chmod", "a+r", f"{d}/envoy.yaml", f"{d}/opa.yaml"])
        r = run(["docker", "run", "--rm", "--user", "10001", "-v", f"{d}/envoy.yaml:/config/envoy.yaml:ro", "-v", f"{d}/mtls:/mtls:ro", "-v", f"{d}/ca:/client-ca:ro",
                 a.envoy_image, "--mode", "validate", "-c", "/config/envoy.yaml"])
        ok = r.returncode == 0 and "OK" in (r.stdout + r.stderr)
        print("envoy --mode validate:", "OK" if ok else "FAIL\n" + (r.stdout + r.stderr)[-600:])
        # OPA: bind free ports instead of the pod's, run a few seconds, then stop
        args = [x.replace("--addr=localhost:8181", "--addr=127.0.0.1:18181").replace("--diagnostic-addr=0.0.0.0:8282", "--diagnostic-addr=127.0.0.1:18282") for x in opa_args]
        name = f"gw-smoke-{os.getpid()}"
        p = subprocess.Popen(["docker", "run", "--rm", "--name", name, "--user", "10001", "-v", f"{d}/opa.yaml:/config/opa.yaml:ro", a.opa_image, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            out, _ = p.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "stop", "-t", "1", name], capture_output=True)
            out, _ = p.communicate()
        # OPA logs JSON lines: it must reach "Starting gRPC server" (the envoy plugin loaded); the only error allowed is the bundle pull (no bundle-server here)
        bad = [l for l in out.splitlines() if '"level":"error"' in l and "Bundle load failed" not in l and "bundle" not in l.lower()] + (["unknown flag"] if "unknown flag" in out else [])
        started = "Starting gRPC server" in out
        print("opa start:", "OK" if started and not bad else "FAIL")
        if bad or not started:
            print(out[-800:])
        sys.exit(0 if ok and started and not bad else 1)


if __name__ == "__main__":
    main()
