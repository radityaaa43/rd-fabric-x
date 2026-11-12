#!/usr/bin/env python3
"""R32 closure tooling for the four fx-gw doors (stdout only, nothing is applied, no cluster call, no key read).

usage: r32.py job --image repo@sha256:HEX --gw BI=URL --gw A=URL --gw B=URL --gw C=URL      print the cross-party 403 Job (ConfigMap + Job in rd-lensa)
       r32.py verdict < job-log                                                              PASS/FAIL of the 16-pair matrix from the Job log
       r32.py revisions [--expect-fabricx-bi N] fx-gw-1=FILE fx-gw-2=FILE fx-gw-3=FILE fx-gw-4=FILE   quote the bundle revisions each gateway reports
            FILE = `kubectl -n <ns> logs deploy/fx-gw-<N> -c opa --tail=400` (OPA status log lines; read-only)

`job`: ONE Job in rd-lensa, labelled app=lensa role=probe-flow (the existing NetworkPolicy egress-gateways-flow selects it: egress to the four fx-gw :8443 and DNS, nothing else). It mounts the four
EXISTING Secrets lensa-gw-mtls-{bi,a,b,c} by name with the same layout as the Lensa Deployment (<P>/ca.crt, lensa.crt, lensa.key), so no key is copied or moved. For every caller party P and
every gateway Q it POSTs the read op `balance` over mTLS with P's Lensa leaf and prints `P Q <http status|ERR>`. Expected after the R32 publish: P != Q -> 403 (12 pairs); P == Q -> any HTTP answer
but 403 (4 positive controls; the body is minimal so the backend may answer 400). No write op is ever sent. The Job needs the Lensa image (node) by digest; the operator creates it (rd-lensa is not
a rd-fabricx namespace).
`verdict`: PASS only when all 16 pairs appear exactly once and match the expectation above. An ERR (no HTTP answer) is never a 403 and never a positive control.
`revisions`: the last OPA status line of each gateway, both bundles (bi, bank), with the activation time; closure quotes it for EVERY gateway because they differ.
"""
import argparse, json, re, sys
import yaml

PARTIES = ["BI", "A", "B", "C"]
NODE = {"BI": 1, "A": 2, "B": 3, "C": 4}
READS = {"balance", "history", "records", "finality", "report", "usage"}
NS = "rd-lensa"
LABELS = {"app": "lensa", "part-of": "rd-lensa", "role": "probe-flow"}
UID = 10001
NAME = "r32-cross-party"

PROBE = """import https from 'node:https';
import { readFileSync } from 'node:fs';
const cfg = JSON.parse(readFileSync('/probe/matrix.json', 'utf8'));
const body = JSON.stringify(cfg.body);
function call(caller, target) {
  const t = cfg.targets[target];
  const u = new URL(t.url);
  const opts = {
    method: 'POST', host: u.hostname, port: u.port || 443, path: '/', servername: t.servername, timeout: 10000,
    ca: readFileSync(`/certs/${caller}/ca.crt`), cert: readFileSync(`/certs/${caller}/lensa.crt`), key: readFileSync(`/certs/${caller}/lensa.key`),
    headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
  };
  return new Promise((resolve) => {
    const req = https.request(opts, (res) => { res.resume(); res.on('end', () => resolve(String(res.statusCode))); });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve('ERR'));
    req.end(body);
  });
}
for (const caller of cfg.callers) {
  for (const target of cfg.callers) {
    const status = await call(caller, target);
    console.log(`${caller} ${target} ${status}`);
  }
}
"""


def die(msg):
    sys.exit(f"r32.py: {msg}")


def render_job(image, urls):
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image or ""):
        die("--image must be pinned by digest (repo@sha256:<64 hex>)")
    if sorted(urls) != sorted(PARTIES):
        die(f"--gw needs exactly {', '.join(PARTIES)} (got {', '.join(sorted(urls)) or 'none'})")
    for p, u in urls.items():
        if not re.fullmatch(r"https://[A-Za-z0-9.-]+:\d+", u):
            die(f"--gw {p}: https://host:port expected, got {u!r}")
    cfg = {"body": {"op": "balance"}, "callers": PARTIES,
           "targets": {p: {"url": urls[p], "servername": f"fx-gw-{NODE[p]}"} for p in PARTIES}}
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"{NAME}-in", "namespace": NS, "labels": {"app": "lensa", "part-of": "rd-lensa"}},
          "data": {"matrix.json": json.dumps(cfg, indent=1), "probe.mjs": PROBE}}
    certs = [{"secret": {"name": f"lensa-gw-mtls-{p.lower()}", "items": [{"key": f, "path": f"{p}/{f}"} for f in ("ca.crt", "lensa.crt", "lensa.key")]}} for p in PARTIES]
    sec = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME, "namespace": NS, "labels": {"app": "lensa", "part-of": "rd-lensa"}},
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 240, "ttlSecondsAfterFinished": 900,
                    "template": {"metadata": {"labels": LABELS}, "spec": {
                        "automountServiceAccountToken": False, "restartPolicy": "Never",
                        "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "runAsGroup": UID, "fsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
                        "imagePullSecrets": [{"name": "ghcr-pull"}],
                        "containers": [{"name": "probe", "image": image, "command": ["node", "/probe/probe.mjs"], "securityContext": sec,
                                        "volumeMounts": [{"name": "certs", "mountPath": "/certs", "readOnly": True}, {"name": "probe", "mountPath": "/probe", "readOnly": True}],
                                        "resources": {"requests": {"cpu": "20m", "memory": "64Mi", "ephemeral-storage": "8Mi"}, "limits": {"cpu": "500m", "memory": "192Mi", "ephemeral-storage": "16Mi"}}}],
                        "volumes": [{"name": "certs", "projected": {"defaultMode": 0o440, "sources": certs}},
                                    {"name": "probe", "configMap": {"name": f"{NAME}-in", "defaultMode": 0o444}}]}}}}
    return yaml.safe_dump_all([cm, job], sort_keys=False)


def verdict(log):
    seen, rep = {}, []
    for line in log.splitlines():
        m = re.fullmatch(r"(BI|A|B|C) (BI|A|B|C) (\d{3}|ERR)", line.strip())
        if m:
            k = (m.group(1), m.group(2))
            if k in seen:
                rep.append(f"FAIL {k[0]} {k[1]}: reported twice")
            seen[k] = m.group(3)
    for c in PARTIES:
        for t in PARTIES:
            s = seen.get((c, t))
            if s is None:
                rep.append(f"FAIL {c} {t}: missing")
            elif c != t and s != "403":
                rep.append(f"FAIL {c} {t}: cross-party got {s}, want 403")
            elif c == t and s in ("403", "ERR"):
                rep.append(f"FAIL {c} {t}: own leaf got {s}, want an HTTP answer other than 403")
    ok = not rep
    rep.append(f"{'PASS' if ok else 'FAIL'}: 12 cross pairs 403, 4 own leaves answered, from {len(seen)} reported pairs")
    return ok, rep


def revisions(log):
    last = None
    for line in log.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if isinstance(d, dict) and isinstance(d.get("bundles"), dict):
            last = d["bundles"]
    if last is None:
        die("no OPA bundle status line in the log")
    out = {}
    for name in ("bi", "bank"):
        b = last.get(name)
        if not isinstance(b, dict) or not b.get("active_revision") or not b.get("last_successful_activation"):
            die(f"bundle {name!r} has no active_revision with an activation in the last status line")
        out[name] = b["active_revision"]
    return out


def revision_table(logs, expect_fabricx_bi=None):
    ok, rep = True, []
    for n in (1, 2, 3, 4):
        g = f"fx-gw-{n}"
        if g not in logs:
            ok = False
            rep.append(f"{g}: MISSING log")
            continue
        r = revisions(logs[g])
        flag = ""
        if expect_fabricx_bi is not None and not re.search(rf"-fabricx\.{expect_fabricx_bi}(-|$)", r["bi"]):
            ok = False
            flag = f"  MISMATCH (bi bundle fabricx != {expect_fabricx_bi})"
        rep.append(f"{g}: bi={r['bi']} bank={r['bank']}{flag}")
    rep.append("PASS: revisions quoted for all four gateways" if ok else "FAIL: see lines above")
    return ok, rep


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("job")
    j.add_argument("--image", required=True)
    j.add_argument("--gw", action="append", default=[], metavar="PARTY=URL")
    sub.add_parser("verdict")
    r = sub.add_parser("revisions")
    r.add_argument("--expect-fabricx-bi", type=int)
    r.add_argument("files", nargs="+", metavar="fx-gw-N=FILE")
    a = ap.parse_args(argv)
    if a.cmd == "job":
        urls = dict(x.split("=", 1) for x in a.gw)
        sys.stdout.write(render_job(a.image, urls))
        return 0
    if a.cmd == "verdict":
        ok, rep = verdict(sys.stdin.read())
    else:
        logs = {}
        for f in a.files:
            k, _, path = f.partition("=")
            logs[k] = open(path).read()
        ok, rep = revision_table(logs, a.expect_fabricx_bi)
    print("\n".join(rep))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
