#!/usr/bin/env python3
"""Own-only import of the CENTRAL FSC material into rdbi-<pod>-files (fabricx S13 piece 4; interim until S15).

usage: import_central.py <party> rd-fabricx-<party> --kubeconfig K --templates <live dir with <node>/core.yaml> --home <~/.fabricx-token> --keys-out <file.json>
What stays central until S15 (PLAN S13 interim custody note): ids/anon/msp (the shared Idemix submitter material), the Idemix owner wallet of each bank node and the
issuer wallet MSP. For each node of the org this reads ONLY the directories that node's own core.yaml names (core_rewrite.per_org_core), never another node's, refuses symlinks
and an empty directory, and adds the files to the org's Secret rdbi-<pod>-files with ONE direct API call `PATCH /api/v1/namespaces/<ns>/secrets/rdbi-<pod>-files` (merge-patch+json) using the party kubeconfig's own server/CA/token (read in memory,
never printed, never on argv). `kubectl patch` is NOT used: it GETs first and the party-admin Role has create/update/patch on secrets but no get. --keys-out receives the key NAMES (JSON list) that render.py takes as --central-keys; no value is ever written there.
Key = "own__<node>__<path below the node dir with / as __>", the same naming as enroll_fsc.secret_key(); characters outside [-._a-zA-Z0-9] in a file name (the issuer wallet has
`issuer@Orgissuer.example.com-cert.pem`) become `_` (an MSP dir is read by directory scan, not by file name); two files that collide after that are refused.
"""
import base64, json, os, re, ssl, sys, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "fca"))
import core_rewrite as cr
import enroll
import enroll_fsc
import yaml

T = "/home/rdbi/.fabricx-token"
KEY = re.compile(r"^[-._a-zA-Z0-9]{1,253}$")


def central_dirs(core, node, home):
    """[(path below own/, source dir)] of the central material this node's core.yaml needs"""
    _, man = cr.per_org_core(core, node, home, T)
    out = []
    for pod_path, info in man.items():
        if info["kind"] != "secret" or not pod_path.startswith(f"{T}/own/"):
            continue
        rel = pod_path[len(f"{T}/own/"):]
        if "/ids/anon/" in f"/{rel}/" or "/wallets/" in rel:
            out.append((rel, info["src"]))
    return out


def files_of(src):
    if os.path.islink(src) or not os.path.isdir(src):
        sys.exit(f"import_central.py: {src} is not a plain directory")
    out = []
    for d, dirs, names in os.walk(src):
        for x in dirs + names:
            if os.path.islink(os.path.join(d, x)):
                sys.exit(f"import_central.py: {os.path.join(d, x)} is a symlink: refused")
        out += [os.path.join(d, x) for x in names]
    if not out:
        sys.exit(f"import_central.py: {src} holds no file")
    return sorted(out)


def api_patch(kubeconfig, ns, name, data):
    """merge-patch Secret `name` with base64 `data`; returns nothing, exits with a scrubbed message on error"""
    cfg = yaml.safe_load(open(kubeconfig))
    ctx = next(c["context"] for c in cfg["contexts"] if c["name"] == cfg["current-context"])
    cl = next(c["cluster"] for c in cfg["clusters"] if c["name"] == ctx["cluster"])
    token = next(u["user"]["token"] for u in cfg["users"] if u["name"] == ctx["user"])
    server = cl["server"].rstrip("/")
    sslctx = None
    if server.startswith("https://"):
        sslctx = ssl.create_default_context(cadata=base64.b64decode(cl["certificate-authority-data"]).decode())
    req = urllib.request.Request(f"{server}/api/v1/namespaces/{ns}/secrets/{name}", data=json.dumps({"data": data}).encode(), method="PATCH",
                                 headers={"Content-Type": "application/merge-patch+json", "Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        urllib.request.urlopen(req, context=sslctx, timeout=60).read()
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("message", "")
        except ValueError:
            msg = ""
        sys.exit(f"import_central.py: PATCH {ns}/{name} failed: HTTP {e.code} {enroll.scrub(msg, [token, *data.values()])[:300]}")
    except (urllib.error.URLError, OSError) as e:
        sys.exit(f"import_central.py: PATCH {ns}/{name} failed: {enroll.scrub(str(e), [token, *data.values()])[:200]}")


def import_central(party, ns, kubeconfig, templates, home, keys_out):
    n = enroll.check_target(party, ns)
    pod, nodes = enroll_fsc.NODES[party]
    data = {}
    for node in nodes:
        core = yaml.safe_load(open(f"{templates}/{node}/core.yaml"))
        for rel, src in central_dirs(core, node, home):
            for f in files_of(src):
                key = re.sub(r"[^-._a-zA-Z0-9]", "_", enroll_fsc.secret_key(f"own/{rel}/{os.path.relpath(f, src)}"))
                if not KEY.match(key) or key in data:
                    sys.exit(f"import_central.py: {key!r} is not a valid or is a duplicate Secret key (file names collide after sanitizing)")
                with open(f, "rb") as fh:
                    data[key] = base64.b64encode(fh.read()).decode()
    if not data:
        sys.exit("import_central.py: nothing to import for this org")
    api_patch(kubeconfig, ns, f"rdbi-{pod}-files", data)
    with open(keys_out, "w") as f:
        json.dump(sorted(data), f)


if __name__ == "__main__":
    a = sys.argv[1:]
    try:
        party, ns = a[0], a[1]
        opt = dict(zip(a[2::2], a[3::2]))
        import_central(party, ns, opt["--kubeconfig"], opt["--templates"], opt["--home"], opt["--keys-out"])
    except (IndexError, KeyError):
        sys.exit(__doc__)
