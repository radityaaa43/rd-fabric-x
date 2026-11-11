#!/usr/bin/env python3
"""Own-only import of the CENTRAL FSC material into rdbi-<pod>-files (fabricx S13 piece 4; interim until S15).

usage: import_central.py <party> rd-fabricx-<party> --kubeconfig K --templates <live dir with <node>/core.yaml> --home <~/.fabricx-token> --keys-out <file.json>
What stays central until S15 (PLAN S13 interim custody note): ids/anon/msp (the shared Idemix submitter material), the Idemix owner wallet of each bank node and the
issuer wallet MSP. For each node of the org this reads ONLY the directories that node's own core.yaml names (core_rewrite.per_org_core), never another node's, refuses symlinks
and an empty directory, and adds the files to the org's Secret rdbi-<pod>-files with `kubectl patch --type merge --patch-file /dev/stdin` (party-admin may patch; values only on
stdin, never argv). --keys-out receives the key NAMES (JSON list) that render.py takes as --central-keys; no value is ever written there.
Key = "own__<node>__<path below the node dir with / as __>", the same naming as enroll_fsc.secret_key().
"""
import base64, json, os, re, subprocess, sys

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


def import_central(party, ns, kubeconfig, templates, home, keys_out):
    n = enroll.check_target(party, ns)
    pod, nodes = enroll_fsc.NODES[party]
    data = {}
    for node in nodes:
        core = yaml.safe_load(open(f"{templates}/{node}/core.yaml"))
        for rel, src in central_dirs(core, node, home):
            for f in files_of(src):
                key = enroll_fsc.secret_key(f"own/{rel}/{os.path.relpath(f, src)}")
                if not KEY.match(key):
                    sys.exit(f"import_central.py: {key!r} is not a valid Secret key")
                with open(f, "rb") as fh:
                    data[key] = base64.b64encode(fh.read()).decode()
    if not data:
        sys.exit("import_central.py: nothing to import for this org")
    enroll.sh("kubectl", "--kubeconfig", kubeconfig, "-n", ns, "patch", "secret", f"rdbi-{pod}-files", "--type", "merge", "--patch-file", "/dev/stdin",
              stdin=json.dumps({"data": data}), secrets=list(data.values()))
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
