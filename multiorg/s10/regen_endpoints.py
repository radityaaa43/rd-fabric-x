#!/usr/bin/env python3
"""Regenerate each org's endpoints.yaml from the port plan and a host template, into a COPY of the exchange trees (fabricx S10 prep).

usage: regen_endpoints.py --exchange DIR --out NEWDIR --lb-host-template '{role}-{n}.lb.{party}'
Ports come from PORT_PLAN (multiorg/fca/enroll.py: assembler 8011, consenter 8012, router 8013, batcher1 8014). Hosts come from the template
(placeholders `*.lb.<party>` until S16 gives the real LB hosts; a build with placeholders is a --dry-run only). The copy gets a new
MANIFEST.sha256 per org: the printed hashes are what each org must announce again and what `build_genesis.py --heads` takes.
The source trees are never modified; NEWDIR must not exist.
"""
import hashlib, json, os, re, shutil, sys
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "fca"))
import check_exchange
import enroll


def die(msg):
    sys.exit(f"regen_endpoints.py: {msg}")


def write_manifest(root):
    lines = sorted(f"{hashlib.sha256(open(p, 'rb').read()).hexdigest()}  {os.path.relpath(p, root)}\n"
                   for d, _, names in os.walk(root) for x in names if x != "MANIFEST.sha256" for p in [os.path.join(d, x)])
    with open(os.path.join(root, "MANIFEST.sha256"), "w") as f:
        f.write("".join(lines))
    with open(os.path.join(root, "MANIFEST.sha256"), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def regen(src, dst, template):
    if os.path.realpath(src) == os.path.realpath(dst) or os.path.exists(dst):
        die(f"{dst} must be a new directory (the source trees are never modified)")
    if not any(v in template for v in ("{role}", "{n}", "{party}")):
        die("the host template must contain {role}, {n} or {party}: one host per role and party")
    parties = sorted(int(d[3:]) for d in os.listdir(src) if re.fullmatch(r"org\d+", d))
    names = {n: p for p, n in enroll.PARTY_N.items()}
    plan = {}
    for n in parties:
        problems = check_exchange.problems(f"{src}/org{n}", n)
        if problems:
            die(f"org{n} exchange tree is not clean: {'; '.join(problems[:3])}")
        if n not in names:
            die(f"org{n} is not one of {sorted(names)}")
        roles = yaml.safe_load(open(f"{src}/org{n}/endpoints.yaml"))
        ep = {}
        for role in roles:
            if role not in enroll.PORT_PLAN:
                die(f"org{n}: role {role!r} has no port in the plan {sorted(enroll.PORT_PLAN)}")
            try:
                host = template.format(role=role, n=n, party=names[n])
            except (KeyError, IndexError, ValueError):
                die(f"bad host template {template!r}")
            enroll.check_san(host)
            ep[role] = {"Host": host, "Port": enroll.PORT_PLAN[role]}
        plan[n] = ep
    shutil.copytree(src, dst)
    heads = {}
    for n, ep in plan.items():
        with open(f"{dst}/org{n}/endpoints.yaml", "w") as f:
            yaml.safe_dump(ep, f)
        heads[n] = write_manifest(f"{dst}/org{n}")
    return heads


if __name__ == "__main__":
    a, opt = sys.argv[1:], {}
    while len(a) >= 2 and a[0].startswith("--"):
        opt[a[0]], a = a[1], a[2:]
    if a or not {"--exchange", "--out", "--lb-host-template"} <= set(opt):
        sys.exit(__doc__)
    heads = regen(opt["--exchange"], opt["--out"], opt["--lb-host-template"])
    print(json.dumps({"out": opt["--out"], "heads": ",".join(f"{n}={h}" for n, h in sorted(heads.items()))}, indent=1))
