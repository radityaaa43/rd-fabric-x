#!/usr/bin/env python3
"""Check one org's public-material exchange directory (fabricx S9, RUNBOOK-S9-party-keys.md section 4).

usage: check_exchange.py <exchange/org<N>> <N>
Exit 0 only if: required public files exist, no private key material is present (by content or by name),
endpoints.yaml names every role, and MANIFEST.sha256 matches the files. Prints the first problems to stderr.
"""
import glob, hashlib, os, sys
import yaml


def problems(root, n):
    out = []
    must = ["msp/cacerts/*.pem", "msp/tlscacerts/*.pem"]
    base = f"orderers/party{n}"
    roles = sorted(os.path.basename(p) for p in glob.glob(f"{root}/{base}/*"))
    for need in ("router", "consenter", "assembler"):
        if need not in roles:
            out.append(f"missing role dir {base}/{need}")
    if not [r for r in roles if r.startswith("batcher")]:
        out.append(f"missing role dir {base}/batcher<k>")
    for r in roles:
        must.append(f"{base}/{r}/tls/*.pem")
        if r.startswith("batcher") or r == "consenter":
            must.append(f"{base}/{r}/msp/signcerts/*.pem")
    out += [f"missing {m}" for m in must if not glob.glob(f"{root}/{m}")]
    try:
        ep = yaml.safe_load(open(f"{root}/endpoints.yaml"))
        out += [f"endpoints.yaml: {r} needs Host and Port" for r in roles if not isinstance(ep.get(r), dict) or not {"Host", "Port"} <= set(ep[r])]
    except (OSError, AttributeError, yaml.YAMLError):
        out.append("endpoints.yaml missing or not a mapping")
    listed = {}
    try:
        for line in open(f"{root}/MANIFEST.sha256"):
            h, rel = line.rstrip("\n").split("  ", 1)
            listed[rel] = h
    except (OSError, ValueError):
        out.append("MANIFEST.sha256 missing or malformed")
    seen = set()
    for d, _, names in os.walk(root):
        for name in names:
            p = os.path.join(d, name)
            rel = os.path.relpath(p, root)
            if rel == "MANIFEST.sha256":
                continue
            seen.add(rel)
            data = open(p, "rb").read()
            if b"PRIVATE KEY" in data or name.endswith("_sk") or "keystore" in rel.split(os.sep):
                out.append(f"private key material: {rel} (PRIVATE KEY / keystore / *_sk)")
            if listed and listed.get(rel) != hashlib.sha256(data).hexdigest():
                out.append(f"MANIFEST.sha256 does not match {rel}")
    out += [f"MANIFEST.sha256 lists {rel} which is not there" for rel in listed if rel not in seen]
    return out


if __name__ == "__main__":
    if len(sys.argv) != 3 or not sys.argv[2].isdigit():
        sys.exit(__doc__)
    found = problems(sys.argv[1], int(sys.argv[2]))
    for p in found[:20]:
        print(p, file=sys.stderr)
    sys.exit(1 if found else 0)
