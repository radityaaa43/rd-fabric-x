#!/usr/bin/env python3
"""Hygiene check (repo is PUBLIC): fail when a tracked text file contains the name of a namespace that belongs to another team.
The names are NOT stored here: only sha256 hashes of whole tokens ([A-Za-z0-9_-]+, lower-cased). The report prints file:line counts, never the token.
Run: python3 scripts/hygiene-foreign-ns.py   (exit 1 on any hit). Self-test: python3 scripts/hygiene-foreign-ns.py --selftest"""
import hashlib, re, subprocess, sys, tempfile, os
HASHES = {
    "13b1551e96407ef52e7559cdedd10e5ab6fb599ad13ae56f8984a98760454ca3",
    "605d472654e64696aa40782437de4325b6a9cb0b6747e34577fd5aab9deebad2",
    "66aa8240a419bd66c6f3bf820b249e63a1fb6a72c21dea3949148e5ed006743d",
    "7d14fb0d171ad6c3cdb13519526676988473c851405dabc702d58c69fc1f1346",
    "841b31a53238528cd6b01b5b29ff5cf34a6ddb3e161d85aa99a7434d1788a95d",
    "848809b6eb972a2ddb30f37a725b6b2cd2391d23519983970dcf1dc4e278882c",
    "8d7470fe494a646c61facd0314398655d980013410f1a626734563fc2255b890",
    "927674d0cee6c4473fb8fc93566ee6189ff3663cfdb5fd6fd2a2de6c698683dd",
    "946d1ef8fc83f200e6bb4d0015541c01a1022c918fc2969d113e034c56614de5",
    "b61d28fe2b44f952f3b64f077ebae1c4c462782749686dbe4fd60520f41c1c3d",
    "bec71910bc9b32b5faaf9996b1856fc03daedb15e60711bb96b1575e9b43f5e5",
    "bfd668f1abb2969c29fdc59fe5aa248d9bb016b76958c93fcac7bc3266b48810",
    "e530b52ebc196e6b8ecece6cb40c7670ba0ed321f46c363158b6bad11d240550",
}
TOKEN = re.compile(r"[A-Za-z0-9_-]+")
def hits_in(text):
    out = []
    for n, line in enumerate(text.split("\n"), 1):
        k = sum(1 for t in TOKEN.findall(line) if hashlib.sha256(t.lower().encode()).hexdigest() in HASHES)
        if k: out.append((n, k))
    return out
def scan(root):
    files = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True, check=True).stdout.split("\n")
    bad = 0
    for f in files:
        p = os.path.join(root, f)
        if not f or not os.path.isfile(p): continue
        try: txt = open(p, encoding="utf-8").read()
        except Exception: continue  # binary
        for n, k in hits_in(txt):
            print(f"HYGIENE FAIL {f}:{n} ({k} foreign namespace name(s); token not printed)"); bad += k
    return bad
def selftest():
    probe = "fabricx" + "-bi"  # built at runtime: the literal never sits in this file
    assert hits_in("ok line\nnothing here: besu, paladin, rd-zeto-bi")  == [], "false positive"
    assert hits_in(f"x\nuse `{probe}` here") == [(2, 1)], "missed a foreign name"
    assert hits_in(f"{probe}-extra") == [], "token boundary wrong"
    print("selftest ok")
if __name__ == "__main__":
    if "--selftest" in sys.argv: selftest(); sys.exit(0)
    bad = scan(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    print("hygiene: %d foreign namespace name(s) in the tracked tree" % bad)
    sys.exit(1 if bad else 0)
