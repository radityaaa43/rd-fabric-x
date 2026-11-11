#!/usr/bin/env python3
"""Fail if any layer of a `docker save` archive holds a PEM private key block (S15 gate b: the rdbi-node image carries no key material).

usage: scan_image_keys.py image.tar [--allow FILE]
--allow FILE: lines `<path in the layer> <sha256 of that file>` (# comments): a hit in exactly that file with exactly that content is reported as allowed (it is a known benign
file of the pinned base image) and does not fail; any other hit still does. Exit 0 = clean, 1 = a PEM private key block was found (the file name is printed, never the key), 2 = the archive could not be read (fail closed).
A block is `-----BEGIN [<kind> ]PRIVATE KEY-----` + base64 body + the matching END line, so a certificate, or the words in a Go string, do not match."""
import hashlib, json, re, sys, tarfile

KEY = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\r\n :,.-]{40,}?-----END [A-Z ]*PRIVATE KEY-----")


def load_allow(path):
    allow = {}
    for line in open(path):
        if line.strip() and not line.startswith("#"):
            f = line.split()
            if len(f) != 2 or not re.fullmatch(r"[0-9a-f]{64}", f[1]):
                raise ValueError("allow file line must be: <path> <sha256>")
            allow[f[0]] = f[1]
    return allow


def main(path, allow_path=None):
    allow = load_allow(allow_path) if allow_path else {}
    hits, allowed, files, layers = [], [], 0, 0
    with tarfile.open(path) as outer:
        manifest = json.load(outer.extractfile("manifest.json"))
        for entry in manifest:
            for ln in entry["Layers"]:
                layers += 1
                with tarfile.open(fileobj=outer.extractfile(ln)) as layer:
                    for m in layer:
                        if not m.isfile():
                            continue
                        files += 1
                        data = layer.extractfile(m).read()
                        if KEY.search(data):
                            if allow.get(m.name) == hashlib.sha256(data).hexdigest():
                                allowed.append(m.name)
                            else:
                                hits.append((layers, m.name))
    for n, name in hits:
        print(f"PRIVATE KEY block in layer {n}: {name}")
    for name in allowed:
        print(f"allowed (base image): {name}")
    print(f"scan: {layers} layers, {files} files, {len(hits)} private key blocks outside the allow-list" if allow_path else f"scan: {layers} layers, {files} files, {len(hits)} private key blocks")
    return 1 if hits else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 1:
        args = (a[0], None)
    elif len(a) == 3 and a[1] == "--allow":
        args = (a[0], a[2])
    else:
        sys.exit("usage: scan_image_keys.py image.tar [--allow FILE]")
    try:
        sys.exit(main(*args))
    except (OSError, KeyError, ValueError, tarfile.TarError) as e:
        print(f"scan_image_keys.py: cannot read the archive: {type(e).__name__}", file=sys.stderr)
        sys.exit(2)
