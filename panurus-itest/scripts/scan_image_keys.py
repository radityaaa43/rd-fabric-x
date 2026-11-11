#!/usr/bin/env python3
"""Fail if any layer of a `docker save` archive holds a PEM private key block (S15 gate b: the rdbi-node image carries no key material).

usage: scan_image_keys.py image.tar [--allow FILE --dockerfile FILE]
--allow FILE: a line `base <image@sha256:digest>` plus lines `<path in the layer> <sha256 of that file>` (# comments). The allow-list only applies under that base: --dockerfile FILE is
required and its FROM must equal the `base` line byte for byte (a tag, a changed digest, a missing line: exit 3, nothing is scanned). A hit in exactly that file with exactly that content is reported as allowed (it is a known benign
file of the pinned base image) and does not fail; any other hit still does. Exit 0 = clean, 1 = a PEM private key block was found (the file name is printed, never the key), 2 = the archive could not be read (fail closed).
A block is `-----BEGIN [<kind> ]PRIVATE KEY-----` + base64 body + the matching END line, so a certificate, or the words in a Go string, do not match."""
import hashlib, json, re, sys, tarfile

KEY = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\r\n :,.-]{40,}?-----END [A-Z ]*PRIVATE KEY-----")


def load_allow(path):
    base, allow = None, {}
    for line in open(path):
        if line.strip() and not line.startswith("#"):
            f = line.split()
            if f[0] == "base":
                if len(f) != 2 or not re.fullmatch(r"\S+@sha256:[0-9a-f]{64}", f[1]) or base:
                    raise ValueError("one `base <image@sha256:digest>` line")
                base = f[1]
            elif len(f) != 2 or not re.fullmatch(r"[0-9a-f]{64}", f[1]):
                raise ValueError("allow file line must be: <path> <sha256>")
            else:
                allow[f[0]] = f[1]
    return base, allow


def dockerfile_base(path):
    froms = [l.split()[1] for l in open(path) if l.startswith("FROM ")]
    return froms[0] if len(froms) == 1 else None


def main(path, allow_path=None, dockerfile=None):
    allow = {}
    if allow_path:
        base, allow = load_allow(allow_path)
        found = dockerfile_base(dockerfile) if dockerfile else None
        if not base or not dockerfile or found != base:
            print(f"scan_image_keys.py: the allow-list is for base {base!r}; the Dockerfile FROM is {found!r}: refusing (fail closed)", file=sys.stderr)
            return 3
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
        args = (a[0], None, None)
    elif len(a) == 3 and a[1] == "--allow":
        args = (a[0], a[2], None)
    elif len(a) == 5 and a[1] == "--allow" and a[3] == "--dockerfile":
        args = (a[0], a[2], a[4])
    else:
        sys.exit("usage: scan_image_keys.py image.tar [--allow FILE --dockerfile FILE]")
    try:
        sys.exit(main(*args))
    except (OSError, KeyError, ValueError, tarfile.TarError) as e:
        print(f"scan_image_keys.py: cannot read the archive: {type(e).__name__}", file=sys.stderr)
        sys.exit(2)
