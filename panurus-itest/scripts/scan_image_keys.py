#!/usr/bin/env python3
"""Fail if any layer of a `docker save` archive holds a PEM private key block (S15 gate b: the rdbi-node image carries no key material).

usage: scan_image_keys.py image.tar
Exit 0 = clean, 1 = a PEM private key block was found (the file name is printed, never the key), 2 = the archive could not be read (fail closed).
A block is `-----BEGIN [<kind> ]PRIVATE KEY-----` + base64 body + the matching END line, so a certificate, or the words in a Go string, do not match."""
import json, re, sys, tarfile

KEY = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\r\n :,.-]{40,}?-----END [A-Z ]*PRIVATE KEY-----")


def main(path):
    hits, files, layers = [], 0, 0
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
                            hits.append((layers, m.name))
    for n, name in hits:
        print(f"PRIVATE KEY block in layer {n}: {name}")
    print(f"scan: {layers} layers, {files} files, {len(hits)} private key blocks")
    return 1 if hits else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: scan_image_keys.py image.tar")
    try:
        sys.exit(main(sys.argv[1]))
    except (OSError, KeyError, ValueError, tarfile.TarError) as e:
        print(f"scan_image_keys.py: cannot read the archive: {type(e).__name__}", file=sys.stderr)
        sys.exit(2)
