"""Tests for scan_image_keys.py (S15 gate b: no key material in the rdbi-node image layers) and the patch allow-list (gate a). No docker, no network.

  python3 -m unittest discover -s panurus-itest/scripts
"""
import hashlib, io, json, os, subprocess, sys, tarfile, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PATCHES = os.path.join(os.path.dirname(HERE), "patches")
KEY = b"-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA" + b"A" * 60 + b"\n-----END EC PRIVATE KEY-----\n"


def layer(files):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return b.getvalue()


def image_tar(path, layers):
    """a `docker save`-shaped archive: manifest.json + one tar per layer"""
    with tarfile.open(path, "w") as t:
        names = []
        for i, files in enumerate(layers):
            data = layer(files)
            n = f"blobs/{i}/layer.tar"
            ti = tarfile.TarInfo(n)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
            names.append(n)
        m = json.dumps([{"Config": "c.json", "RepoTags": ["scan:local"], "Layers": names}]).encode()
        ti = tarfile.TarInfo("manifest.json")
        ti.size = len(m)
        t.addfile(ti, io.BytesIO(m))


def scan(path):
    return subprocess.run([sys.executable, "-I", os.path.join(HERE, "scan_image_keys.py"), path], capture_output=True, text=True)


class Scan(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.p = os.path.join(self.d.name, "image.tar")

    def tearDown(self):
        self.d.cleanup()

    def test_clean_image_passes(self):
        image_tar(self.p, [{"usr/local/bin/rdbi-node": b"\x7fELF" + os.urandom(2000)}, {"etc/passwd": b"rdbi:x:10001\n"}])
        r = scan(self.p)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("2 layers", r.stdout)

    def test_pem_private_key_in_any_layer_fails_and_names_the_file_not_the_key(self):
        image_tar(self.p, [{"a": b"x"}, {"home/rdbi/.fabricx-token/own/k.pem": b"junk" + KEY}])
        r = scan(self.p)
        self.assertEqual(r.returncode, 1)
        self.assertIn("home/rdbi/.fabricx-token/own/k.pem", r.stdout)
        self.assertNotIn("MHcCAQEEIA", r.stdout + r.stderr)

    def test_all_pem_private_key_kinds_are_found(self):
        for kind in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY"):
            blob = f"-----BEGIN {kind}-----\n".encode() + b"QUJD" * 20 + f"\n-----END {kind}-----\n".encode()
            image_tar(self.p, [{"k": blob}])
            self.assertEqual(scan(self.p).returncode, 1, kind)

    def test_a_certificate_or_a_header_word_alone_is_not_a_hit(self):
        cert = b"-----BEGIN CERTIFICATE-----\n" + b"QUJD" * 20 + b"\n-----END CERTIFICATE-----\n"
        image_tar(self.p, [{"c.pem": cert, "go-string": b"x509: failed to parse PRIVATE KEY block"}])
        self.assertEqual(scan(self.p).returncode, 0)

    def test_unreadable_archive_fails_closed(self):
        with open(self.p, "wb") as f:
            f.write(b"not a tar")
        self.assertNotEqual(scan(self.p).returncode, 0)


class PatchAllowList(unittest.TestCase):
    def test_accepted_file_matches_the_patches_exactly(self):
        lines = [l.split() for l in open(os.path.join(PATCHES, "ACCEPTED.sha256")) if l.strip() and not l.startswith("#")]
        want = {name: h for h, name in lines}
        have = {n: hashlib.sha256(open(os.path.join(PATCHES, n), "rb").read()).hexdigest() for n in os.listdir(PATCHES) if n.endswith(".patch")}
        self.assertEqual(have, want)   # an extra, missing or modified patch fails here and in the workflow
        self.assertEqual(len(want), 5)   # 4 Panurus patches + the FSC full-certificate patch (README deviation 1)


if __name__ == "__main__":
    unittest.main()
