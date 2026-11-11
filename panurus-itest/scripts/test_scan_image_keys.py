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


class Allow(unittest.TestCase):
    """the one known benign hit of the pinned Debian base (libgnutls30 embeds a PKCS8 self-test key): allowed by path AND file sha256, and only under the pinned base (Dockerfile FROM must equal the `base` line)"""
    BASE = "debian:bookworm-slim@sha256:" + "ab" * 32

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.p = os.path.join(self.d.name, "image.tar")
        self.lib = b"ELF" + KEY + b"tail"
        self.allow = os.path.join(self.d.name, "allow.txt")
        self.dockerfile = os.path.join(self.d.name, "Dockerfile")
        self.from_dockerfile(self.BASE)

    def tearDown(self):
        self.d.cleanup()

    def from_dockerfile(self, ref):
        with open(self.dockerfile, "w") as f:
            f.write(f"# comment\nFROM {ref}\nRUN true\n")

    def allow_line(self, path, data, base=BASE):
        with open(self.allow, "w") as f:
            f.write("# comment\n" + (f"base {base}\n" if base else "") + f"{path} {hashlib.sha256(data).hexdigest()}\n")

    def run_scan(self, dockerfile=True):
        a = [sys.executable, "-I", os.path.join(HERE, "scan_image_keys.py"), self.p, "--allow", self.allow]
        if dockerfile:
            a += ["--dockerfile", self.dockerfile]
        return subprocess.run(a, capture_output=True, text=True)

    def test_listed_path_and_hash_is_allowed_and_reported(self):
        image_tar(self.p, [{"usr/lib/libgnutls.so": self.lib}, {"usr/local/bin/x": b"clean"}])
        self.allow_line("usr/lib/libgnutls.so", self.lib)
        r = self.run_scan()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("allowed (base image): usr/lib/libgnutls.so", r.stdout)
        self.assertIn("0 private key blocks outside the allow-list", r.stdout)

    def test_changed_base_digest_in_the_dockerfile_fails_closed(self):
        image_tar(self.p, [{"usr/lib/libgnutls.so": self.lib}])
        self.allow_line("usr/lib/libgnutls.so", self.lib)
        self.from_dockerfile("debian:bookworm-slim@sha256:" + "cd" * 32)   # a base bump with the allow file still present
        r = self.run_scan()
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("allowed (base image)", r.stdout)

    def test_a_tag_instead_of_a_digest_fails_closed(self):
        image_tar(self.p, [{"a": b"x"}])
        self.allow_line("usr/lib/libgnutls.so", self.lib)
        self.from_dockerfile("debian:bookworm-slim")
        self.assertNotEqual(self.run_scan().returncode, 0)

    def test_allow_file_without_base_line_or_without_dockerfile_fails_closed(self):
        image_tar(self.p, [{"a": b"x"}])
        self.allow_line("usr/lib/libgnutls.so", self.lib, base=None)
        self.assertNotEqual(self.run_scan().returncode, 0)
        self.allow_line("usr/lib/libgnutls.so", self.lib)
        self.assertNotEqual(self.run_scan(dockerfile=False).returncode, 0)

    def test_same_path_other_content_fails(self):
        image_tar(self.p, [{"usr/lib/libgnutls.so": self.lib + b"changed"}])
        self.allow_line("usr/lib/libgnutls.so", self.lib)
        self.assertEqual(self.run_scan().returncode, 1)

    def test_same_content_other_path_fails(self):
        image_tar(self.p, [{"home/rdbi/key.pem": self.lib}])
        self.allow_line("usr/lib/libgnutls.so", self.lib)
        self.assertEqual(self.run_scan().returncode, 1)

    def test_another_key_next_to_the_allowed_file_fails(self):
        image_tar(self.p, [{"usr/lib/libgnutls.so": self.lib, "home/rdbi/own.pem": KEY}])
        self.allow_line("usr/lib/libgnutls.so", self.lib)
        r = self.run_scan()
        self.assertEqual(r.returncode, 1)
        self.assertIn("home/rdbi/own.pem", r.stdout)

    def test_malformed_allow_file_fails_closed(self):
        image_tar(self.p, [{"a": b"x"}])
        with open(self.allow, "w") as f:
            f.write(f"base {self.BASE}\nonly-one-field\n")
        self.assertEqual(self.run_scan().returncode, 2)


class PatchAllowList(unittest.TestCase):
    def test_workflow_every_run_step_has_pipefail(self):
        # the first run printed "1 private key blocks" and the step still passed: `cmd | tee` has the exit status of tee unless pipefail is on.
        # Workflow-level `defaults: run: shell: bash` makes GitHub run EVERY run step as `bash -eo pipefail`; no step may override it.
        import yaml
        wf = yaml.safe_load(open(os.path.join(os.path.dirname(os.path.dirname(HERE)), ".github", "workflows", "rdbi-image.yml")))
        self.assertEqual(wf["defaults"], {"run": {"shell": "bash"}})
        runs = [s for s in wf["jobs"]["image"]["steps"] if "run" in s]
        self.assertGreaterEqual(len(runs), 6)
        for s in runs:
            self.assertIn(s.get("shell", "bash"), ("bash",), s.get("name"))
        self.assertNotIn("defaults", wf["jobs"]["image"])   # a job-level default would override the workflow one
        scan = [s for s in runs if s.get("name", "").startswith("Scan the image layers")][0]["run"]
        self.assertIn("--allow panurus-itest/k8s/scan-allow.txt", scan)
        self.assertIn("--dockerfile panurus-itest/k8s/Dockerfile", scan)

    def test_scan_allow_list_is_one_pinned_base_file(self):
        lines = [l.split() for l in open(os.path.join(os.path.dirname(HERE), "k8s", "scan-allow.txt")) if l.strip() and not l.startswith("#")]
        base = [l for l in lines if l[0] == "base"]
        files = [l for l in lines if l[0] != "base"]
        self.assertEqual(files, [["usr/lib/x86_64-linux-gnu/libgnutls.so.30.34.3", "779b25d20249988bea2c1aa6bbeb218f5ae7ea8a9d30ce4f54ea37372965cc4b"]])
        self.assertEqual(len(base), 1)
        froms = [l.split()[1] for l in open(os.path.join(os.path.dirname(HERE), "k8s", "Dockerfile")) if l.startswith("FROM ")]
        self.assertEqual(froms, [base[0][1]])   # the allow file and the Dockerfile name the same pinned base

    def test_accepted_file_matches_the_patches_exactly(self):
        lines = [l.split() for l in open(os.path.join(PATCHES, "ACCEPTED.sha256")) if l.strip() and not l.startswith("#")]
        want = {name: h for h, name in lines}
        have = {n: hashlib.sha256(open(os.path.join(PATCHES, n), "rb").read()).hexdigest() for n in os.listdir(PATCHES) if n.endswith(".patch")}
        self.assertEqual(have, want)   # an extra, missing or modified patch fails here and in the workflow
        self.assertEqual(len(want), 5)   # 4 Panurus patches + the FSC full-certificate patch (README deviation 1)


if __name__ == "__main__":
    unittest.main()
