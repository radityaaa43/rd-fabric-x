"""Offline test for check_exchange.py (fabricx S9 public-material exchange): fake trees, no cluster.

  python3 -m unittest discover -s multiorg        (needs PyYAML)
"""
import hashlib, os, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
ROLES = ("router", "batcher1", "consenter", "assembler")


def write(root, rel, data):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(data)


def manifest(root):
    lines = []
    for d, _, names in sorted(os.walk(root)):
        for n in sorted(names):
            if n != "MANIFEST.sha256":
                p = os.path.join(d, n)
                lines.append(f"{hashlib.sha256(open(p, 'rb').read()).hexdigest()}  {os.path.relpath(p, root)}\n")
    write(root, "MANIFEST.sha256", "".join(sorted(lines)))


def good_tree(root, n=2):
    write(root, "msp/cacerts/ca.pem", CERT)
    write(root, "msp/tlscacerts/tlsca.pem", CERT)
    for r in ROLES:
        write(root, f"orderers/party{n}/{r}/tls/server.crt", CERT)
        if r in ("batcher1", "consenter"):
            write(root, f"orderers/party{n}/{r}/msp/signcerts/{r}-cert.pem", CERT)
    write(root, "endpoints.yaml", yaml.safe_dump({r: {"Host": f"{r}-{n}.rd-fabricx-bank-a.svc", "Port": 7000 + i} for i, r in enumerate(ROLES)}))
    manifest(root)


def check(root, n=2):
    return subprocess.run([sys.executable, os.path.join(HERE, "check_exchange.py"), root, str(n)], capture_output=True, text=True)


class Exchange(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "org2")
        good_tree(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_good_tree_passes(self):
        r = check(self.root)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_private_key_content_is_refused(self):
        write(self.root, "orderers/party2/router/tls/key.pem", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
        manifest(self.root)
        r = check(self.root)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("PRIVATE KEY", r.stderr)

    def test_key_file_name_is_refused(self):
        write(self.root, "orderers/party2/router/msp/keystore/abc_sk", "x")
        manifest(self.root)
        self.assertNotEqual(check(self.root).returncode, 0)

    def test_missing_role_is_refused(self):
        for r in ROLES:
            with self.subTest(role=r):
                t = tempfile.TemporaryDirectory()
                root = os.path.join(t.name, "org2")
                good_tree(root)
                subprocess.run(["rm", "-r", os.path.join(root, f"orderers/party2/{r}")], check=True)
                manifest(root)
                self.assertNotEqual(check(root).returncode, 0)
                t.cleanup()

    def test_missing_ca_or_endpoint_is_refused(self):
        for rel in ("msp/cacerts/ca.pem", "msp/tlscacerts/tlsca.pem", "endpoints.yaml"):
            with self.subTest(missing=rel):
                t = tempfile.TemporaryDirectory()
                root = os.path.join(t.name, "org2")
                good_tree(root)
                os.remove(os.path.join(root, rel))
                manifest(root)
                self.assertNotEqual(check(root).returncode, 0)
                t.cleanup()

    def test_changed_file_breaks_manifest(self):
        write(self.root, "msp/cacerts/ca.pem", CERT + "# tampered\n")
        r = check(self.root)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MANIFEST", r.stderr)

    def test_admincerts_required_only_when_asked(self):
        import importlib; ce = importlib.import_module("check_exchange")
        self.assertEqual(ce.problems(self.root, 2), [])                                   # default: not required (B3 trees)
        self.assertIn("missing msp/admincerts/*.pem", ce.problems(self.root, 2, require_admin=True))
        write(self.root, "msp/admincerts/admin-2-cert.pem", CERT)
        manifest(self.root)
        self.assertEqual(ce.problems(self.root, 2, require_admin=True), [])
        write(self.root, "msp/admincerts/admin-2-cert.pem", "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n")
        manifest(self.root)
        self.assertTrue(any("private key" in p for p in ce.problems(self.root, 2, require_admin=True)))

    def test_knowncerts_required_only_when_asked(self):
        import importlib; ce = importlib.import_module("check_exchange")
        self.assertIn("missing msp/knowncerts/*.pem", ce.problems(self.root, 2, require_known=True))
        write(self.root, "msp/knowncerts/endorser-2-cert.pem", CERT)
        manifest(self.root)
        self.assertEqual(ce.problems(self.root, 2, require_known=True), [])
        self.assertEqual(ce.problems(self.root, 2), [])

    def test_wrong_party_number_is_refused(self):
        self.assertNotEqual(check(self.root, 3).returncode, 0)


if __name__ == "__main__":
    unittest.main()
