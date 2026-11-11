"""Offline tests for multiorg/gw/enroll_gw.py (fabricx S16 custody: gateway identities and Secrets). Stub fabric-ca-client and kubectl on PATH (multiorg/fca/test_fca.py).

  python3 -m unittest discover -s multiorg/gw
"""
import os, shutil, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "fca"))
sys.path.insert(0, HERE)
import enroll
import enroll_gw
import test_fca as tf   # FCA_STUB, KUBECTL_STUB

CERT = "-----BEGIN CERTIFICATE-----\nMII{}\n-----END CERTIFICATE-----\n"


def make_inputs(root):
    for m in (1, 2, 3, 4):
        p = f"{root}/tlsx/org{m}/msp/tlscacerts/tlsca.pem"
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(CERT.format(f"TLSCA{m}"))
    with open(f"{root}/lensa-ca.pem", "w") as f:
        f.write(CERT.format("LENSA2"))


class Flow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bin, self.log = os.path.join(self.tmp.name, "bin"), os.path.join(self.tmp.name, "log")
        os.makedirs(self.bin)
        os.makedirs(self.log)
        for name, body in (("fabric-ca-client", tf.FCA_STUB), ("kubectl", tf.KUBECTL_STUB)):
            p = os.path.join(self.bin, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
        self.env = {k: os.environ.get(k) for k in ("PATH", "STUB_LOG", "STUB_FAIL")}
        os.environ["PATH"] = self.bin + ":" + os.environ["PATH"]
        os.environ["STUB_LOG"] = self.log
        os.environ.pop("STUB_FAIL", None)
        self.work = tempfile.mkdtemp(dir="/dev/shm")
        os.rmdir(self.work)
        make_inputs(self.tmp.name)
        self.tls, self.lensa = f"{self.tmp.name}/tlsx", f"{self.tmp.name}/lensa-ca.pem"
        self.out = os.path.join(self.tmp.name, "gw-exchange", "org2")

    def tearDown(self):
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        if os.path.exists(self.work):
            enroll.destroy(self.work)
        self.tmp.cleanup()

    def logtext(self, name):
        p = os.path.join(self.log, name)
        return open(p).read() if os.path.exists(p) else ""

    def run_make(self, party="bank-a", ns="rd-fabricx-bank-a", out=None, **kw):
        enroll.init(party, ns, "/k", self.work)
        enroll_gw.make(party, ns, "/k", "http://localhost:7054", self.work, self.tls, self.lensa, out or self.out, **kw)

    def secrets(self):
        t = self.logtext("kubectl-stdin.log")
        docs = yaml.safe_load(t)
        return {d["metadata"]["name"]: d for d in docs["items"]}

    def test_four_secrets_with_exact_keys(self):
        self.run_make()
        s = self.secrets()
        self.assertEqual(sorted(s), ["fx-gw-2-client", "fx-gw-2-client-ca", "fx-gw-2-peer", "fx-gw-2-server"])
        self.assertEqual(sorted(s["fx-gw-2-server"]["stringData"]), ["tls.crt", "tls.key"])
        self.assertEqual(sorted(s["fx-gw-2-peer"]["stringData"]), ["tls.crt", "tls.key"])
        self.assertEqual(sorted(s["fx-gw-2-client"]["stringData"]), ["gw.key"])
        self.assertEqual(sorted(s["fx-gw-2-client-ca"]["stringData"]), ["ca.crt"])
        for d in s.values():
            self.assertEqual(d["metadata"]["namespace"], "rd-fabricx-bank-a")
            self.assertEqual(d["type"], "Opaque")
        self.assertNotIn("PRIVATE KEY", s["fx-gw-2-client-ca"]["stringData"]["ca.crt"])
        self.assertIn("PRIVATE KEY", s["fx-gw-2-client"]["stringData"]["gw.key"])

    def test_client_ca_is_lensa_plus_the_four_tls_cas(self):
        self.run_make()
        ca = self.secrets()["fx-gw-2-client-ca"]["stringData"]["ca.crt"]
        self.assertEqual(ca, "".join(CERT.format(x) for x in ("LENSA2", "TLSCA1", "TLSCA2", "TLSCA3", "TLSCA4")))

    def test_identities_are_clients_at_the_orgs_own_ca(self):
        self.run_make()
        argv = self.logtext("argv.log")
        for who in ("fx-gw-2", "fx-gw-2-peer", "bank2-gw"):
            self.assertIn(f"--id.name {who} ", argv + " ", who)
        self.assertEqual(argv.count("--id.type client"), 3)
        self.assertNotIn("--id.type admin", argv)

    def test_tls_certs_carry_the_gateway_name(self):
        self.run_make()
        tls = [l for l in self.logtext("argv.log").splitlines() if "--enrollment.profile tls" in l and "--csr.hosts" in l]
        self.assertEqual(len(tls), 2)
        for l in tls:
            self.assertIn("fx-gw-2,fx-gw-2.rd-fabricx-bank-a.svc.cluster.local", l)

    def test_public_tree_has_certs_only_and_a_manifest(self):
        self.run_make()
        names = sorted(os.path.relpath(os.path.join(d, x), self.out) for d, _, fs in os.walk(self.out) for x in fs)
        self.assertEqual(names, ["MANIFEST.sha256", "gw/bank2-gw.pem", "gw/fx-gw-2-peer.pem", "gw/fx-gw-2.pem"])
        for n in names:
            self.assertNotIn("PRIVATE KEY", open(os.path.join(self.out, n)).read())

    def test_secrets_never_in_argv_and_files_destroyed(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        pw = open(os.path.join(self.work, "admin.pass")).read().strip()
        enroll_gw.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.tls, self.lensa, self.out)
        argv = self.logtext("argv.log") + self.logtext("kubectl.log")
        for bad in (pw, "ROLESECRET", "--id.secret", "PRIVATE KEY"):
            self.assertNotIn(bad, argv)
        self.assertIn(f"admin:{pw}@localhost", self.logtext("url.log"))
        self.assertFalse(os.path.exists(self.work))

    def test_generation_renames_identities_not_secrets(self):
        self.run_make(generation="g2")
        self.assertIn("--id.name fx-gw-2-g2 ", self.logtext("argv.log") + " ")
        self.assertEqual(sorted(self.secrets())[0], "fx-gw-2-client")

    def test_refusals_create_nothing(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        os.makedirs(self.out)   # an existing out dir is refused
        with self.assertRaises(SystemExit):
            enroll_gw.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.tls, self.lensa, self.out)
        self.assertEqual(self.logtext("kubectl-stdin.log"), "")
        self.assertFalse(os.path.exists(self.work))
        with self.assertRaises(SystemExit):   # work dir outside /dev/shm
            enroll_gw.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", "/tmp/not-shm", self.tls, self.lensa, self.out + "x")
        with self.assertRaises(SystemExit):   # namespace of another org
            enroll_gw.make("bank-a", "rd-fabricx-bank-b", "/k", "http://localhost:7054", self.work, self.tls, self.lensa, self.out + "y")
        with open(self.lensa, "w") as f:      # a private key in the "public" Lensa CA file
            f.write(CERT.format("L") + "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n")
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        with self.assertRaises(SystemExit):
            enroll_gw.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.tls, self.lensa, self.out + "z")
        make_inputs(self.tmp.name)
        shutil.rmtree(os.path.join(self.tls, "org3"))   # a TLS CA of one org is missing
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        with self.assertRaises(SystemExit):
            enroll_gw.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.tls, self.lensa, self.out + "w")
        self.assertEqual(self.logtext("kubectl-stdin.log"), "")

    def test_failure_text_has_no_secret_and_no_partial_secret(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        pw = open(os.path.join(self.work, "admin.pass")).read().strip()
        os.environ["STUB_FAIL"] = "bank2-gw"
        with self.assertRaises(SystemExit) as cm:
            enroll_gw.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.tls, self.lensa, self.out)
        self.assertNotIn(pw, str(cm.exception))
        self.assertEqual(self.logtext("kubectl-stdin.log"), "")
        self.assertFalse(os.path.exists(self.out))
        self.assertFalse(os.path.exists(self.work))


if __name__ == "__main__":
    unittest.main()
