"""Offline tests for multiorg/fsc/enroll_fsc.py (fabricx S13: per-org FSC identities, key custody).
Stub fabric-ca-client and kubectl on PATH (the stubs of multiorg/fca/test_fca.py).

  python3 -m unittest discover -s multiorg/fsc
"""
import glob, os, shutil, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "fca"))
sys.path.insert(0, HERE)
import enroll
import enroll_fsc
import test_fca as tf   # FCA_STUB, KUBECTL_STUB

CERT = "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n"


def make_exchange(root, n=2):
    for rel in (f"org{n}/msp/cacerts/ca.pem", f"org{n}/msp/knowncerts/endorser-{n}-cert.pem"):
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(CERT)


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
        self.ex = os.path.join(self.tmp.name, "exchange")
        make_exchange(self.ex)
        self.out = os.path.join(self.tmp.name, "fsc-exchange", "org2")

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
        if not os.path.exists(p):
            return ""
        with open(p) as f:
            return f.read()

    def run_make(self, **kw):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        enroll_fsc.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.ex, self.out, **kw)

    def secrets(self):
        parts = self.logtext("kubectl-stdin.log").split("apiVersion: v1\n")[1:]
        return {d["metadata"]["name"]: d for d in (yaml.safe_load("apiVersion: v1\n" + t) for t in parts)}

    def test_one_secret_per_pod_with_per_node_keys_only(self):
        self.run_make()
        s = self.secrets()
        self.assertEqual(sorted(s), ["rdbi-bank2-files"])
        keys = sorted(s["rdbi-bank2-files"]["stringData"])
        common = ["fsc__admin.pem", "fsc__cert.pem", "fsc__key.pem", "fsc__tls-ca.crt", "fsc__tls.crt", "fsc__tls.key", "tls__cert.pem", "tls__key.pem"]
        bank = [f"own__bank2__{k}" for k in common] + [f"own__bank2__ids__bank2__msp__{k}" for k in ("cacerts__ca.pem", "keystore__priv_sk", "signcerts__cert.pem")]
        endorser = [f"own__endorser-2__{k}" for k in common]   # its MSP is the existing fsc-endorser-2-secret, mounted by the render
        self.assertEqual(keys, sorted(bank + endorser))
        self.assertEqual(s["rdbi-bank2-files"]["metadata"]["namespace"], "rd-fabricx-bank-a")
        self.assertFalse(os.path.exists(self.work))

    def test_secret_key_mapping_is_reversible(self):
        self.assertEqual(enroll_fsc.secret_key("own/bank2/fsc/key.pem"), "own__bank2__fsc__key.pem")
        self.assertEqual(enroll_fsc.secret_path("own__bank2__ids__bank2__msp__keystore__priv_sk"), "own/bank2/ids/bank2/msp/keystore/priv_sk")

    def test_identities_all_clients_at_the_orgs_own_ca(self):
        self.run_make()
        argv = self.logtext("argv.log")
        for who in ("bank2-fsc", "bank2-admin", "bank2-id", "endorser-2-fsc", "endorser-2-admin", "endorser-2-tls"):
            self.assertIn(f"--id.name {who} ", argv + " ", who)
        self.assertNotIn("--id.name endorser-2 ", argv + " ")      # the genesis known_certs identity is never re-registered
        self.assertNotIn("--id.name endorser-2-id", argv)
        self.assertEqual(argv.count("--id.type client"), 6)
        self.assertNotIn("--id.type admin", argv)

    def test_fsc_tls_sans_are_the_node_names(self):
        self.run_make()
        tls = [l for l in self.logtext("argv.log").splitlines() if "--enrollment.profile tls" in l and "--csr.hosts" in l]
        self.assertTrue(any("bank2,bank2.rd-fabricx-bank-a.svc.cluster.local" in l for l in tls))
        self.assertTrue(any("endorser-2,endorser-2.rd-fabricx-bank-a.svc.cluster.local" in l for l in tls))

    def test_public_tree_has_certs_only_and_a_manifest(self):
        self.run_make()
        rel = sorted(os.path.relpath(p, self.out) for p in glob.glob(f"{self.out}/**/*", recursive=True) if os.path.isfile(p))
        self.assertEqual(rel, ["MANIFEST.sha256", "admin/bank2-admin.pem", "admin/endorser-2-admin.pem", "fsc/bank2.pem", "fsc/endorser-2.pem",
                               "ids/bank2/msp/cacerts/ca.pem", "ids/bank2/msp/signcerts/cert.pem",
                               "ids/endorser-2/msp/cacerts/ca.pem", "ids/endorser-2/msp/signcerts/cert.pem"])
        for p in glob.glob(f"{self.out}/**/*", recursive=True):
            if os.path.isfile(p):
                with open(p) as f:
                    self.assertNotIn("PRIVATE KEY", f.read(), p)

    def test_endorser_public_cert_is_the_known_cert_from_the_exchange(self):
        with open(os.path.join(self.ex, "org2", "msp", "knowncerts", "endorser-2-cert.pem"), "w") as f:
            f.write(CERT.replace("MII", "KNOWN"))
        self.run_make()
        with open(os.path.join(self.out, "ids", "endorser-2", "msp", "signcerts", "cert.pem")) as f:
            self.assertIn("KNOWN", f.read())

    def test_secrets_never_in_argv_and_files_destroyed(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        with open(os.path.join(self.work, "admin.pass")) as f:
            pw = f.read().strip()
        enroll_fsc.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.ex, self.out)
        argv = self.logtext("argv.log") + self.logtext("kubectl.log")
        for bad in (pw, "ROLESECRET", "--id.secret", "PRIVATE KEY"):
            self.assertNotIn(bad, argv)
        self.assertIn(f"admin:{pw}@localhost", self.logtext("url.log"))
        self.assertFalse(os.path.exists(self.work))

    def test_generation_renames_identities_not_secrets(self):
        self.run_make(generation="g2")
        self.assertIn("--id.name bank2-fsc-g2 ", self.logtext("argv.log") + " ")
        self.assertEqual(sorted(self.secrets()), ["rdbi-bank2-files"])

    def test_refusals_create_nothing(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        os.makedirs(self.out)   # an existing out dir is refused
        with self.assertRaises(SystemExit):
            enroll_fsc.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.ex, self.out)
        self.assertEqual(self.logtext("kubectl-stdin.log"), "")
        self.assertFalse(os.path.exists(self.work))
        with self.assertRaises(SystemExit):
            enroll_fsc.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", "/tmp/not-shm", self.ex, self.out + "x")
        with self.assertRaises(SystemExit):
            enroll_fsc.make("bank-a", "rd-fabricx-bank-b", "/k", "http://localhost:7054", self.work, self.ex, self.out + "y")
        shutil.rmtree(os.path.join(self.ex, "org2", "msp", "knowncerts"))   # no endorser known cert in the exchange
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        with self.assertRaises(SystemExit):
            enroll_fsc.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.ex, self.out + "z")
        self.assertEqual(self.logtext("kubectl-stdin.log"), "")

    def test_failure_text_has_no_secret_and_no_partial_secret(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        with open(os.path.join(self.work, "admin.pass")) as f:
            pw = f.read().strip()
        os.environ["STUB_FAIL"] = "endorser-2/id/tls"
        with self.assertRaises(SystemExit) as cm:
            enroll_fsc.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.ex, self.out)
        self.assertNotIn(pw, str(cm.exception))
        self.assertEqual(self.logtext("kubectl-stdin.log"), "")
        self.assertFalse(os.path.exists(self.out))
        self.assertFalse(os.path.exists(self.work))


if __name__ == "__main__":
    unittest.main()
