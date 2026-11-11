"""Offline tests for multiorg/committer/make_secrets.py (fabricx S12 custody: the four Secret sets of one org's committer).
Stub fabric-ca-client and kubectl on PATH (same stubs as multiorg/fca/test_fca.py); the DB cert is made with the real openssl.

  python3 -m unittest discover -s multiorg/committer
"""
import os, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "fca"))
sys.path.insert(0, HERE)
import enroll
import make_secrets
import test_fca as tf   # FCA_STUB, KUBECTL_STUB

SVCS = ("verifier", "vc", "coordinator", "sidecar", "query-service")


def make_exchange(root):
    for n in (1, 2, 3, 4):
        p = os.path.join(root, f"org{n}", "msp", "tlscacerts")
        os.makedirs(p)
        with open(os.path.join(p, "tlsca.pem"), "w") as f:
            f.write(f"-----BEGIN CERTIFICATE-----\nTLSCA{n}\n-----END CERTIFICATE-----\n")


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
        self._verify = make_secrets.verify_chain
        make_secrets.verify_chain = lambda *a, **k: None   # the stub CA makes fake certificates; verify_chain has its own test below

    def tearDown(self):
        make_secrets.verify_chain = self._verify
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

    def run_make(self, **kw):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        make_secrets.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.ex, **kw)

    def secrets(self):
        parts = self.logtext("kubectl-stdin.log").split("apiVersion: v1\n")[1:]   # the stub appends each stdin without a `---`
        return {d["metadata"]["name"]: d for d in (yaml.safe_load("apiVersion: v1\n" + t) for t in parts)}

    def test_four_secrets_exact_names_and_keys(self):
        self.run_make()
        s = self.secrets()
        self.assertEqual(sorted(s), ["committer-db-credentials", "committer-db-tls", "committer-sidecar-msp", "committer-tls"])
        keys = {n: sorted(d["stringData"]) for n, d in s.items()}
        self.assertEqual(keys["committer-tls"], ["ca.crt", "server.crt", "server.key"])
        self.assertEqual(keys["committer-db-tls"], ["ca.crt", "server.crt", "server.key"])
        self.assertEqual(keys["committer-db-credentials"], ["password"])
        self.assertEqual(keys["committer-sidecar-msp"], ["cacert.pem", "keystore-priv_sk", "signcert.pem"])
        for d in s.values():
            self.assertEqual(d["metadata"]["namespace"], "rd-fabricx-bank-a")
            self.assertEqual(d["kind"], "Secret")
        self.assertFalse(os.path.exists(self.work))   # destroyed

    def test_committer_tls_ca_bundle_is_all_four_org_tls_cas(self):
        self.run_make()
        ca = self.secrets()["committer-tls"]["stringData"]["ca.crt"]
        for n in (1, 2, 3, 4):
            self.assertIn(f"TLSCA{n}", ca)

    def test_identity_is_a_client_with_the_committer_sans_on_the_tls_enrollment(self):
        self.run_make()
        argv = self.logtext("argv.log")
        self.assertIn("--id.name committer-2 ", argv + " ")
        self.assertIn("--id.type client", argv)
        tls = [l for l in argv.splitlines() if "--enrollment.profile tls" in l]
        self.assertEqual(len(tls), 1)
        for s in SVCS:
            self.assertIn(f"committer-{s}", tls[0])
            self.assertIn(f"committer-{s}.rd-fabricx-bank-a.svc.cluster.local", tls[0])
        msp = [l for l in argv.splitlines() if l.startswith("enroll") and "--enrollment.profile" not in l and "admin-msp" not in l]
        self.assertEqual(len(msp), 1)

    def test_generation_renames_the_identity_only(self):
        self.run_make(generation="g2")
        self.assertIn("--id.name committer-2-g2 ", self.logtext("argv.log") + " ")
        self.assertIn("committer-tls", self.secrets())   # Secret names stay

    def test_secrets_never_in_argv_and_files_are_destroyed(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        pw = open(os.path.join(self.work, "admin.pass")).read().strip()
        make_secrets.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.ex)
        argv = self.logtext("argv.log") + self.logtext("kubectl.log")
        db_pw = self.secrets()["committer-db-credentials"]["stringData"]["password"]
        for bad in (pw, "ROLESECRET", db_pw, "--id.secret", "PRIVATE KEY"):
            self.assertNotIn(bad, argv)
        self.assertIn(f"admin:{pw}@localhost", self.logtext("url.log"))
        self.assertFalse(os.path.exists(self.work))

    def test_db_password_is_random_and_long(self):
        self.run_make()
        first = self.secrets()["committer-db-credentials"]["stringData"]["password"]
        self.assertGreaterEqual(len(first), 32)
        self.assertRegex(first, r"^[0-9a-f]+$")

    def test_db_certificate_is_real_has_the_db_sans_and_chains_to_its_ca(self):
        self.run_make()
        d = self.secrets()["committer-db-tls"]["stringData"]
        w = tempfile.mkdtemp(dir="/dev/shm")
        try:
            for k, v in d.items():
                with open(os.path.join(w, k), "w") as f:
                    f.write(v)
            text = subprocess.run(["openssl", "x509", "-in", f"{w}/server.crt", "-noout", "-text"], capture_output=True, text=True, check=True).stdout
            self.assertIn("DNS:committer-db", text)
            self.assertIn("DNS:committer-db.rd-fabricx-bank-a.svc.cluster.local", text)
            r = subprocess.run(["openssl", "verify", "-CAfile", f"{w}/ca.crt", f"{w}/server.crt"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            self.assertIn("PRIVATE KEY", d["server.key"])
            self.assertNotIn("PRIVATE KEY", d["ca.crt"])   # the throwaway CA key is never stored
        finally:
            enroll.destroy(w)

    def test_refusals_leave_nothing_behind(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        import shutil
        shutil.rmtree(os.path.join(self.ex, "org3"))   # a missing TLS CA must refuse before any Secret is made
        with self.assertRaises(SystemExit):
            make_secrets.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.ex)
        self.assertEqual(self.logtext("kubectl-stdin.log"), "")
        self.assertFalse(os.path.exists(self.work))
        with self.assertRaises(SystemExit):
            make_secrets.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", "/tmp/not-shm", self.ex)
        with self.assertRaises(SystemExit):
            make_secrets.make("bank-a", "rd-fabricx-bank-b", "/k", "http://localhost:7054", self.work, self.ex)

    def test_failure_text_has_no_secret(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        pw = open(os.path.join(self.work, "admin.pass")).read().strip()
        os.environ["STUB_FAIL"] = "tls"
        with self.assertRaises(SystemExit) as cm:
            make_secrets.make("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.ex)
        self.assertNotIn(pw, str(cm.exception))
        self.assertNotIn("ROLESECRET", str(cm.exception))
        self.assertEqual(self.logtext("kubectl-stdin.log"), "")   # no Secret before every cert exists
        self.assertFalse(os.path.exists(self.work))


class VerifyChain(unittest.TestCase):
    """verify_chain is the one place the real certificates are checked before any Secret is created."""

    def mk(self, d):
        def sh(*a):
            subprocess.run(a, check=True, capture_output=True)
        for ca in ("a", "b"):
            sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{d}/{ca}.key", "-subj", f"/CN={ca}", "-days", "2",
               "-addext", "basicConstraints=critical,CA:TRUE", "-out", f"{d}/{ca}.pem")
        sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", f"{d}/l.key")
        sh("openssl", "req", "-new", "-key", f"{d}/l.key", "-subj", "/CN=l", "-out", f"{d}/l.csr")
        with open(f"{d}/l.ext", "w") as f:
            f.write("subjectAltName=DNS:committer-verifier,DNS:committer-vc\n")
        sh("openssl", "x509", "-req", "-in", f"{d}/l.csr", "-CA", f"{d}/a.pem", "-CAkey", f"{d}/a.key", "-CAcreateserial", "-days", "2", "-extfile", f"{d}/l.ext", "-out", f"{d}/l.pem")

    def test_good_wrong_ca_and_missing_san(self):
        d = tempfile.mkdtemp(dir="/dev/shm")
        try:
            self.mk(d)
            cert, ca, other = (open(f"{d}/{x}").read() for x in ("l.pem", "a.pem", "b.pem"))
            make_secrets.verify_chain(cert, ca, ["committer-verifier", "committer-vc"])
            with self.assertRaises(SystemExit):
                make_secrets.verify_chain(cert, other, ["committer-verifier"])       # not issued by that CA
            with self.assertRaises(SystemExit):
                make_secrets.verify_chain(cert, ca, ["committer-coordinator"])       # SAN missing
        finally:
            enroll.destroy(d)


if __name__ == "__main__":
    unittest.main()
