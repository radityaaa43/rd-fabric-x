"""Offline tests for multiorg/fsc/p2p_san.py (S13 precondition: the cert a p2p listener PRESENTS must carry the names peers dial). Throwaway certs from the local openssl.

  python3 -m unittest discover -s multiorg/fsc
"""
import os, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p2p_san


def cert(sans):
    d = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", f"{d}/k", "-out", f"{d}/c", "-days", "1", "-subj", "/CN=t"]
                   + (["-addext", "subjectAltName=" + ",".join(f"DNS:{s}" for s in sans)] if sans else []), capture_output=True, check=True)
    return open(f"{d}/c").read()


class San(unittest.TestCase):
    def test_names_per_party(self):
        self.assertEqual(p2p_san.names("bank-b", "bank3"), ["bank3", "bank3.rd-fabricx-bank-b.svc.cluster.local"])
        self.assertEqual(p2p_san.names("bi", "issuer"), ["issuer", "issuer.rd-fabricx-bi.svc.cluster.local"])

    def test_san_reads_all_dns_names(self):
        self.assertEqual(p2p_san.san(cert(["a", "b.c"])), ["a", "b.c"])
        self.assertEqual(p2p_san.san(cert([])), [])

    def test_good_cert_passes(self):
        self.assertEqual(p2p_san.check(cert(["endorser-3", "endorser-3.rd-fabricx-bank-b.svc.cluster.local"]), "bank-b", "endorser-3"), [])

    def test_extra_names_are_fine(self):
        self.assertEqual(p2p_san.check(cert(["endorser-3", "endorser-3.rd-fabricx-bank-b.svc.cluster.local", "x"]), "bank-b", "endorser-3"), [])

    def test_the_live_defect_hostname_only_fails_and_says_what_is_missing(self):
        miss = p2p_san.check(cert(["bi-server"]), "bank-b", "endorser-3")
        self.assertEqual(miss, ["endorser-3", "endorser-3.rd-fabricx-bank-b.svc.cluster.local"])

    def test_one_of_two_names_fails(self):
        self.assertEqual(p2p_san.check(cert(["bank3"]), "bank-b", "bank3"), ["bank3.rd-fabricx-bank-b.svc.cluster.local"])

    def test_fingerprint_is_sha256_of_the_cert(self):
        c = cert(["a"])
        f = p2p_san.fingerprint(c)
        self.assertRegex(f, r"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$")
        self.assertEqual(f, p2p_san.fingerprint(c))
        self.assertNotEqual(f, p2p_san.fingerprint(cert(["a"])))

    def test_listeners_cover_8_nodes(self):
        l = p2p_san.LISTEN
        self.assertEqual(sorted(n for p in l for n, _, _ in l[p]), sorted(["issuer", "endorser-1", "bank2", "endorser-2", "bank3", "endorser-3", "bank4", "endorser-4"]))

    def test_cli_check_file(self):
        d = tempfile.mkdtemp()
        open(f"{d}/ok.pem", "w").write(cert(["bank4", "bank4.rd-fabricx-bank-c.svc.cluster.local"]))
        open(f"{d}/bad.pem", "w").write(cert(["bi-server"]))
        run = lambda f: subprocess.run([sys.executable, "-I", os.path.join(HERE, "p2p_san.py"), "file", f, "bank-c", "bank4"], capture_output=True, text=True)
        self.assertEqual(run(f"{d}/ok.pem").returncode, 0)
        r = run(f"{d}/bad.pem")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MISSING", r.stdout)


if __name__ == "__main__":
    unittest.main()
