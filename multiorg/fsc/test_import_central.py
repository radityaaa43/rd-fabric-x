"""Offline tests for multiorg/fsc/import_central.py (fabricx S13 piece 4: own-only import of the central ids/anon, Idemix owner wallet and issuer wallet files).
Fake home tree (with the OTHER nodes' files in it, to prove nothing foreign is read), stub kubectl on PATH; the fixture core is test_core_rewrite.core().

  python3 -m unittest discover -s multiorg/fsc
"""
import base64, json, os, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import enroll_fsc
import import_central
import test_core_rewrite as tcr

CH = "default-testchannel-token_chaincode"
ISSUER_W = f"issuer/issuers/peerOrganizations/Orgissuer.example.com/users/issuer@Orgissuer.example.com/msp"


class Flow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.tmp.name, "home")
        t = os.path.join(self.tmp.name, "live")
        for n in tcr.NODES:   # templates dir
            os.makedirs(f"{t}/{n}")
            core = tcr.core(n)
            with open(f"{t}/{n}/core.yaml", "w") as f:
                yaml.safe_dump(self._home(core), f)
        self.templates = t
        for rel in ("ids/anon/msp/cacerts/ca.pem", "ids/anon/msp/IssuerPublicKey", "ids/anon/msp/keystore/anon-secret"):
            self.put(rel, f"ANON:{rel}")
        for n in ("bank2", "bank3", "bank4", "issuer"):
            self.put(f"livegen/token/crypto/{CH}/idemix/{n}/user/SignerConfig", f"WALLET:{n}")
            self.put(f"livegen/token/crypto/{CH}/idemix/{n}/msp/IssuerPublicKey", f"WALLETMSP:{n}")
        self.put(f"livegen/token/crypto/{CH}/{ISSUER_W}/keystore/priv_sk", "ISSUERKEY")
        self.put(f"livegen/token/crypto/{CH}/{ISSUER_W}/signcerts/cert.pem", "ISSUERCERT")
        self.bin = os.path.join(self.tmp.name, "bin")
        self.log = os.path.join(self.tmp.name, "log")
        os.makedirs(self.bin)
        os.makedirs(self.log)
        p = os.path.join(self.bin, "kubectl")
        with open(p, "w") as f:
            f.write("#!/bin/sh\necho \"$@\" >> \"$STUB_LOG/kubectl.log\"\ncat >> \"$STUB_LOG/kubectl-stdin.log\"\nexit 0\n")
        os.chmod(p, 0o755)
        self.env = {k: os.environ.get(k) for k in ("PATH", "STUB_LOG")}
        os.environ["PATH"] = self.bin + ":" + os.environ["PATH"]
        os.environ["STUB_LOG"] = self.log
        self.keys_out = os.path.join(self.tmp.name, "keys.json")

    def tearDown(self):
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def _home(self, o):
        if isinstance(o, dict):
            return {k: self._home(v) for k, v in o.items()}
        if isinstance(o, list):
            return [self._home(v) for v in o]
        return o.replace(tcr.H, self.home) if isinstance(o, str) else o

    def put(self, rel, text):
        p = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def logtext(self, name):
        p = os.path.join(self.log, name)
        if not os.path.exists(p):
            return ""
        with open(p) as f:
            return f.read()

    def run_import(self, party="bank-a", **kw):
        import_central.import_central(party, f"rd-fabricx-{party}", "/k", self.templates, self.home, self.keys_out, **kw)

    def patch(self):
        return json.loads(self.logtext("kubectl-stdin.log"))["data"]

    def test_bank_gets_its_own_anon_and_owner_wallet_only(self):
        self.run_import("bank-a")
        data = self.patch()
        vals = {k: base64.b64decode(v).decode() for k, v in data.items()}
        self.assertEqual(sorted(data), sorted([
            "own__bank2__ids__anon__msp__cacerts__ca.pem", "own__bank2__ids__anon__msp__IssuerPublicKey", "own__bank2__ids__anon__msp__keystore__anon-secret",
            "own__bank2__wallets__bank2__user__SignerConfig", "own__bank2__wallets__bank2__msp__IssuerPublicKey"]))
        for v in vals.values():
            self.assertNotIn("bank3", v)
            self.assertNotIn("bank4", v)
            self.assertNotIn("issuer", v.lower().replace("issuerpublickey", ""))
        self.assertEqual(vals["own__bank2__wallets__bank2__user__SignerConfig"], "WALLET:bank2")

    def test_issuer_gets_anon_and_the_issuer_wallet_msp_not_a_bank_wallet(self):
        self.run_import("bi")
        data = self.patch()
        self.assertIn("own__issuer__ids__anon__msp__cacerts__ca.pem", data)
        self.assertEqual(base64.b64decode(data["own__issuer__wallets__issuer-msp__keystore__priv_sk"]).decode(), "ISSUERKEY")
        self.assertFalse([k for k in data if "endorser" in k])
        self.assertFalse([k for k in data if "bank" in k])

    def test_endorser_only_party_nodes_never_get_central_files(self):
        self.run_import("bank-b")
        self.assertFalse([k for k in self.patch() if "endorser-3" in k])

    def test_patch_goes_through_stdin_never_argv_and_names_the_secret(self):
        self.run_import("bank-a")
        argv = self.logtext("kubectl.log")
        self.assertIn("patch secret rdbi-bank2-files", argv)
        self.assertIn("--type merge", argv)
        self.assertIn("--patch-file /dev/stdin", argv)
        for bad in ("WALLET", "ANON", "ISSUERKEY", "data"):
            self.assertNotIn(bad, argv.replace("--patch-file", ""))

    def test_keys_file_has_names_only(self):
        self.run_import("bank-a")
        keys = json.load(open(self.keys_out))
        self.assertEqual(sorted(keys), sorted(self.patch()))
        self.assertNotIn("WALLET", open(self.keys_out).read())

    def test_every_key_is_a_valid_secret_key_and_resolves_to_the_core_paths(self):
        # render's --central-keys turns key k into the pod path enroll_fsc.secret_path(k): that must be the manifest private path the core needs
        self.run_import("bank-a")
        import core_rewrite as cr
        _, man = cr.per_org_core(yaml.safe_load(open(f"{self.templates}/bank2/core.yaml")), "bank2", self.home, tcr.T)
        need = {pp[len(f"{tcr.T}/own/"):] for pp, i in man.items() if i["kind"] == "secret" and ("/ids/anon/" in pp or "/wallets/" in pp)}
        got = {enroll_fsc.secret_path(k)[len("own/"):] for k in json.load(open(self.keys_out))}
        for n in need:
            self.assertTrue(any(g.startswith(n + "/") for g in got), n)
        for k in json.load(open(self.keys_out)):
            self.assertRegex(k, r"^[-._a-zA-Z0-9]{1,253}$")

    def test_missing_source_symlink_and_foreign_path_refused_without_calling_kubectl(self):
        os.remove(os.path.join(self.home, "ids/anon/msp/IssuerPublicKey"))
        os.symlink("/etc/passwd", os.path.join(self.home, "ids/anon/msp/IssuerPublicKey"))
        with self.assertRaises(SystemExit):
            self.run_import("bank-a")
        self.assertEqual(self.logtext("kubectl.log"), "")
        with self.assertRaises(SystemExit):
            import_central.import_central("bank-a", "rd-fabricx-bank-b", "/k", self.templates, self.home, self.keys_out)
        self.assertEqual(self.logtext("kubectl.log"), "")

    def test_nothing_to_import_for_an_empty_source_dir_is_refused(self):
        import shutil
        shutil.rmtree(os.path.join(self.home, "ids/anon/msp"))
        os.makedirs(os.path.join(self.home, "ids/anon/msp"))
        with self.assertRaises(SystemExit):
            self.run_import("bank-a")
        self.assertEqual(self.logtext("kubectl.log"), "")


if __name__ == "__main__":
    unittest.main()
