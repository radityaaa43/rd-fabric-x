"""Offline tests for multiorg/fca (fabricx S9): CA manifests and the enroll layout. No cluster, no fabric-ca-client.

  python3 -m unittest discover -s multiorg/fca        (needs PyYAML)
"""
import os, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import enroll, render
import check_exchange

PARTIES = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
DIGEST = "ghcr.io/hyperledger/fabric-ca@sha256:87c36f0b655838e2c3b00379cafc6efb36dc6f8d88b2cec9c707fd47e93b1c63"


def docs(party):
    return list(yaml.safe_load_all(render.render(party)))


class Manifests(unittest.TestCase):
    def test_objects_and_names(self):
        for p, n in PARTIES.items():
            with self.subTest(party=p):
                d = {(x["kind"], x["metadata"]["name"]): x for x in docs(p)}
                self.assertEqual(set(d), {("Service", f"fca-org{n}"), ("PersistentVolumeClaim", f"fca-org{n}-data"),
                                          ("Deployment", f"fca-org{n}")})
                self.assertEqual({x["metadata"]["namespace"] for x in d.values()}, {f"rd-fabricx-{p}"})

    def test_restricted_and_pinned(self):
        for p in PARTIES:
            dep = next(x for x in docs(p) if x["kind"] == "Deployment")
            spec = dep["spec"]["template"]["spec"]
            self.assertIs(spec["securityContext"]["runAsNonRoot"], True)
            self.assertEqual(spec["securityContext"]["seccompProfile"], {"type": "RuntimeDefault"})
            self.assertIn("fsGroup", spec["securityContext"])
            for c in spec["containers"]:
                self.assertEqual(c["image"], DIGEST)
                self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False)
                self.assertEqual(c["securityContext"]["capabilities"]["drop"], ["ALL"])
                self.assertIn("cpu", c["resources"]["limits"])
                self.assertIn("ephemeral-storage", c["resources"]["limits"])
                self.assertIn("requests", c["resources"])
            self.assertEqual(dep["spec"]["strategy"], {"type": "Recreate"})   # one PVC, ReadWriteOnce

    def test_no_secret_material_in_manifest(self):
        out = render.render("bank-a")
        self.assertNotIn("Secret", [x["kind"] for x in docs("bank-a")])
        self.assertNotIn("PRIVATE KEY", out)
        # the admin password is a Secret created at enroll time, referenced by name only
        env = next(x for x in docs("bank-a") if x["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["env"]
        self.assertTrue(any("valueFrom" in e and e["valueFrom"]["secretKeyRef"]["name"] == "fca-org2-admin" for e in env))

    def test_cluster2_label_and_refusals(self):
        self.assertEqual(next(x for x in docs("bank-c") if x["kind"] == "Deployment")["metadata"]["namespace"], "rd-fabricx-bank-c")
        for bad in ("bank-d", "fabricx", ""):
            with self.assertRaises(SystemExit):
                render.render(bad)


class Enroll(unittest.TestCase):
    def fake_enrolled(self, root, n=2):
        """what fabric-ca-client leaves per role after `enroll` (msp profile) and `enroll --enrollment.profile tls`"""
        for role in enroll.ROLES:
            for sub, files in (("msp", ["signcerts/cert.pem", "cacerts/ca.pem", "keystore/abc_sk"]),
                               ("tls", ["signcerts/cert.pem", "tlscacerts/tlsca.pem", "keystore/def_sk"])):
                for f in files:
                    p = os.path.join(root, role, sub, f)
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    with open(p, "w") as fh:
                        fh.write("-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n" if f.endswith("_sk") else
                                 "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n")

    def test_layout_passes_checker_and_secrets_hold_the_keys(self):
        with tempfile.TemporaryDirectory() as t:
            self.fake_enrolled(os.path.join(t, "enrolled"))
            ex = os.path.join(t, "exchange", "org2")
            secrets = enroll.build(os.path.join(t, "enrolled"), ex, 2, "rd-fabricx-bank-a", {r: f"{r}-2.rd-fabricx-bank-a.svc.cluster.local" for r in enroll.ROLES})
            self.assertEqual(check_exchange.problems(ex, 2), [])
            self.assertEqual({s["metadata"]["name"] for s in secrets},
                             {f"orderer-{r}-2-secret" for r in ("router", "batcher", "consenter", "assembler")})
            for s in secrets:
                self.assertEqual(s["metadata"]["namespace"], "rd-fabricx-bank-a")
                self.assertIn("msp-keystore-priv_sk", s["stringData"])      # node reads keystore/priv_sk (config/config.go:308)
                self.assertIn("tls-server.key", s["stringData"])            # config/generate/local_config_gen.go:195
            blob = subprocess.run(["grep", "-r", "PRIVATE KEY", ex], capture_output=True, text=True).stdout
            self.assertEqual(blob, "")

    def test_wrong_namespace_or_party_refused(self):
        for args in (("bank-a", "rd-fabricx-bi"), ("bank-a", "fabricx"), ("bank-x", "rd-fabricx-bank-x")):
            with self.assertRaises(SystemExit):
                enroll.check_target(*args)
        self.assertEqual(enroll.check_target("bank-c", "rd-fabricx-bank-c"), 4)


if __name__ == "__main__":
    unittest.main()
