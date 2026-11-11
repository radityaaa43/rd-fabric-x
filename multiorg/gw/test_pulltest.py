"""Tests for multiorg/gw/pulltest.py: the pull-test Deployment is DERIVED from the real gateway pod spec (same imagePullSecrets, ServiceAccount, securityContext), with
imagePullPolicy Always so a node-cached image cannot hide a missing pull secret (live S16: bank-b and bi passed only through the node cache, bank-a got ImagePullBackOff 401).

  python3 -m unittest discover -s multiorg/gw
"""
import importlib.util, os, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
import test_render as tr   # fixtures (make_inputs, build, by, PARTIES)

_spec = importlib.util.spec_from_file_location("gw_pulltest", os.path.join(HERE, "pulltest.py"))
pt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pt)

PODLEVEL = ("imagePullSecrets", "serviceAccountName", "securityContext", "hostAliases", "nodeSelector", "automountServiceAccountToken")


class PullTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        tr.make_inputs(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def gw(self, party):
        n = tr.PARTIES[party]
        return tr.by(tr.build(self.root, party), "Deployment", f"fx-gw-{n}")

    def test_pod_level_spec_is_the_gateways(self):
        for p in tr.PARTIES:
            real = self.gw(p)["spec"]["template"]["spec"]
            d = yaml.safe_load(pt.render_pulltest(self.gw(p), replicas=1))
            got = d["spec"]["template"]["spec"]
            for k in PODLEVEL:
                self.assertEqual(got.get(k), real.get(k), f"{p} {k}")
            self.assertEqual(got["imagePullSecrets"], [{"name": "ghcr-pull"}])

    def test_every_gateway_image_is_pulled_always(self):
        for p in tr.PARTIES:
            real = self.gw(p)["spec"]["template"]["spec"]
            d = yaml.safe_load(pt.render_pulltest(self.gw(p), replicas=1))
            spec = d["spec"]["template"]["spec"]
            cs = spec.get("initContainers", []) + spec["containers"]
            self.assertEqual(sorted({c["image"] for c in cs}), sorted({c["image"] for c in real["containers"]}))
            for c in cs:
                self.assertEqual(c["imagePullPolicy"], "Always", c["name"])

    def test_name_namespace_labels_and_replicas(self):
        d = yaml.safe_load(pt.render_pulltest(self.gw("bank-a"), replicas=0))
        self.assertEqual((d["metadata"]["name"], d["metadata"]["namespace"]), ("pull-test-fx", "rd-fabricx-bank-a"))
        self.assertEqual(d["spec"]["replicas"], 0)
        self.assertNotIn("volumes", d["spec"]["template"]["spec"])   # no secret/configmap mounts: a pull test only

    def test_a_gateway_without_a_pull_secret_makes_the_derived_test_fail_loudly(self):
        g = self.gw("bank-a")
        del g["spec"]["template"]["spec"]["imagePullSecrets"]
        with self.assertRaises(SystemExit):
            pt.render_pulltest(g, replicas=1)


if __name__ == "__main__":
    unittest.main()
