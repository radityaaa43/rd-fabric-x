"""Offline tests for regen_endpoints.py (fabricx S10 prep)."""
import hashlib, os, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import regen_endpoints
import test_check_exchange as tce
import check_exchange


class Regen(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.src, self.dst = os.path.join(self.tmp.name, "src"), os.path.join(self.tmp.name, "dst")
        for n in (1, 2, 3, 4):
            tce.good_tree(os.path.join(self.src, f"org{n}"), n)         # endpoints with port 7000+i, like B3's 7050 trees: off plan

    def tearDown(self):
        self.tmp.cleanup()

    def test_ports_from_the_plan_hosts_from_the_template(self):
        heads = regen_endpoints.regen(self.src, self.dst, "{role}-{n}.lb.{party}")
        ep = yaml.safe_load(open(os.path.join(self.dst, "org3", "endpoints.yaml")))
        self.assertEqual({r: v["Port"] for r, v in ep.items()}, {"assembler": 8011, "consenter": 8012, "router": 8013, "batcher1": 8014})
        self.assertEqual(ep["router"]["Host"], "router-3.lb.bank-b")
        self.assertEqual(ep["batcher1"]["Host"], "batcher1-3.lb.bank-b")
        self.assertEqual(sorted(heads), [1, 2, 3, 4])

    def test_new_manifest_matches_and_trees_stay_clean(self):
        heads = regen_endpoints.regen(self.src, self.dst, "{role}-{n}.lb.{party}")
        for n, h in heads.items():
            d = os.path.join(self.dst, f"org{n}")
            self.assertEqual(check_exchange.problems(d, n), [])
            self.assertEqual(h, hashlib.sha256(open(os.path.join(d, "MANIFEST.sha256"), "rb").read()).hexdigest())

    def test_source_is_untouched_and_in_place_is_refused(self):
        before = open(os.path.join(self.src, "org2", "endpoints.yaml")).read()
        regen_endpoints.regen(self.src, self.dst, "{role}-{n}.lb.{party}")
        self.assertEqual(open(os.path.join(self.src, "org2", "endpoints.yaml")).read(), before)
        with self.assertRaises(SystemExit):
            regen_endpoints.regen(self.src, self.src, "{role}-{n}.lb.{party}")
        with self.assertRaises(SystemExit):
            regen_endpoints.regen(self.src, self.dst, "{role}-{n}.lb.{party}")         # destination exists now

    def test_bad_template_refused(self):
        for bad in ("fixed.example.org", "{role} bad.example", ""):
            with self.assertRaises(SystemExit):
                regen_endpoints.regen(self.src, os.path.join(self.tmp.name, "d2"), bad)
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "d2")))

    def test_unclean_tree_refused(self):
        with open(os.path.join(self.src, "org2", "orderers", "party2", "router", "tls", "server.key"), "w") as f:
            f.write("-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n")
        tce.manifest(os.path.join(self.src, "org2"))
        with self.assertRaises(SystemExit):
            regen_endpoints.regen(self.src, self.dst, "{role}-{n}.lb.{party}")


if __name__ == "__main__":
    unittest.main()
