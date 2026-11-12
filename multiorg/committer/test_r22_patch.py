"""Offline tests of committer/r22_patch.py: the strategic patch that applies R22 to ONE live committer StatefulSet is EXTRACTED from the committer renderer
(labels.rd/role + podAntiAffinity, nothing else), never typed by hand. No cluster.

  python3 -m unittest discover -s multiorg/committer
"""
import hashlib, importlib.util, json, os, subprocess, sys, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
_s = importlib.util.spec_from_file_location("r22_patch", os.path.join(HERE, "r22_patch.py"))
r22 = importlib.util.module_from_spec(_s); _s.loader.exec_module(r22)
_s = importlib.util.spec_from_file_location("committer_render", os.path.join(HERE, "render.py"))
render = importlib.util.module_from_spec(_s); _s.loader.exec_module(render)

C1 = ("bi", "bank-a", "bank-b")
STATE = ("committer-db", "committer-sidecar")


def sts(party, name):
    docs = [d for d in yaml.safe_load_all(render.render(party)) if d]
    (d,) = [d for d in docs if d["kind"] == "StatefulSet" and d["metadata"]["name"] == name]
    return d


def cli(*args):
    return subprocess.run([sys.executable, os.path.join(HERE, "r22_patch.py"), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)


class Patch(unittest.TestCase):
    def test_patch_fields_equal_render_fields_and_nothing_else(self):
        for party in C1:
            for name in STATE:
                tpl = sts(party, name)["spec"]["template"]
                want = {"spec": {"template": {"metadata": {"labels": {"rd/role": tpl["metadata"]["labels"]["rd/role"]}},
                                              "spec": {"affinity": {"podAntiAffinity": tpl["spec"]["affinity"]["podAntiAffinity"]}}}}}
                got = json.loads(r22.patch(party, name))
                self.assertEqual(got, want, f"{party}/{name}")
                self.assertEqual(sorted(got), ["spec"])
                self.assertEqual(sorted(got["spec"]), ["template"])
                self.assertEqual(sorted(got["spec"]["template"]), ["metadata", "spec"])
                self.assertEqual(sorted(got["spec"]["template"]["metadata"]), ["labels"])
                self.assertEqual(sorted(got["spec"]["template"]["metadata"]["labels"]), ["rd/role"])
                self.assertEqual(sorted(got["spec"]["template"]["spec"]), ["affinity"])
                self.assertEqual(sorted(got["spec"]["template"]["spec"]["affinity"]), ["podAntiAffinity"])   # the nodeAffinity (AVOID_NODES) of the live object is left alone

    def test_state_holders_carry_the_required_rule_with_the_party_exclusion(self):
        for party in C1:
            for name in STATE:
                aa = json.loads(r22.patch(party, name))["spec"]["template"]["spec"]["affinity"]["podAntiAffinity"]
                (term,) = aa["requiredDuringSchedulingIgnoredDuringExecution"]
                self.assertNotIn("preferredDuringSchedulingIgnoredDuringExecution", aa)
                self.assertEqual(term["topologyKey"], "kubernetes.io/hostname")
                self.assertEqual(term["namespaceSelector"], {"matchLabels": {"part-of": "rd-fabricx"}})
                self.assertIn({"key": "party", "operator": "NotIn", "values": [party]}, term["labelSelector"]["matchExpressions"])

    def test_output_is_deterministic_and_the_cli_prints_the_sha256(self):
        a = r22.patch("bank-b", "committer-db")
        self.assertEqual(a, r22.patch("bank-b", "committer-db"))
        r = cli("bank-b", "committer-db")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, a)
        self.assertEqual(r.stderr.strip(), f"sha256 {hashlib.sha256(a.encode()).hexdigest()} committer-db bank-b")
        self.assertNotEqual(a, r22.patch("bank-a", "committer-db"))

    def test_merged_into_the_rendered_object_the_two_fields_equal_the_render(self):
        for party in C1:
            for name in STATE:
                obj = sts(party, name)
                p = json.loads(r22.patch(party, name))
                self.assertEqual(p["spec"]["template"]["metadata"]["labels"]["rd/role"], obj["spec"]["template"]["metadata"]["labels"]["rd/role"])
                self.assertEqual(p["spec"]["template"]["spec"]["affinity"]["podAntiAffinity"], obj["spec"]["template"]["spec"]["affinity"]["podAntiAffinity"])

    def test_everything_else_is_refused(self):
        for args in (("bank-b", "committer-coordinator"), ("bank-b", "committer-query"), ("bank-b", "committer-vc"), ("bank-b", "committer-verifier"),   # helpers: PREFERRED only, not in the series
                     ("bank-c", "committer-db"), ("bank-c", "committer-sidecar"),                                                                  # cluster 2: no peers
                     ("bank-b", "committer-db-0"), ("bank-b", "fx-gw-3"), ("nobody", "committer-db"), ("bank-b", "")):
            with self.assertRaises(SystemExit, msg=str(args)):
                r22.patch(*args)
            self.assertNotEqual(cli(*args).returncode, 0, str(args))
            self.assertEqual(cli(*args).stdout, "", str(args))


if __name__ == "__main__":
    unittest.main()
