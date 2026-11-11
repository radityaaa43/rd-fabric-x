"""Offline test for namespaces/render.py (fabricx PLAN S1, cluster 1): no cluster, no kubectl.

  python3 -m unittest discover -s namespaces        (needs PyYAML)
"""
import os, subprocess, sys, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import render

PARTIES = ("bi", "bank-a", "bank-b")
POLICIES = {"default-deny-ingress", "allow-same-namespace", "allow-dns-egress"}
SA = "party-admin"


def check(docs, party, cluster=None):
    """Assert the S1 contract on a rendered document list; raises AssertionError on the first gap."""
    ns = f"rd-fabricx-{party}"
    by = {}
    for d in docs:
        by.setdefault(d["kind"], {})[d["metadata"]["name"]] = d
    assert set(by.get("Namespace", {})) == {ns}, f"Namespace {ns} missing or extra: {set(by.get('Namespace', {}))}"
    labels = by["Namespace"][ns]["metadata"]["labels"]
    assert labels.get("part-of") == "rd-fabricx" and labels.get("party") == party, labels
    assert labels.get("pod-security.kubernetes.io/enforce") == "restricted", labels
    assert labels.get("cluster") == cluster, labels  # cluster-1 namespaces carry no cluster label
    assert set(by.get("NetworkPolicy", {})) == POLICIES, f"NetworkPolicy set {set(by.get('NetworkPolicy', {}))}"
    assert set(by.get("ServiceAccount", {})) == {SA}, "ServiceAccount party-admin missing"
    assert set(by.get("Role", {})) == {SA}, "Role party-admin missing"
    assert set(by.get("RoleBinding", {})) == {SA}, "RoleBinding party-admin missing"
    for d in docs:
        if d["kind"] != "Namespace":
            assert d["metadata"].get("namespace") == ns, f"{d['kind']}/{d['metadata']['name']} not in {ns}"
    deny = by["NetworkPolicy"]["default-deny-ingress"]["spec"]
    assert deny["podSelector"] == {} and deny["policyTypes"] == ["Ingress"] and "ingress" not in deny, deny
    dns = by["NetworkPolicy"]["allow-dns-egress"]["spec"]
    assert "Egress" in dns["policyTypes"], dns
    # R16 (option iv): the open-egress policy skips pods labelled rd/egress-locked, so a Job's own narrow egress policy binds (K8s policies are additive)
    assert dns["podSelector"] == {"matchExpressions": [{"key": "rd/egress-locked", "operator": "DoesNotExist"}]}, dns
    assert dns["egress"] == [{}], dns  # L0 for every unlabelled pod: unchanged (lead decision, tightened at S11/S13)
    same = by["NetworkPolicy"]["allow-same-namespace"]["spec"]
    assert same["policyTypes"] == ["Ingress"] and same["ingress"] == [{"from": [{"podSelector": {}}]}], same
    rb = by["RoleBinding"][SA]
    assert rb["roleRef"]["kind"] == "Role" and rb["roleRef"]["name"] == SA, rb["roleRef"]
    assert rb["subjects"] == [{"kind": "ServiceAccount", "name": SA, "namespace": ns}], rb["subjects"]
    for rule in by["Role"][SA]["rules"]:
        assert "*" not in rule["verbs"] and "*" not in rule["resources"], rule
        assert "pods/exec" not in rule["resources"], rule
        if "secrets" in rule["resources"]:
            assert rule["resources"] == ["secrets"] and set(rule["verbs"]) == {"create", "update", "patch"}, rule
    pf = [r for r in by["Role"][SA]["rules"] if "pods/portforward" in r["resources"]]
    assert len(pf) == 1 and pf[0]["verbs"] == ["create"], "pods/portforward create only (S9: reach the own CA)"
    granted = {r for rule in by["Role"][SA]["rules"] for r in rule["resources"]}
    need = {"pods/portforward", "deployments", "statefulsets", "services", "configmaps", "persistentvolumeclaims",
            "networkpolicies", "pods", "pods/log", "secrets"}
    assert need <= granted, f"Role misses {need - granted}"


class Render(unittest.TestCase):
    def docs(self, party):
        return list(yaml.safe_load_all(render.render(party)))

    def test_each_party_meets_contract(self):
        for p in PARTIES:
            with self.subTest(party=p):
                check(self.docs(p), p)

    def test_missing_object_is_caught(self):
        for p in PARTIES:
            docs = self.docs(p)
            for i, d in enumerate(docs):
                if d["kind"] == "Namespace":
                    continue
                with self.subTest(party=p, dropped=f"{d['kind']}/{d['metadata']['name']}"):
                    with self.assertRaises(AssertionError):
                        check(docs[:i] + docs[i + 1:], p)

    def test_renamed_sa_is_caught(self):
        docs = self.docs("bi")
        for d in docs:
            if d["kind"] == "ServiceAccount":
                d["metadata"]["name"] = "admin"
        with self.assertRaises(AssertionError):
            check(docs, "bi")

    def run_cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(HERE, "render.py"), *args], capture_output=True, text=True)

    def test_bank_c_refused_without_flag(self):
        with self.assertRaises(SystemExit):
            render.render("bank-c")
        r = self.run_cli("bank-c")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--cluster 2", r.stderr)
        self.assertEqual(r.stdout, "")

    def test_bank_c_cluster2_meets_contract(self):
        docs = list(yaml.safe_load_all(render.render("bank-c", cluster=2)))
        check(docs, "bank-c", cluster="2")
        r = self.run_cli("--cluster", "2", "bank-c")
        self.assertEqual(r.returncode, 0, r.stderr)
        check(list(yaml.safe_load_all(r.stdout)), "bank-c", cluster="2")

    def test_cluster2_only_bank_c(self):
        for p in PARTIES:
            with self.subTest(party=p):
                with self.assertRaises(SystemExit):
                    render.render(p, cluster=2)
        self.assertNotEqual(self.run_cli("--cluster", "2", "bi").returncode, 0)

    def test_cluster1_output_unchanged_by_flag_support(self):
        for p in PARTIES:
            self.assertNotIn("cluster", self.docs(p)[0]["metadata"]["labels"])

    def test_ns_only_cluster2_is_only_the_namespace(self):  # GO 1: the first cluster-2 write
        r = self.run_cli("--cluster", "2", "--ns-only", "bank-c")
        self.assertEqual(r.returncode, 0, r.stderr)
        docs = list(yaml.safe_load_all(r.stdout))
        self.assertEqual([(d["kind"], d["metadata"]["name"]) for d in docs], [("Namespace", "rd-fabricx-bank-c")])
        self.assertEqual(docs[0]["metadata"]["labels"]["cluster"], "2")
        self.assertEqual(docs[0]["metadata"]["labels"]["pod-security.kubernetes.io/enforce"], "restricted")
        # GO 2 is the full render: it starts with the same Namespace doc and has 6 more
        full = list(yaml.safe_load_all(self.run_cli("--cluster", "2", "bank-c").stdout))
        self.assertEqual(len(full), 7)
        self.assertEqual(full[0], docs[0])
        self.assertEqual(render.render("bank-c", cluster=2, ns_only=True), r.stdout)

    def test_ns_only_keeps_the_guards(self):
        self.assertNotEqual(self.run_cli("--ns-only", "bank-c").returncode, 0)             # bank-c needs --cluster 2
        self.assertNotEqual(self.run_cli("--cluster", "2", "--ns-only", "bi").returncode, 0)
        self.assertEqual(self.run_cli("--ns-only", "bank-c").stdout, "")

    def test_bad_cluster_refused(self):
        self.assertNotEqual(self.run_cli("--cluster", "3", "bank-c").returncode, 0)

    def test_unknown_party_refused(self):
        with self.assertRaises(SystemExit):
            render.render("bank-d")


if __name__ == "__main__":
    unittest.main()
