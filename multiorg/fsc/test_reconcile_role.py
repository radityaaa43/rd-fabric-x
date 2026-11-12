"""Tests for multiorg/fsc/reconcile_role.py (S17, analyst Q18: Role for the reconcile check). No cluster.

  python3 -m unittest discover -s multiorg/fsc
"""
import os, subprocess, sys, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
POD = "rdbi-bi-6f58bd75d4-pmd9s"


def render(*a):
    return subprocess.run([sys.executable, "-I", os.path.join(HERE, "reconcile_role.py"), *a], capture_output=True, text=True)


class Role(unittest.TestCase):
    """R13 time-boxed Role for the reconcile DB read: ONLY committer-db-0 (no FSC pod: a key holder), never standing."""

    def docs(self):
        r = render()
        self.assertEqual(r.returncode, 0, r.stderr)
        return {d["kind"]: d for d in yaml.safe_load_all(r.stdout)}

    def test_role_names_exactly_committer_db_0_with_exactly_two_verbs(self):
        role = self.docs()["Role"]
        self.assertEqual(role["metadata"]["name"], "reconcile")
        self.assertEqual(role["metadata"]["namespace"], "rd-fabricx-bi")
        self.assertEqual(role["metadata"]["labels"], {"app.kubernetes.io/part-of": "rd-fabricx", "rd/r13": "time-boxed"})
        self.assertEqual(role["rules"], [
            {"apiGroups": [""], "resources": ["pods"], "resourceNames": ["committer-db-0"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["pods/exec"], "resourceNames": ["committer-db-0"], "verbs": ["create"]}])

    def test_no_fsc_pod_in_the_role_and_the_old_flag_is_gone(self):
        self.assertNotIn("rdbi-bi", yaml.safe_dump(self.docs()["Role"]))
        self.assertNotEqual(render("--fsc-pod", POD).returncode, 0)

    def test_no_list_watch_wildcard_or_other_resource(self):
        text = yaml.safe_dump(self.docs()["Role"])
        for bad in ("list", "watch", "'*'", "secrets", "deployments", "delete", "update", "patch", "pods/log", "pods/portforward", "pods/attach"):
            self.assertNotIn(bad, text)

    def test_binding_is_bi_own_party_credential_only(self):
        b = self.docs()["RoleBinding"]
        self.assertEqual(b["metadata"]["namespace"], "rd-fabricx-bi")
        self.assertEqual(b["subjects"], [{"kind": "ServiceAccount", "name": "party-admin", "namespace": "rd-fabricx-bi"}])
        self.assertEqual(b["roleRef"], {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reconcile"})

    def test_deterministic(self):
        self.assertEqual(render().stdout, render().stdout)


if __name__ == "__main__":
    unittest.main()
