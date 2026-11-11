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
    def docs(self, pod=POD):
        r = render("--fsc-pod", pod)
        self.assertEqual(r.returncode, 0, r.stderr)
        return {d["kind"]: d for d in yaml.safe_load_all(r.stdout)}

    def test_role_names_exactly_two_pods_with_exactly_two_verbs(self):
        role = self.docs()["Role"]
        self.assertEqual(role["metadata"], {"name": "reconcile", "namespace": "rd-fabricx-bi", "labels": {"app.kubernetes.io/part-of": "rd-fabricx"}})
        names = ["committer-db-0", POD]
        self.assertEqual(role["rules"], [
            {"apiGroups": [""], "resources": ["pods"], "resourceNames": names, "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["pods/exec"], "resourceNames": names, "verbs": ["create"]}])

    def test_no_list_watch_wildcard_or_other_resource(self):
        text = yaml.safe_dump(self.docs()["Role"])
        for bad in ("list", "watch", "'*'", "secrets", "deployments", "delete", "update", "patch", "pods/log", "pods/portforward"):
            self.assertNotIn(bad, text)

    def test_binding_is_bi_own_party_credential_only(self):
        b = self.docs()["RoleBinding"]
        self.assertEqual(b["metadata"]["namespace"], "rd-fabricx-bi")
        self.assertEqual(b["subjects"], [{"kind": "ServiceAccount", "name": "party-admin", "namespace": "rd-fabricx-bi"}])
        self.assertEqual(b["roleRef"], {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reconcile"})

    def test_pod_name_must_be_the_bi_fsc_pod(self):
        for bad in ("committer-db-0", "rdbi-bank2-abc-def", "rdbi-bi", "rdbi-bi-x y-z", "rdbi-bi-6f58bd75d4-pmd9s\nextra", "", "*"):
            self.assertNotEqual(render("--fsc-pod", bad).returncode, 0, bad)

    def test_no_pod_name_no_role(self):
        self.assertNotEqual(render().returncode, 0)

    def test_deterministic(self):
        self.assertEqual(render("--fsc-pod", POD).stdout, render("--fsc-pod", POD).stdout)


if __name__ == "__main__":
    unittest.main()
