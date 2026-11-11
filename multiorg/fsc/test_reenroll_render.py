"""Offline tests for multiorg/fsc/reenroll_render.py: the in-namespace Job that re-issues one FSC identity cert (SAN fix) with `fabric-ca-client reenroll`, authenticated by the CURRENT cert+key,
without any CA admin password. Constraints: digest image, own SA, time-boxed Role (resourceNames [rdbi-<pod>-files], get+patch), egress-locked pod, egress only own CA + API server + DNS.

  python3 -m unittest discover -s multiorg/fsc
"""
import os, subprocess, sys, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reenroll_render as rr

IMG = "ghcr.io/example/fsc-reenroll@sha256:" + "7" * 64
API = "10.200.0.1/32"
POD = {"bi": "bi", "bank-a": "bank2", "bank-b": "bank3", "bank-c": "bank4"}
NODES = {"bi": ["issuer", "endorser-1"], "bank-a": ["bank2", "endorser-2"], "bank-b": ["bank3", "endorser-3"], "bank-c": ["bank4", "endorser-4"]}


def docs(text):
    return list(yaml.safe_load_all(text))


def by(ds, kind):
    r = [d for d in ds if d["kind"] == kind]
    assert len(r) == 1, kind
    return r[0]


class Role(unittest.TestCase):
    def test_role_is_one_secret_get_patch_only(self):
        for p in POD:
            ds = docs(rr.render_role(p))
            role = by(ds, "Role")
            self.assertEqual(role["metadata"]["namespace"], f"rd-fabricx-{p}")
            self.assertEqual(role["rules"], [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": [f"rdbi-{POD[p]}-files"], "verbs": ["get", "patch"]}])
            rb = by(ds, "RoleBinding")
            self.assertEqual(rb["subjects"], [{"kind": "ServiceAccount", "name": "fsc-reenroll", "namespace": f"rd-fabricx-{p}"}])
            self.assertEqual(by(ds, "ServiceAccount")["metadata"]["name"], "fsc-reenroll")

    def test_unknown_party_refused(self):
        with self.assertRaises(SystemExit):
            rr.render_role("bank-d")


class Job(unittest.TestCase):
    def job(self, party="bank-b", node=None, **kw):
        a = dict(image=IMG, name="g1", api_cidr=API)
        a.update(kw)
        return docs(rr.render_job(party, node or NODES[party][1], **a))

    def test_objects_and_names(self):
        ds = self.job()
        self.assertEqual(sorted((d["kind"], d["metadata"]["name"]) for d in ds), [("Job", "fsc-reenroll-endorser-3-g1"), ("NetworkPolicy", "fsc-reenroll-endorser-3-g1-egress")])

    def test_volumes_are_exactly_the_two_identity_items_and_a_scratch_dir(self):
        spec = by(self.job(), "Job")["spec"]["template"]["spec"]
        vols = {v["name"]: v for v in spec["volumes"]}
        self.assertEqual(sorted(vols), ["in", "work"])
        self.assertEqual(vols["in"], {"name": "in", "secret": {"secretName": "rdbi-bank3-files", "defaultMode": 0o440, "items": [
            {"key": "own__endorser-3__fsc__cert.pem", "path": "cert.pem"}, {"key": "own__endorser-3__fsc__key.pem", "path": "key.pem"}]}})
        self.assertEqual(vols["work"], {"name": "work", "emptyDir": {"medium": "Memory"}})
        mounts = {m["name"]: (m["mountPath"], m.get("readOnly", False)) for m in spec["containers"][0]["volumeMounts"]}
        self.assertEqual(mounts, {"in": ("/in", True), "work": ("/work", False)})

    def test_pod_is_locked_uses_its_own_sa_with_a_token_and_is_bounded(self):
        job = by(self.job(), "Job")
        pod = job["spec"]["template"]
        self.assertEqual(pod["metadata"]["labels"]["rd/egress-locked"], "true")
        self.assertEqual(pod["spec"]["serviceAccountName"], "fsc-reenroll")
        self.assertTrue(pod["spec"]["automountServiceAccountToken"])   # the helper PATCHes one Secret through the API
        self.assertEqual((job["spec"]["backoffLimit"], job["spec"]["activeDeadlineSeconds"], job["spec"]["ttlSecondsAfterFinished"]), (0, 180, 900))
        sc = pod["spec"]["containers"][0]["securityContext"]
        self.assertTrue(sc["readOnlyRootFilesystem"] and sc["runAsNonRoot"] and not sc["allowPrivilegeEscalation"])
        self.assertEqual(pod["spec"]["imagePullSecrets"], [{"name": "ghcr-pull"}])

    def test_command_has_no_secret_and_no_ca_password(self):
        c = by(self.job(), "Job")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["command"][0], "fsc-reenroll")
        self.assertEqual(c["command"][1:], ["--node", "endorser-3", "--ca-url", "http://fca-org3.rd-fabricx-bank-b.svc.cluster.local:7054",
                                            "--hosts", "endorser-3,endorser-3.rd-fabricx-bank-b.svc.cluster.local", "--names", "C=US,ST=North Carolina,O=Hyperledger",
                                            "--secret", "rdbi-bank3-files", "--in", "/in", "--work", "/work",
                                            "--keys", "own__endorser-3__fsc__cert.pem,own__endorser-3__fsc__key.pem", "--gen", "g1"])
        text = yaml.safe_dump(by(self.job(), "Job"))
        for bad in ("password", "FABRIC_CA_CLIENT_URL", "admin.pass", "fca-org3-admin", "env:"):
            self.assertNotIn(bad, text)

    def test_egress_is_own_ca_api_server_and_dns_only(self):
        np = by(self.job(), "NetworkPolicy")["spec"]
        self.assertEqual(np["policyTypes"], ["Ingress", "Egress"])
        self.assertNotIn("ingress", np)
        self.assertEqual(np["egress"], [
            {"to": [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": "fca-org3"}}}], "ports": [{"port": 7054, "protocol": "TCP"}]},
            {"to": [{"ipBlock": {"cidr": API}}], "ports": [{"port": 443, "protocol": "TCP"}]},
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]}])

    def test_modes_add_exactly_one_flag(self):
        cmd = lambda **kw: by(self.job(**kw), "Job")["spec"]["template"]["spec"]["containers"][0]["command"]
        self.assertEqual(cmd(mode="dry-run")[-1], "--dry-run")
        self.assertEqual(cmd(mode="remove-prev")[-1], "--remove-prev")
        self.assertNotIn("--dry-run", cmd())
        self.assertNotIn("--remove-prev", cmd())
        with self.assertRaises(SystemExit):
            self.job(mode="delete")

    def test_remove_prev_job_mounts_no_identity(self):
        spec = by(self.job(mode="remove-prev"), "Job")["spec"]["template"]["spec"]
        self.assertEqual(sorted(v["name"] for v in spec["volumes"]), ["work"])

    def test_every_node_of_every_party(self):
        for p, nodes in NODES.items():
            for node in nodes:
                with self.subTest(p=p, node=node):
                    j = by(self.job(p, node), "Job")
                    self.assertEqual(j["metadata"]["namespace"], f"rd-fabricx-{p}")
                    src = j["spec"]["template"]["spec"]["volumes"][0]["secret"]
                    self.assertEqual(src["secretName"], f"rdbi-{POD[p]}-files")

    def test_checked_inputs(self):
        for kw in (dict(image="repo:latest"), dict(name="A B"), dict(api_cidr="0.0.0.0/0"), dict(api_cidr="10.0.0.0/24"), dict(api_cidr="x")):
            with self.subTest(kw=kw):
                with self.assertRaises(SystemExit):
                    self.job(**kw)
        with self.assertRaises(SystemExit):
            self.job("bank-b", "bank2")        # a node of another party
        with self.assertRaises(SystemExit):
            self.job("bank-d", "x")

    def test_cli(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "reenroll_render.py"), "job", "bi", "issuer", "--image", IMG, "--name", "g1", "--api-cidr", API], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sum(1 for d in docs(r.stdout) if d and d["kind"] == "Job"), 1)


if __name__ == "__main__":
    unittest.main()
