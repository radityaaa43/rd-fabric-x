"""Offline tests for multiorg/ceremony/render.py (fabricx S14 ceremony: the in-namespace signing Job of one org, analyst conditions 1-9). No cluster, no key read.

  python3 -m unittest discover -s multiorg/ceremony
"""
import importlib.util, os, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("ceremony_render", os.path.join(HERE, "render.py"))
render = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render)

PARTIES = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
IMG = "ghcr.io/example/fabricx-tools-ci@sha256:" + "9" * 64
CERT = "-----BEGIN CERTIFICATE-----\nMIIca\n-----END CERTIFICATE-----\n"
TX = '{"tx_id":"abc","data":"ZGF0YQ=="}'


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tx, self.ca = f"{self.tmp.name}/tx1.json", f"{self.tmp.name}/ca.pem"
        open(self.tx, "w").write(TX)
        open(self.ca, "w").write(CERT)

    def job(self, party, **kw):
        a = dict(tx=self.tx, cacert=self.ca, image=IMG, tx_name="tx1")
        a.update(kw)
        return list(yaml.safe_load_all(render.render_job(party, **a)))

    def by(self, docs, kind):
        r = [d for d in docs if d["kind"] == kind]
        self.assertEqual(len(r), 1, kind)
        return r[0]


class Role(Base):
    def test_role_is_jobs_create_get_pods_get_logs_get_only(self):
        for p in PARTIES:
            docs = list(yaml.safe_load_all(render.render_role(p)))
            role = self.by(docs, "Role")
            self.assertEqual(role["metadata"]["namespace"], f"rd-fabricx-{p}")
            self.assertEqual(role["metadata"]["name"], "s14-sign")
            self.assertEqual(role["rules"], [
                {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["create", "get"]},
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]},
                {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]}])
            text = yaml.safe_dump(role)
            for bad in ("secrets", "pods/exec", "delete", "update", "patch", "list", "watch", "'*'", "deployments"):
                self.assertNotIn(bad, text)

    def test_binding_is_the_orgs_own_party_admin_only(self):
        b = self.by(list(yaml.safe_load_all(render.render_role("bank-c"))), "RoleBinding")
        self.assertEqual(b["metadata"]["namespace"], "rd-fabricx-bank-c")
        self.assertEqual(b["subjects"], [{"kind": "ServiceAccount", "name": "party-admin", "namespace": "rd-fabricx-bank-c"}])
        self.assertEqual(b["roleRef"], {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "s14-sign"})

    def test_unknown_party_refused(self):
        with self.assertRaises(SystemExit):
            render.render_role("bank-d")


class Job(Base):
    def test_objects_per_org(self):
        for p, n in PARTIES.items():
            docs = self.job(p)
            self.assertEqual(sorted(d["kind"] for d in docs), ["ConfigMap", "Job", "NetworkPolicy", "ServiceAccount"])
            for d in docs:
                self.assertEqual(d["metadata"]["namespace"], f"rd-fabricx-{p}")
            self.assertFalse([d for d in docs if d["kind"] == "Secret"])

    def test_1_image_by_digest_only(self):
        for bad in ("ghcr.io/x/y:latest", "ghcr.io/x/y", "ghcr.io/x/y@sha256:abc"):
            with self.assertRaises(SystemExit):
                self.job("bi", image=bad)
        pod = self.by(self.job("bi"), "Job")["spec"]["template"]["spec"]
        self.assertEqual([c["image"] for c in pod["containers"]], [IMG])
        self.assertNotIn("initContainers", pod)

    def test_2_dedicated_serviceaccount_without_token(self):
        docs = self.job("bank-a")
        sa = self.by(docs, "ServiceAccount")
        self.assertEqual(sa["metadata"]["name"], "s14-signer")
        self.assertIs(sa["automountServiceAccountToken"], False)
        pod = self.by(docs, "Job")["spec"]["template"]["spec"]
        self.assertEqual(pod["serviceAccountName"], "s14-signer")
        self.assertIs(pod["automountServiceAccountToken"], False)

    def test_3_volumes_only_the_admin_secret_and_the_input_configmap(self):
        for p, n in PARTIES.items():
            pod = self.by(self.job(p), "Job")["spec"]["template"]["spec"]
            self.assertEqual(len(pod["volumes"]), 1)
            srcs = pod["volumes"][0]["projected"]["sources"]
            self.assertEqual(sorted(("secret" if "secret" in s else "configMap", (s.get("secret") or s["configMap"])["name"]) for s in srcs),
                             sorted([("secret", f"orderer-admin-{n}-secret"), ("configMap", f"s14-in-tx1")]))
            sec = [s["secret"] for s in srcs if "secret" in s][0]
            self.assertEqual(sec["items"], [{"key": "msp-keystore-priv_sk", "path": "msp/keystore/priv_sk"}, {"key": "msp-signcert.pem", "path": "msp/signcerts/cert.pem"}])
            cm = [s["configMap"] for s in srcs if "configMap" in s][0]
            self.assertEqual(sorted(i["path"] for i in cm["items"]), ["config.yaml", "msp/cacerts/ca.pem", "tx.json"])
            mounts = self.by(self.job(p), "Job")["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
            self.assertEqual([(m["mountPath"], m["readOnly"]) for m in mounts], [("/w", True)])
            self.assertNotIn("env", self.by(self.job(p), "Job")["spec"]["template"]["spec"]["containers"][0])

    def test_4_network_policy_denies_everything_for_the_job_pod(self):
        docs = self.job("bi")
        np = self.by(docs, "NetworkPolicy")
        job = self.by(docs, "Job")
        self.assertEqual(np["spec"]["policyTypes"], ["Ingress", "Egress"])
        self.assertNotIn("ingress", np["spec"])
        self.assertNotIn("egress", np["spec"])
        sel = np["spec"]["podSelector"]["matchLabels"]
        for k, v in sel.items():
            self.assertEqual(job["spec"]["template"]["metadata"]["labels"][k], v)

    def test_5_hardened_security_context(self):
        pod = self.by(self.job("bank-c"), "Job")["spec"]["template"]["spec"]
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertEqual(pod["securityContext"]["seccompProfile"], {"type": "RuntimeDefault"})
        sc = pod["containers"][0]["securityContext"]
        self.assertTrue(sc["runAsNonRoot"])
        self.assertTrue(sc["readOnlyRootFilesystem"])
        self.assertFalse(sc["allowPrivilegeEscalation"])
        self.assertEqual(sc["capabilities"], {"drop": ["ALL"]})
        self.assertEqual(sc["runAsUser"], 10001)

    def test_6_no_retry_a_deadline_and_a_ttl(self):
        spec = self.by(self.job("bi"), "Job")["spec"]
        self.assertEqual(spec["backoffLimit"], 0)
        self.assertEqual(spec["activeDeadlineSeconds"], 120)
        self.assertEqual(spec["ttlSecondsAfterFinished"], 900)
        self.assertEqual(spec["template"]["spec"]["restartPolicy"], "Never")

    def test_7_output_is_the_log_only_and_the_command_has_no_shell(self):
        c = self.by(self.job("bi"), "Job")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["command"], ["fxconfig", "--config", "/w/config.yaml", "tx", "endorse", "/w/tx.json"])
        self.assertNotIn("--output", c["command"])
        self.assertNotIn("args", c)

    def test_input_configmap_is_public_only_and_config_points_at_the_org_msp(self):
        for p, n in PARTIES.items():
            cm = self.by(self.job(p), "ConfigMap")
            self.assertEqual(cm["metadata"]["name"], "s14-in-tx1")
            self.assertEqual(sorted(cm["data"]), ["ca.pem", "config.yaml", "tx.json"])
            self.assertEqual(cm["data"]["tx.json"], TX)
            self.assertEqual(cm["data"]["ca.pem"], CERT)
            cfg = yaml.safe_load(cm["data"]["config.yaml"])
            self.assertEqual(cfg, {"msp": {"localMspID": f"org{n}", "configPath": "/w/msp"}})
            self.assertNotIn("PRIVATE KEY", yaml.safe_dump(cm))

    def test_private_key_in_the_inputs_is_refused(self):
        open(self.ca, "w").write(CERT + "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n")
        with self.assertRaises(SystemExit):
            self.job("bi")
        open(self.ca, "w").write(CERT)
        open(self.tx, "w").write(TX + "-----BEGIN EC PRIVATE KEY-----")
        with self.assertRaises(SystemExit):
            self.job("bi")

    def test_names_are_checked(self):
        for bad in ("TX1", "tx 1", "../x", "", "a" * 40):
            with self.assertRaises(SystemExit):
                self.job("bi", tx_name=bad)
        with self.assertRaises(SystemExit):
            self.job("bank-d")

    def test_cli(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "render.py"), "job", "bi", "--tx", self.tx, "--cacert", self.ca, "--image", IMG, "--tx-name", "tx1"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sum(1 for d in yaml.safe_load_all(r.stdout) if d and d["kind"] == "Job"), 1)
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "render.py"), "role", "bank-c"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
