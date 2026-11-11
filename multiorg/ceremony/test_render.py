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


LOCK = "rd/egress-locked"


class Locked(Base):
    """R16 (option iv): the namespace policy allow-dns-egress skips pods labelled rd/egress-locked, so a Job's own narrow policy is the ONLY egress it gets."""

    def probe(self, party="bi", **kw):
        a = dict(image=IMG, name="p1", tries=["ext=1.1.1.1:443"], allow=[])
        a.update(kw)
        return list(yaml.safe_load_all(render.render_probe(party, **a)))

    def test_endorse_job_pod_is_labelled(self):
        for p in PARTIES:
            self.assertEqual(self.by(self.job(p), "Job")["spec"]["template"]["metadata"]["labels"][LOCK], "true")

    def test_job_mounting_a_secret_without_the_label_fails(self):
        docs = self.job("bi")
        job = self.by(docs, "Job")
        del job["spec"]["template"]["metadata"]["labels"][LOCK]
        with self.assertRaises(SystemExit):
            render.check_locked(docs)
        render.check_locked(self.job("bi"))

    def test_probe_job_is_labelled_mounts_no_secret_and_has_its_own_policy(self):
        docs = self.probe(allow=["pod=orderer-router-1:8013", "dns"])
        job, np = self.by(docs, "Job"), self.by(docs, "NetworkPolicy")
        pod = job["spec"]["template"]
        self.assertEqual(pod["metadata"]["labels"][LOCK], "true")
        self.assertNotIn("volumes", pod["spec"])   # no volume at all, so no Secret
        self.assertEqual(np["spec"]["policyTypes"], ["Ingress", "Egress"])
        self.assertNotIn("ingress", np["spec"])
        for k, v in np["spec"]["podSelector"]["matchLabels"].items():
            self.assertEqual(pod["metadata"]["labels"][k], v)
        self.assertEqual(np["spec"]["egress"], [
            {"to": [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": "orderer-router-1"}}}], "ports": [{"port": 8013, "protocol": "TCP"}]},
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]}])

    def test_probe_ip_allow_form_is_one_host_one_port(self):
        np = self.by(self.probe(allow=["ip=10.200.0.1/32:443"]), "NetworkPolicy")["spec"]
        self.assertEqual(np["egress"], [{"to": [{"ipBlock": {"cidr": "10.200.0.1/32"}}], "ports": [{"port": 443, "protocol": "TCP"}]}])
        for bad in ("ip=10.200.0.0/24:443", "ip=0.0.0.0/32:443", "ip=10.200.0.1/32:0", "ip=10.200.0.1:443", "ip=300.1.1.1/32:443"):
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    self.probe(allow=[bad])

    def test_probe_nspod_allow_form_selects_namespace_and_pod_together(self):
        np = self.by(self.probe(allow=["nspod=rd-fabricx-bank-b/rdbi-bank3:5107"]), "NetworkPolicy")["spec"]
        self.assertEqual(np["egress"], [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "rd-fabricx-bank-b"}}, "podSelector": {"matchLabels": {"app.kubernetes.io/name": "rdbi-bank3"}}}],
                                          "ports": [{"port": 5107, "protocol": "TCP"}]}])
        for bad in ("nspod=kube-system/x:1", "nspod=default/x:1", "nspod=rd-fabricx-bank-b/x:0", "nspod=rd-fabricx-bank-b/x", "nspod=rd-fabricx-a b/x:1"):
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    self.probe(allow=[bad])

    def test_probe_without_allow_has_no_egress_rules(self):
        np = self.by(self.probe(), "NetworkPolicy")
        self.assertNotIn("egress", np["spec"])

    def test_probe_command_tries_each_target_and_is_bounded(self):
        c = self.by(self.probe(tries=["ext=1.1.1.1:443", "api=kubernetes.default.svc:443"]), "Job")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["command"][:2], ["bash", "-c"])
        self.assertEqual(c["command"][3:], ["probe", "ext=1.1.1.1:443", "api=kubernetes.default.svc:443"])
        self.assertIn("timeout 4", c["command"][2])
        self.assertEqual(self.by(self.probe(), "Job")["spec"]["activeDeadlineSeconds"], 120)

    def test_probe_args_are_checked(self):
        for kw in (dict(tries=["bad"]), dict(tries=[]), dict(allow=["pod=x"]), dict(allow=["pod=a:70000"]), dict(allow=["any"]), dict(name="X Y"), dict(image="repo:latest")):
            with self.subTest(kw=kw):
                with self.assertRaises(SystemExit):
                    self.probe(**kw)
        with self.assertRaises(SystemExit):
            self.probe("bank-d")


class Net(Base):
    """S14 submit + read-back Jobs of BI (orchestrator S1): committer-tls is the TLS client identity for the router / sidecar / query mTLS."""

    def net(self, kind, party="bi", **kw):
        a = dict(image=IMG, tx_name="tx1")
        if kind == "submit":
            a.update(tx=self.tx)
        a.update(cacert=self.ca, mspca=self.ca)
        a.update(kw)
        return list(yaml.safe_load_all(render.render_net(kind, party, **a)))

    def sources(self, docs):
        v = self.by(docs, "Job")["spec"]["template"]["spec"]["volumes"]
        self.assertEqual(len(v), 1)
        return v[0]["projected"]["sources"], v[0]["projected"]["defaultMode"]

    def test_submit_volumes_are_exactly_the_conditions_list(self):
        src, mode = self.sources(self.net("submit"))
        self.assertEqual(mode, 0o440)   # 0400 would be unreadable for uid 10001 (files are root-owned, fsGroup gives group read)
        self.assertEqual(len(src), 3)
        self.assertEqual(src[0], {"secret": {"name": "orderer-admin-1-secret", "items": [{"key": "msp-keystore-priv_sk", "path": "msp/keystore/priv_sk"}, {"key": "msp-signcert.pem", "path": "msp/signcerts/cert.pem"}]}})
        self.assertEqual(src[1], {"secret": {"name": "committer-tls", "items": [{"key": "server.crt", "path": "tls/client.crt"}, {"key": "server.key", "path": "tls/client.key"}, {"key": "ca.crt", "path": "tls/ca.crt"}]}})
        self.assertEqual(src[2]["configMap"]["name"], "s14-submit-in-tx1")
        self.assertEqual(sorted(i["path"] for i in src[2]["configMap"]["items"]), ["config.yaml", "msp/cacerts/ca.pem", "tlsca.pem", "tx.json"])   # live 21:06Z: fxconfig loads the MSP from /w/msp and needs cacerts/

    def test_readback_has_no_signing_key_and_no_tx(self):
        docs = self.net("readback")
        src, _ = self.sources(docs)
        self.assertEqual([s_.get("secret", {}).get("name") or s_["configMap"]["name"] for s_ in src], ["committer-tls", "s14-readback-in-tx1"])
        self.assertNotIn("orderer-admin", yaml.safe_dump(docs))
        self.assertEqual(sorted(self.by(docs, "ConfigMap")["data"]), ["config.yaml", "mspca.pem", "tlsca.pem"])

    def test_commands_are_exact_and_without_a_shell(self):
        c = lambda k: self.by(self.net(k), "Job")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c("submit")["command"], ["fxconfig", "--config", "/w/config.yaml", "tx", "submit", "/w/tx.json", "--wait"])
        self.assertEqual(c("readback")["command"], ["fxconfig", "--config", "/w/config.yaml", "namespace", "list"])

    def test_pod_is_locked_hardened_bounded(self):
        for k in ("submit", "readback"):
            job = self.by(self.net(k), "Job")
            pod = job["spec"]["template"]
            self.assertEqual(pod["metadata"]["labels"][LOCK], "true")
            self.assertEqual((job["spec"]["backoffLimit"], job["spec"]["activeDeadlineSeconds"], job["spec"]["ttlSecondsAfterFinished"]), (0, 120, 900))
            self.assertFalse(pod["spec"]["automountServiceAccountToken"])
            sc = pod["spec"]["containers"][0]["securityContext"]
            self.assertTrue(sc["readOnlyRootFilesystem"] and sc["runAsNonRoot"] and not sc["allowPrivilegeEscalation"])
            self.assertNotIn("env", pod["spec"]["containers"][0])
            render.check_locked(self.net(k))

    def test_egress_is_exactly_the_named_endpoints_plus_dns(self):
        dns = {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]}
        pod = lambda a, p: {"to": [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": a}}}], "ports": [{"port": p, "protocol": "TCP"}]}
        sub, rb = self.by(self.net("submit"), "NetworkPolicy"), self.by(self.net("readback"), "NetworkPolicy")
        self.assertEqual(sub["spec"]["egress"], [pod("orderer-router-1", 8013), pod("committer-sidecar", 5130), dns])
        self.assertEqual(rb["spec"]["egress"], [pod("committer-query", 5140), dns])
        for np in (sub, rb):
            self.assertEqual(np["spec"]["policyTypes"], ["Ingress", "Egress"])
            self.assertNotIn("ingress", np["spec"])

    def test_config_points_at_in_cluster_names_with_the_router_sni(self):
        cfg = yaml.safe_load(self.by(self.net("submit"), "ConfigMap")["data"]["config.yaml"])
        self.assertEqual(cfg["msp"], {"localMspID": "org1", "configPath": "/w/msp"})
        self.assertEqual(cfg["tls"], {"enabled": True, "clientCert": "/w/tls/client.crt", "clientKey": "/w/tls/client.key", "rootCerts": ["/w/tlsca.pem", "/w/tls/ca.crt"]})
        self.assertEqual(cfg["orderer"]["address"], "lb-1:8013")
        self.assertEqual(cfg["orderer"]["tls"]["serverNameOverride"], "router-1.arma.rd")
        self.assertEqual(cfg["notifications"]["address"], "committer-sidecar:5130")
        self.assertEqual(cfg["queries"]["address"], "committer-query-service:5140")

    def test_only_bi_and_checked_inputs(self):
        for bad in (dict(party="bank-a"), dict(party="bank-d"), dict(image="repo:latest"), dict(tx_name="A B")):
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    self.net("submit", **bad)
        with self.assertRaises(SystemExit):
            self.net("other")
        open(self.ca, "w").write(CERT + "PRIVATE KEY")
        with self.assertRaises(SystemExit):
            self.net("submit")
        open(self.ca, "w").write(CERT)
        with self.assertRaises(SystemExit):   # the MSP CA is required (public cert), also for readback
            self.net("submit", mspca=None)


class SetupPP(Base):
    """(b) qa finding (f): setup-pp as a one-shot Job under BI's own party-admin, not a cluster-admin exec. Mounts only the gateway client identity + public params that the existing Deployment mounts."""

    def pp(self, **kw):
        a = dict(image=IMG, name="pp1")
        a.update(kw)
        return list(yaml.safe_load_all(render.render_setuppp("bi", **a)))

    def test_objects_and_volumes_are_exactly_the_gateway_client_identity(self):
        docs = self.pp()
        self.assertEqual(sorted((d["kind"], d["metadata"]["name"]) for d in docs), [("Job", "s14-setuppp-pp1"), ("NetworkPolicy", "s14-setuppp-egress")])
        spec = self.by(docs, "Job")["spec"]["template"]["spec"]
        vols = {v["name"]: v for v in spec["volumes"]}
        self.assertEqual(sorted(vols), ["home", "live"])
        self.assertEqual(vols["home"], {"name": "home", "emptyDir": {}})
        src = vols["live"]["projected"]["sources"]
        self.assertEqual(vols["live"]["projected"]["defaultMode"], 0o440)
        self.assertEqual(src, [
            {"configMap": {"name": "fx-gw-1-client", "items": [{"key": "client-config.yaml", "path": "live/issuer/client-config.yaml"}, {"key": "issuer-gw.pem", "path": "gw/issuer-gw.pem"}, {"key": "public-params.bin", "path": "live/public-params.bin"}]}},
            {"secret": {"name": "fx-gw-1-client", "items": [{"key": "gw.key", "path": "gw/issuer-gw.key"}]}},
            {"configMap": {"name": "rdbi-public", "items": [{"key": "ca-bundle.pem", "path": "live/issuer/tls-ca.crt"}]}}])
        mounts = {m["name"]: (m["mountPath"], m.get("readOnly", False)) for m in spec["containers"][0]["volumeMounts"]}
        self.assertEqual(mounts, {"home": ("/home/rdbi", False), "live": ("/home/rdbi/.fabricx-token", True)})

    def test_command_env_and_label(self):
        job = self.by(self.pp(), "Job")
        c = job["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["command"], ["rdbi-driver", "setup-pp"])
        self.assertEqual(c["env"], [{"name": "HOME", "value": "/home/rdbi"}, {"name": "NAMESPACE", "value": "rd_dfabi_v2"}])
        self.assertEqual(job["spec"]["template"]["metadata"]["labels"][LOCK], "true")
        self.assertEqual((job["spec"]["backoffLimit"], job["spec"]["activeDeadlineSeconds"], job["spec"]["ttlSecondsAfterFinished"]), (0, 180, 900))
        render.check_locked(self.pp())

    def test_egress_is_the_issuer_view_port_plus_dns_only(self):
        np = self.by(self.pp(), "NetworkPolicy")["spec"]
        self.assertEqual(np["policyTypes"], ["Ingress", "Egress"])
        self.assertNotIn("ingress", np)
        self.assertEqual(np["egress"], [
            {"to": [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": "rdbi-bi"}}}], "ports": [{"port": 5100, "protocol": "TCP"}]},
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]}])

    def test_hardened_and_checked(self):
        spec = self.by(self.pp(), "Job")["spec"]["template"]["spec"]
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertTrue(spec["containers"][0]["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(spec["imagePullSecrets"], [{"name": "ghcr-pull"}])
        for bad in (dict(image="repo:latest"), dict(name="A B"), dict(namespace="x y")):
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    self.pp(**bad)
        with self.assertRaises(SystemExit):
            render.render_setuppp("bank-a", image=IMG, name="pp1")

    def test_namespace_is_an_argument_with_the_default(self):
        c = self.by(self.pp(namespace="rd_other"), "Job")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["env"][1], {"name": "NAMESPACE", "value": "rd_other"})


if __name__ == "__main__":
    unittest.main()
