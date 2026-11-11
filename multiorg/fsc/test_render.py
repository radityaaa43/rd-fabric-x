"""Offline tests for multiorg/fsc/render.py (fabricx S13 piece 3: the FSC pod of one org). Fixture templates = test_core_rewrite.core(); no cluster.

  python3 -m unittest discover -s multiorg/fsc
"""
import os, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import core_rewrite as cr
import enroll_fsc
import importlib.util
import test_core_rewrite as tcr
_spec = importlib.util.spec_from_file_location("fsc_render", os.path.join(HERE, "render.py"))   # fca/render.py has the same name
render = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render)

PARTIES = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
POD = {"bi": "bi", "bank-a": "bank2", "bank-b": "bank3", "bank-c": "bank4"}
DIGEST = "docker.io/example/rdbi@sha256:" + "a" * 64
CERT = "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n"
P2P = {"cluster1": {1: "10.200.1.1", 2: "10.200.1.2", 3: "10.200.1.3", 4: "47.1.1.4"}, "cluster2": {1: "8.1.1.1", 2: "8.1.1.2", 3: "8.1.1.3", 4: "10.210.1.4"}}
CENTRAL = {"issuer": ["own__issuer__ids__anon__msp__cacerts__ca.pem", "own__issuer__wallets__issuer-msp__x"],
           **{b: [f"own__{b}__ids__anon__msp__cacerts__ca.pem", f"own__{b}__wallets__{b}__x"] for b in ("bank2", "bank3", "bank4")}}


def make_inputs(root):
    for n in tcr.NODES:
        d = f"{root}/live/{n}"
        os.makedirs(d)
        with open(f"{d}/core.yaml", "w") as f:
            yaml.safe_dump(tcr.core(n), f)
        with open(f"{d}/role", "w") as f:
            f.write("issuer\n" if n == "issuer" else "endorser\n")
        with open(f"{d}/policy.env", "w") as f:
            f.write("RDBI_LIMIT=100\n")
    for m, party in enumerate(PARTIES, 1):
        for n in enroll_fsc.NODES[party][1]:
            for rel in (f"fsc/{n}.pem", f"ids/{n}/msp/signcerts/cert.pem", f"ids/{n}/msp/cacerts/ca.pem", f"admin/{n}-admin.pem"):
                p = f"{root}/fscx/org{m}/{rel}"
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f:
                    f.write(CERT.replace("MII", f"{n}-{rel.split('/')[0]}"))
        if m == 1:
            with open(f"{root}/bootstrap.pem", "w") as f:
                f.write(CERT.replace("MII", "BOOTSTRAP"))
        p = f"{root}/tlsx/org{m}/msp/tlscacerts/t.pem"
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(CERT.replace("MII", f"TLSCA{m}"))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        make_inputs(self.tmp.name)

    def r(self, party, **over):
        central = [k for n in enroll_fsc.NODES[party][1] for k in CENTRAL.get(n, [])]
        kw = dict(templates=f"{self.tmp.name}/live", fsc_exchange=f"{self.tmp.name}/fscx", tls_exchange=f"{self.tmp.name}/tlsx", image=DIGEST, p2p_ips=P2P,
                  central_keys=central, home=tcr.H, bootstrap_cert=f"{self.tmp.name}/bootstrap.pem")
        if party == "bank-c":
            kw["storage_class"] = "fabricx-essd"
        kw.update(over)
        return list(yaml.safe_load_all(render.render(party, **kw)))

    def by(self, docs, kind):
        return {d["metadata"]["name"]: d for d in docs if d["kind"] == kind}


class Shape(Base):
    def test_objects_and_order(self):
        for p, n in PARTIES.items():
            docs = self.r(p)
            nodes = enroll_fsc.NODES[p][1]
            got = [(d["kind"], d["metadata"]["name"]) for d in docs]
            want = [("ConfigMap", "rdbi-public")] + [("ConfigMap", f"rdbi-core-{x}") for x in nodes] + [("Service", x) for x in nodes] + \
                   [("PersistentVolumeClaim", f"rdbi-{POD[p]}-state"), ("NetworkPolicy", "rdbi-traffic"), ("Deployment", f"rdbi-{POD[p]}")]
            self.assertEqual(got, want, p)
            self.assertNotIn("Secret", [d["kind"] for d in docs])

    def test_deployment_security_and_images(self):
        for p in PARTIES:
            d = self.by(self.r(p), "Deployment")[f"rdbi-{POD[p]}"]
            self.assertEqual(d["spec"]["strategy"], {"type": "Recreate"})
            spec = d["spec"]["template"]["spec"]
            self.assertEqual(spec["securityContext"]["runAsNonRoot"], True)
            self.assertEqual(spec["securityContext"]["runAsUser"], 10001)
            self.assertEqual(spec["securityContext"]["fsGroup"], 10001)
            self.assertEqual(spec["imagePullSecrets"], [{"name": "ghcr-pull"}])
            for c in spec["initContainers"] + spec["containers"]:
                self.assertEqual(c["image"], DIGEST)
                self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False)
                self.assertEqual(c["securityContext"]["capabilities"], {"drop": ["ALL"]})
                self.assertIn("limits", c["resources"])
                self.assertIn("requests", c["resources"])
            self.assertEqual([c["name"] for c in spec["containers"]], enroll_fsc.NODES[p][1])

    def test_tag_image_refused(self):
        with self.assertRaises(SystemExit):
            self.r("bi", image="docker.io/example/rdbi:latest")

    def test_node_env_and_services(self):
        d = self.by(self.r("bank-a"), "Deployment")["rdbi-bank2"]["spec"]["template"]["spec"]["containers"]
        env = {c["name"]: {e["name"]: e["value"] for e in c["env"]} for c in d}
        self.assertEqual(env["bank2"]["FSCNODE_CFG_PATH"], f"{tcr.T}/live/bank2")
        self.assertEqual(env["bank2"]["RDBI_ROLE"], "endorser")
        self.assertEqual(env["bank2"]["RDBI_LIMIT"], "100")
        svc = self.by(self.r("bank-a"), "Service")
        self.assertEqual({p["name"]: p["port"] for p in svc["bank2"]["spec"]["ports"]}, {"grpc": tcr.GRPC["bank2"], "p2p": tcr.GRPC["bank2"] + 1, "web": tcr.GRPC["bank2"] + 2})
        self.assertEqual(svc["bank2"]["spec"]["selector"], {"app.kubernetes.io/name": "rdbi-bank2"})


class Content(Base):
    def test_core_configmap_is_the_rewriter_output(self):
        for n in ("bank2", "endorser-2"):
            cm = self.by(self.r("bank-a"), "ConfigMap")[f"rdbi-core-{n}"]
            got = yaml.safe_load(cm["data"]["core.yaml"])
            want, _ = cr.per_org_core(tcr.core(n), n, tcr.H, tcr.T)
            self.assertEqual(got, want)
            self.assertNotIn("/home/ecs-user", cm["data"]["core.yaml"])

    def test_public_configmap_has_all_certs_and_the_tls_ca_bundle_and_no_key(self):
        cm = self.by(self.r("bank-b"), "ConfigMap")["rdbi-public"]["data"]
        for n in tcr.NODES:
            self.assertIn(f"fsc__{n}.pem", cm)
            self.assertIn(f"ids__{n}__msp__signcerts__cert.pem", cm)
            self.assertIn(f"ids__{n}__msp__cacerts__ca.pem", cm)
        for m in (1, 2, 3, 4):
            self.assertIn(f"TLSCA{m}", cm["ca-bundle.pem"])
        self.assertNotIn("PRIVATE KEY", "".join(cm.values()))

    def test_bootstrap_node_public_cert_is_shipped_and_required(self):
        cm = self.by(self.r("bank-a"), "ConfigMap")["rdbi-public"]["data"]
        self.assertIn("BOOTSTRAP", cm["fsc__lib-p2p-bootstrap-node.pem"])
        with self.assertRaises(SystemExit):
            self.r("bank-a", bootstrap_cert=None)

    def test_own_volume_sources_are_exactly_own_secret_endorser_secret_and_arma_public(self):
        for p, n in PARTIES.items():
            spec = self.by(self.r(p), "Deployment")[f"rdbi-{POD[p]}"]["spec"]["template"]["spec"]
            vol = {v["name"]: v for v in spec["volumes"]}
            src = vol["own"]["projected"]["sources"]
            secrets = sorted(s["secret"]["name"] for s in src if "secret" in s)
            self.assertEqual(secrets, sorted([f"rdbi-{POD[p]}-files", f"fsc-endorser-{n}-secret"]))
            self.assertEqual(sorted(s["configMap"]["name"] for s in src if "configMap" in s), [f"arma-public-{n}"])
            own = next(s for s in src if s.get("secret", {}).get("name") == f"rdbi-{POD[p]}-files")["secret"]["items"]
            paths = {i["path"] for i in own}
            for node in enroll_fsc.NODES[p][1]:
                for rel in enroll_fsc.own_files(node):
                    self.assertIn(f"{node}/{rel}", paths)
            for s in src:
                self.assertNotIn("driver", str(s))

    def test_endorser_msp_comes_from_the_existing_secret(self):
        spec = self.by(self.r("bank-a"), "Deployment")["rdbi-bank2"]["spec"]["template"]["spec"]
        src = next(s for s in spec["volumes"][0:] if s["name"] == "own")["projected"]["sources"]
        e = next(s for s in src if s.get("secret", {}).get("name") == "fsc-endorser-2-secret")["secret"]["items"]
        self.assertEqual({i["key"]: i["path"] for i in e}, {"msp-keystore-priv_sk": "endorser-2/ids/endorser-2/msp/keystore/priv_sk",
                                                              "msp-signcert.pem": "endorser-2/ids/endorser-2/msp/signcerts/cert.pem"})
        c = next(s for s in src if "configMap" in s)["configMap"]["items"]
        self.assertEqual({i["key"]: i["path"] for i in c}, {"msp-cacert.pem": "endorser-2/ids/endorser-2/msp/cacerts/ca.pem"})

    def test_every_private_path_the_core_needs_is_covered(self):
        self.r("bank-a")   # with the central keys it renders
        with self.assertRaises(SystemExit):
            self.r("bank-a", central_keys=[])                       # the anon / wallet paths are not covered: refuse
        self.r("bank-a", central_keys=[], allow_uncovered=True)     # explicit dry rendering


class Network(Base):
    def test_host_aliases_foreign_orgs_only_per_cluster(self):
        sp = self.by(self.r("bank-a"), "Deployment")["rdbi-bank2"]["spec"]["template"]["spec"]
        got = {a["ip"]: sorted(a["hostnames"]) for a in sp["hostAliases"] if not a["hostnames"][0].endswith(".arma.rd")}
        self.assertEqual(got, {"10.200.1.1": ["endorser-1", "issuer"], "10.200.1.3": ["bank3", "endorser-3"], "47.1.1.4": ["bank4", "endorser-4"]})
        sc = self.by(self.r("bank-c"), "Deployment")["rdbi-bank4"]["spec"]["template"]["spec"]
        got = {a["ip"]: sorted(a["hostnames"]) for a in sc["hostAliases"] if not a["hostnames"][0].endswith(".arma.rd")}
        self.assertEqual(got, {"8.1.1.1": ["endorser-1", "issuer"], "8.1.1.2": ["bank2", "endorser-2"], "8.1.1.3": ["bank3", "endorser-3"]})

    def test_orderer_names_resolve_to_the_arma_addresses_of_the_pods_cluster(self):
        for p, cl in (("bank-a", "cluster1"), ("bank-c", "cluster2")):
            sp = self.by(self.r(p), "Deployment")[f"rdbi-{POD[p]}"]["spec"]["template"]["spec"]
            m = {h: a["ip"] for a in sp["hostAliases"] for h in a["hostnames"] if h.endswith(".arma.rd")}
            self.assertEqual(sorted(m), sorted(f"{r}-{i}.arma.rd" for i in (1, 2, 3, 4) for r in ("assembler", "router")))
            self.assertEqual(m["router-1.arma.rd"], render.arma.IPS[cl][1])

    def test_network_policy_no_driver_grpc_only_from_own_gateway(self):
        np = self.by(self.r("bank-a"), "NetworkPolicy")["rdbi-traffic"]["spec"]
        self.assertEqual(np["policyTypes"], ["Ingress", "Egress"])
        text = yaml.safe_dump(np)
        self.assertNotIn("driver", text)
        ing = {tuple(sorted(p["port"] for p in r["ports"])): r.get("from") for r in np["ingress"]}
        self.assertIn((tcr.GRPC["bank2"], tcr.GRPC["endorser-2"]), ing)
        grpc = ing[(tcr.GRPC["bank2"], tcr.GRPC["endorser-2"])]
        self.assertEqual(grpc, [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": "fx-gw-2"}}}])
        p2p = [r for r in np["ingress"] if {p["port"] for p in r["ports"]} == {tcr.GRPC["bank2"] + 1, tcr.GRPC["endorser-2"] + 1}]
        self.assertEqual(len(p2p), 1)

    def test_no_p2p_service_by_default_and_flag_makes_a_cluster_policy_acl_service(self):
        self.assertNotIn("rdbi-p2p-bank2", self.by(self.r("bank-a"), "Service"))
        docs = self.r("bank-a", p2p_lb={"acl_id": "acl-d9ji5nwbqutwulof33ydb", "ranges": ["1.2.3.4/32"]})
        s = self.by(docs, "Service")["rdbi-p2p-bank2"]
        self.assertEqual(s["spec"]["type"], "LoadBalancer")
        self.assertEqual(s["spec"]["externalTrafficPolicy"], "Cluster")
        self.assertEqual(s["spec"]["loadBalancerSourceRanges"], ["1.2.3.4/32"])
        a = s["metadata"]["annotations"]
        self.assertEqual(a["service.beta.kubernetes.io/alibaba-cloud-loadbalancer-acl-id"], "acl-d9ji5nwbqutwulof33ydb")
        self.assertEqual(a["service.beta.kubernetes.io/alibaba-cloud-loadbalancer-acl-status"], "on")
        self.assertEqual(sorted(p["port"] for p in s["spec"]["ports"]), [tcr.GRPC["bank2"] + 1, tcr.GRPC["endorser-2"] + 1])
        self.assertEqual(s["spec"]["selector"], {"app.kubernetes.io/name": "rdbi-bank2"})
        for bad in ({"acl_id": "x", "ranges": ["1.2.3.4/32"]}, {"acl_id": "acl-abc", "ranges": []}, {"acl_id": "acl-abc", "ranges": ["1.2.3.0/24"]}):
            with self.assertRaises(SystemExit):
                self.r("bank-a", p2p_lb=bad)

    def test_p2p_addresses_are_required(self):
        with self.assertRaises(SystemExit):
            self.r("bank-a", p2p_ips=None)


class Placement(Base):
    def test_cluster1_defaults_and_bank_c(self):
        sp = self.by(self.r("bi"), "Deployment")["rdbi-bi"]["spec"]["template"]["spec"]
        self.assertEqual(sp["nodeSelector"], {"topology.kubernetes.io/zone": "ap-southeast-5b"})
        pvc = self.by(self.r("bi"), "PersistentVolumeClaim")["rdbi-bi-state"]
        self.assertEqual(pvc["spec"]["storageClassName"], "alicloud-essd-wffc")
        sc = self.by(self.r("bank-c"), "Deployment")["rdbi-bank4"]["spec"]["template"]["spec"]
        self.assertNotIn("nodeSelector", sc)
        self.assertEqual(self.by(self.r("bank-c"), "PersistentVolumeClaim")["rdbi-bank4-state"]["spec"]["storageClassName"], "fabricx-essd")
        with self.assertRaises(SystemExit):
            self.r("bank-c", storage_class=None)


if __name__ == "__main__":
    unittest.main()
