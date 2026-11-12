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
POD_NODE = {"bi": "issuer", "bank-a": "bank2", "bank-b": "bank3", "bank-c": "bank4"}   # the node the gateway fronts
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
        # P2P: the arma shape that passes both the eni health checks and the cross-cluster peers (proven on lb-1..4), never any source
        self.assertEqual(p2p[0]["from"], [{"namespaceSelector": {"matchLabels": {"part-of": "rd-fabricx"}}}, {"ipBlock": {"cidr": "47.237.84.150/32"}}, {"ipBlock": {"cidr": "100.64.0.0/10"}}])
        for party, want in (("bank-c", [{"ipBlock": {"cidr": "8.215.62.92/32"}}, {"ipBlock": {"cidr": "100.64.0.0/10"}}]),):
            c = self.by(self.r(party), "NetworkPolicy")["rdbi-traffic"]["spec"]
            pc = [r for r in c["ingress"] if "fx-gw" not in str(r.get("from"))]
            self.assertEqual(pc[0]["from"], want)   # cluster 2: no namespace selector, the other cluster's egress + the CLB health check

    # R17: the egress of rdbi-traffic is the narrow form (multiorg/test_netpol_form.py docstring); the old rules (podSelector {}, all ports; DNS without the CoreDNS selector;
    # one ipBlock rule over every address and port) are gone. No earlier test pinned the egress, so none was changed.
    def egress(self, party):
        return self.by(self.r(party), "NetworkPolicy")["rdbi-traffic"]["spec"]["egress"]

    def test_egress_exact_rules_for_bi_cluster1(self):
        g = tcr.GRPC
        sel = lambda nm: {"matchLabels": {"app.kubernetes.io/name": nm}}
        tcp = lambda *ps: [{"protocol": "TCP", "port": p} for p in ps]
        peer = lambda ns, nm, *ps: {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}}, "podSelector": sel(nm)}], "ports": tcp(*ps)}
        want = [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                 "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
                {"to": [{"podSelector": sel("committer-sidecar")}], "ports": tcp(5130)},
                {"to": [{"podSelector": sel("committer-query")}], "ports": tcp(5140)},
                {"to": [{"podSelector": sel("orderer-router-1")}], "ports": tcp(8013)},
                {"to": [{"podSelector": sel("orderer-assembler-1")}], "ports": tcp(8011)},
                peer("rd-fabricx-bank-a", "rdbi-bank2", g["bank2"] + 1, g["endorser-2"] + 1), peer("rd-fabricx-bank-a", "orderer-router-2", 8013), peer("rd-fabricx-bank-a", "orderer-assembler-2", 8011),
                peer("rd-fabricx-bank-b", "rdbi-bank3", g["bank3"] + 1, g["endorser-3"] + 1), peer("rd-fabricx-bank-b", "orderer-router-3", 8013), peer("rd-fabricx-bank-b", "orderer-assembler-3", 8011),
                {"to": [{"ipBlock": {"cidr": "47.1.1.4/32"}}], "ports": tcp(g["bank4"] + 1, g["endorser-4"] + 1)},   # bank-c, cluster 2: P2P address of the peer
                {"to": [{"ipBlock": {"cidr": "47.236.199.240/32"}}], "ports": tcp(8011, 8013)}]                      # bank-c, cluster 2: lb-4 public address (arma.IPS[cluster1][4])
        self.assertEqual(self.egress("bi"), want)

    def test_egress_exact_rules_for_bank_c_cluster2(self):
        g = tcr.GRPC
        sel = lambda nm: {"matchLabels": {"app.kubernetes.io/name": nm}}
        tcp = lambda *ps: [{"protocol": "TCP", "port": p} for p in ps]
        want_own = [{"to": [{"podSelector": sel("committer-sidecar")}], "ports": tcp(5130)}, {"to": [{"podSelector": sel("committer-query")}], "ports": tcp(5140)},
                    {"to": [{"podSelector": sel("orderer-router-4")}], "ports": tcp(8013)}, {"to": [{"podSelector": sel("orderer-assembler-4")}], "ports": tcp(8011)}]
        want_peers = [{"to": [{"ipBlock": {"cidr": f"{P2P['cluster2'][m]}/32"}}], "ports": tcp(g[a] + 1, g[b] + 1)} for m, a, b in ((1, "issuer", "endorser-1"), (2, "bank2", "endorser-2"), (3, "bank3", "endorser-3"))]
        arma = [{"to": [{"ipBlock": {"cidr": f"{render.arma.IPS['cluster2'][m]}/32"}}], "ports": tcp(8011, 8013)} for m in (1, 2, 3)]
        got = self.egress("bank-c")
        self.assertEqual(got[1:], want_own + [x for pair in zip(want_peers, arma) for x in pair])
        self.assertEqual(got[0]["to"][0]["podSelector"], {"matchLabels": {"k8s-app": "kube-dns"}})

    def test_egress_has_no_empty_pod_selector_and_every_rule_has_ports(self):
        for p in PARTIES:
            for rule in self.egress(p):
                self.assertTrue(rule["ports"], (p, rule))
                for to in rule["to"]:
                    self.assertNotEqual(to.get("podSelector"), {}, (p, rule))
                    self.assertNotEqual(to.get("namespaceSelector"), {}, (p, rule))

    def test_no_ipblock_for_a_same_cluster_address(self):
        for p in PARTIES:
            cl = "cluster2" if p == "bank-c" else "cluster1"
            same = {m for q, m in PARTIES.items() if ("cluster2" if q == "bank-c" else "cluster1") == cl}
            addrs = {f"{a}/32" for m in same for a in (P2P[cl][m], render.arma.IPS[cl][m])}
            blocks = [to["ipBlock"]["cidr"] for r in self.egress(p) for to in r["to"] if "ipBlock" in to]
            self.assertFalse(addrs & set(blocks), (p, addrs & set(blocks)))

    def test_cross_cluster_ipblocks_are_host_32_on_the_peer_ports_only(self):
        g = tcr.GRPC
        peer_ports = {"bi": {g["issuer"] + 1, g["endorser-1"] + 1}, "bank-a": {g["bank2"] + 1, g["endorser-2"] + 1}, "bank-b": {g["bank3"] + 1, g["endorser-3"] + 1}, "bank-c": {g["bank4"] + 1, g["endorser-4"] + 1}}
        for p in PARTIES:
            cl = "cluster2" if p == "bank-c" else "cluster1"
            other = [q for q in PARTIES if ("cluster2" if q == "bank-c" else "cluster1") != cl]
            allowed = {"p2p": {P2P[cl][PARTIES[q]]: peer_ports[q] for q in other}, "arma": {render.arma.IPS[cl][PARTIES[q]]: {8011, 8013} for q in other}}
            want = {**allowed["p2p"], **allowed["arma"]}
            got = {}
            for r in self.egress(p):
                for to in r["to"]:
                    if "ipBlock" in to:
                        cidr = to["ipBlock"]["cidr"]
                        self.assertTrue(cidr.endswith("/32") and set(to) == {"ipBlock"} and len(r["to"]) == 1, (p, r))
                        got[cidr[:-3]] = {x["port"] for x in r["ports"]}
            self.assertEqual(got, want, p)

    def test_bank_c_egress_names_no_cluster1_namespace(self):
        text = yaml.safe_dump(self.egress("bank-c"))
        for q in ("bi", "bank-a", "bank-b"):
            self.assertNotIn(f"rd-fabricx-{q}", text)
        sels = [to["namespaceSelector"]["matchLabels"] for r in self.egress("bank-c") for to in r["to"] if "namespaceSelector" in to]
        self.assertEqual(sels, [{"kubernetes.io/metadata.name": "kube-system"}])

    def test_cluster1_party_selects_both_other_cluster1_namespaces_by_exact_name(self):
        for p in ("bi", "bank-a", "bank-b"):
            names = {to["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] for r in self.egress(p) for to in r["to"] if "namespaceSelector" in to}
            self.assertEqual(names, {"kube-system", *(f"rd-fabricx-{q}" for q in ("bi", "bank-a", "bank-b") if q != p)})

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
        self.assertEqual(a["service.beta.kubernetes.io/backend-type"], "eni")   # the S10b shape (a choice, not a proven dependency of the ACL)
        self.assertEqual(a["service.beta.kubernetes.io/alibaba-cloud-loadbalancer-acl-type"], "white")
        self.assertEqual(sorted(p["port"] for p in s["spec"]["ports"]), [tcr.GRPC["bank2"] + 1, tcr.GRPC["endorser-2"] + 1])
        self.assertEqual(s["spec"]["selector"], {"app.kubernetes.io/name": "rdbi-bank2"})
        for bad in ({"acl_id": "x", "ranges": ["1.2.3.4/32"]}, {"acl_id": "acl-abc", "ranges": []}, {"acl_id": "acl-abc", "ranges": ["1.2.3.0/24"]}):
            with self.assertRaises(SystemExit):
                self.r("bank-a", p2p_lb=bad)

    def gw_exchange(self, party, text="-----BEGIN CERTIFICATE-----\nMIIgw\n-----END CERTIFICATE-----\n"):
        n = PARTIES[party]
        d = f"{self.tmp.name}/gwx"
        os.makedirs(f"{d}/org{n}/gw", exist_ok=True)
        with open(f"{d}/org{n}/gw/{POD_NODE[party]}-gw.pem", "w") as f:
            f.write(text)
        return d

    def test_gw_exchange_swaps_the_party_nodes_client_cert_only(self):
        for party in PARTIES:
            node = POD_NODE[party]
            docs = self.r(party, gw_exchange=self.gw_exchange(party))
            cores = self.by(docs, "ConfigMap")
            gw_core = yaml.safe_load(cores[f"rdbi-core-{node}"]["data"]["core.yaml"])
            self.assertEqual(gw_core["fsc"]["client"]["certs"], [f"{render.T}/public/gw/{node}-gw.pem"])
            ep = f"endorser-{PARTIES[party]}"
            ep_core = yaml.safe_load(cores[f"rdbi-core-{ep}"]["data"]["core.yaml"])
            self.assertEqual(ep_core["fsc"]["client"]["certs"], [f"{render.T}/own/{ep}/fsc/admin.pem"])   # the endorser has no gateway: unchanged
            pub = cores["rdbi-public"]["data"] if "rdbi-public" in cores else self.by(docs, "ConfigMap")["rdbi-public"]["data"]
            self.assertEqual(pub[f"gw__{node}-gw.pem"], "-----BEGIN CERTIFICATE-----\nMIIgw\n-----END CERTIFICATE-----\n")
            dep = self.by(docs, "Deployment")[f"rdbi-{POD[party]}"]
            items = [v for v in dep["spec"]["template"]["spec"]["volumes"] if v["name"] == "public"][0]["configMap"]["items"]
            self.assertIn({"key": f"gw__{node}-gw.pem", "path": f"gw/{node}-gw.pem"}, items)

    def test_without_gw_exchange_nothing_about_the_gateway_is_rendered(self):
        docs = self.r("bank-a")
        pub = self.by(docs, "ConfigMap")["rdbi-public"]["data"]
        self.assertFalse([k for k in pub if k.startswith("gw__")])
        c = yaml.safe_load(self.by(docs, "ConfigMap")["rdbi-core-bank2"]["data"]["core.yaml"])
        self.assertEqual(c["fsc"]["client"]["certs"], [f"{render.T}/own/bank2/fsc/admin.pem"])

    def test_gw_cert_must_exist_and_be_public(self):
        with self.assertRaises(SystemExit):
            self.r("bank-a", gw_exchange=f"{self.tmp.name}/nowhere")
        with self.assertRaises(SystemExit):
            self.r("bank-a", gw_exchange=self.gw_exchange("bank-a", "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n"))

    def test_p2p_addresses_are_required(self):
        with self.assertRaises(SystemExit):
            self.r("bank-a", p2p_ips=None)

def r22_term(role, party):
    """R22 (worker = failure domain): a role pod may not share a worker with the same role of ANOTHER party, across the rd-fabricx-* namespaces."""
    return {"topologyKey": "kubernetes.io/hostname", "namespaceSelector": {"matchLabels": {"part-of": "rd-fabricx"}},
            "labelSelector": {"matchExpressions": [{"key": "rd/role", "operator": "In", "values": [f"fabricx-{role}"]},
                                                   {"key": "party", "operator": "NotIn", "values": [party]}]}}

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


    def test_r22_fsc_pod_never_shares_a_worker_with_another_party_fsc_pod(self):
        for party, pod in POD.items():
            docs = self.r(party)
            d = self.by(docs, "Deployment")[f"rdbi-{pod}"]["spec"]["template"]
            self.assertEqual(d["metadata"]["labels"]["rd/role"], "fabricx-fsc")
            self.assertEqual(d["spec"]["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"], [r22_term("fsc", party)])
            self.assertNotIn("nodeAffinity", d["spec"]["affinity"])
            others = [x for x in docs if x["kind"] in ("Deployment", "StatefulSet", "Job") and x["metadata"]["name"] != f"rdbi-{pod}"]
            for x in others:
                self.assertNotIn("rd/role", x["spec"]["template"]["metadata"]["labels"])

if __name__ == "__main__":
    unittest.main()
