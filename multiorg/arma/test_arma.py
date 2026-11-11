"""Offline tests for multiorg/arma/render.py (fabricx S11/S18: Arma party pods). Fake exchange trees, fake genesis file, no cluster.

  python3 -m unittest discover -s multiorg/arma        (needs PyYAML)
"""
import base64, difflib, hashlib, importlib.util, os, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "fca"))   # enroll (PORT_PLAN); fca/render.py has the same name as ours, so HERE goes first
sys.path.insert(0, HERE)
import enroll, render
import test_check_exchange as tce

PARTIES = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
ROLES = ("router", "batcher1", "consenter", "assembler")
OBJ = {"router": "router", "batcher1": "batcher", "consenter": "consenter", "assembler": "assembler"}
# the arma CLI commands (orderer@dd296e3 node/server/arma.go:30-58): the consenter's command is `consensus`, not its role name
CMD = {"router": "router", "batcher1": "batcher", "consenter": "consensus", "assembler": "assembler"}
DIGEST = "docker.io/hyperledger/fabric-x-orderer@sha256:052ae8e16571d3d4de2e1a0c4e9ed0d979d782d3539d3c8fb1f7f66fe560e265"
GENESIS = b"FAKE GENESIS BLOCK\n" * 50
GEN_SHA = hashlib.sha256(GENESIS).hexdigest()
TEMPLATES = os.path.join(HERE, "templates")
# decision 1 (lead): cluster 1 pods use the ClusterIPs of lb-1/2/3 and the public LB address of lb-4; cluster 2 pods the reverse
C1 = {1: "10.200.55.11", 2: "10.200.27.215", 3: "10.200.63.143", 4: "47.236.199.240"}
C2 = {1: "8.215.24.249", 2: "8.215.30.255", 3: "147.139.133.68", 4: "10.210.48.103"}


def load_lb():
    spec = importlib.util.spec_from_file_location("lb_render", os.path.join(os.path.dirname(HERE), "lb", "render.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def cert(label):
    return f"-----BEGIN CERTIFICATE-----\n{label}\n-----END CERTIFICATE-----\n"


def make_exchange(root):
    for n in (1, 2, 3, 4):
        d = os.path.join(root, f"org{n}")
        tce.good_tree(d, n)
        tce.write(d, "msp/cacerts/ca.pem", cert(f"CA{n}"))
        tce.write(d, "msp/tlscacerts/tlsca.pem", cert(f"TLSCA{n}"))
        tce.write(d, f"msp/admincerts/admin-{n}-cert.pem", cert(f"ADMIN{n}"))
        tce.write(d, "endpoints.yaml", yaml.safe_dump({r: {"Host": f"{r}-{n}.arma.rd", "Port": enroll.PORT_PLAN[r]} for r in ROLES}))
        tce.manifest(d)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ex = os.path.join(self.tmp.name, "ex")
        make_exchange(self.ex)
        self.gen = os.path.join(self.tmp.name, "genesis.block")
        with open(self.gen, "wb") as f:
            f.write(GENESIS)

    def kw(self, party, **over):
        kw = dict(exchange=self.ex, genesis=self.gen, genesis_sha256=GEN_SHA)
        if party == "bank-c":
            kw.update(storage_class="fabricx-essd")   # cluster 2: no zone pin (WaitForFirstConsumer class, lead 2026-11-11)
        kw.update(over)
        return kw

    def docs(self, party, **over):
        return list(yaml.safe_load_all(render.render(party, **self.kw(party, **over))))

    def sts(self, party, **over):
        return {x["metadata"]["name"]: x for x in self.docs(party, **over) if x["kind"] == "StatefulSet"}

    def cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(HERE, "render.py"), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)

    def cli_args(self, party, **over):
        a = [party, "--exchange", self.ex, "--genesis", self.gen, "--genesis-sha256", GEN_SHA]
        if party == "bank-c":
            a += ["--storage-class", "fabricx-essd"]
        for k, v in over.items():
            a += [f"--{k.replace('_', '-')}", v]
        return a

    def refused(self, party="bi", **over):
        with self.assertRaises(SystemExit):
            render.render(party, **self.kw(party, **over))


class Objects(Base):
    def test_objects_names_and_order(self):
        for p, n in PARTIES.items():
            with self.subTest(party=p):
                d = self.docs(p)
                got = [(x["kind"], x["metadata"]["name"]) for x in d]
                want = [("ConfigMap", "genesis-block"), ("ConfigMap", f"arma-public-{n}")]
                want += [("ConfigMap", f"arma-config-{OBJ[r]}-{n}") for r in ROLES]
                want += [("NetworkPolicy", "allow-arma-peers")]
                want += [("StatefulSet", f"orderer-{OBJ[r]}-{n}") for r in ROLES]
                self.assertEqual(got, want)
                self.assertEqual({x["metadata"]["namespace"] for x in d}, {f"rd-fabricx-{p}"})
                self.assertNotIn("Secret", {x["kind"] for x in d})   # the key Secrets come from enroll.py
                self.assertNotIn("Service", {x["kind"] for x in d})  # lb-<N> comes from multiorg/lb/render.py

    def test_cli_prints_the_same_documents(self):
        r = self.cli(*self.cli_args("bank-a"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stderr, "")
        self.assertEqual(list(yaml.safe_load_all(r.stdout)), self.docs("bank-a"))

    def test_unknown_party_refused(self):
        with self.assertRaises(SystemExit):
            render.render("bank-z", **self.kw("bi"))
        r = self.cli(*self.cli_args("bank-z"))
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")

    def test_statefulset_shape(self):
        for p, n in PARTIES.items():
            for r in ROLES:
                with self.subTest(party=p, role=r):
                    s = self.sts(p)[f"orderer-{OBJ[r]}-{n}"]
                    self.assertEqual(s["spec"]["replicas"], 1)
                    self.assertEqual(s["spec"]["serviceName"], f"lb-{n}")
                    c = s["spec"]["template"]["spec"]["containers"][0]
                    self.assertEqual(c["image"], DIGEST)
                    self.assertNotIn("command", c)                                  # the image entrypoint
                    self.assertEqual(c["args"], [CMD[r], "--config=/config/node_config.yaml"])
                    v = s["spec"]["volumeClaimTemplates"]
                    self.assertEqual(len(v), 1)
                    self.assertEqual(v[0]["metadata"]["name"], "data")
                    self.assertEqual(v[0]["spec"]["resources"]["requests"]["storage"], "2Gi")
                    self.assertEqual(v[0]["spec"]["accessModes"], ["ReadWriteOnce"])
                    self.assertIn({"name": "data", "mountPath": "/data"}, c["volumeMounts"])
                    self.assertEqual(s["spec"]["selector"]["matchLabels"], {"app.kubernetes.io/name": f"orderer-{OBJ[r]}-{n}"})

    def test_replicas_option(self):
        self.assertEqual({s["spec"]["replicas"] for s in self.sts("bi", replicas=2).values()}, {2})
        for bad in (0, -1):
            self.refused(replicas=bad)
        r = self.cli(*self.cli_args("bi", replicas="0"))
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")


class LbContract(Base):
    """the Service lb-<N> (multiorg/lb/render.py) must select exactly these pods through these port names"""

    def test_service_targets_exist_on_exactly_one_role_pod(self):
        lb = load_lb()
        for p, n in PARTIES.items():
            with self.subTest(party=p):
                svc = list(yaml.safe_load_all(lb.render(p, "acl-abc123", ["203.0.113.7/32"])))[0]
                pods = [s["spec"]["template"] for s in self.sts(p).values()]
                self.assertEqual(len(pods), 4)
                for port in svc["spec"]["ports"]:
                    owners = [t for t in pods for c in t["spec"]["containers"] for cp in c["ports"] if cp["name"] == port["targetPort"]]
                    self.assertEqual(len(owners), 1, port)
                    cp = [cp for c in owners[0]["spec"]["containers"] for cp in c["ports"] if cp["name"] == port["targetPort"]][0]
                    self.assertEqual(cp["containerPort"], port["port"])
                for t in pods:   # selector is a subset of the labels of every role pod
                    self.assertLessEqual(svc["spec"]["selector"].items(), t["metadata"]["labels"].items())
                self.assertEqual(svc["spec"]["selector"], {"rd-fabricx/arma-party": str(n)})

    def test_named_ports_and_labels(self):
        for p, n in PARTIES.items():
            for r in ROLES:
                with self.subTest(party=p, role=r):
                    t = self.sts(p)[f"orderer-{OBJ[r]}-{n}"]["spec"]["template"]
                    c = t["spec"]["containers"][0]
                    ports = {cp["name"]: cp["containerPort"] for cp in c["ports"]}
                    self.assertEqual(ports[r], enroll.PORT_PLAN[r])          # == PORT_PLAN
                    self.assertEqual(len(ports), 2)                          # the role port and ops
                    ops = ports["ops"]
                    self.assertNotIn(ops, enroll.PORT_PLAN.values())
                    L = t["metadata"]["labels"]
                    self.assertEqual(L["rd-fabricx/arma-party"], str(n))
                    self.assertEqual(L["app.kubernetes.io/part-of"], "rd-fabricx")
                    self.assertEqual(L["party"], p)
                    self.assertEqual(L["app.kubernetes.io/name"], f"orderer-{OBJ[r]}-{n}")

    def test_ops_ports_differ_per_role(self):
        ops = {r: [cp["containerPort"] for cp in self.sts("bi")[f"orderer-{OBJ[r]}-1"]["spec"]["template"]["spec"]["containers"][0]["ports"] if cp["name"] == "ops"][0] for r in ROLES}
        self.assertEqual(len(set(ops.values())), 4)
        self.assertEqual(sorted(ops.values()), [7060, 7061, 7062, 7063])


class HostAliases(Base):
    def aliases(self, party, **over):
        return {name: s["spec"]["template"]["spec"]["hostAliases"] for name, s in self.sts(party, **over).items()}

    def want(self, table):
        return [{"ip": table[n], "hostnames": [f"{r}-{n}.arma.rd" for r in ROLES]} for n in (1, 2, 3, 4)]

    def test_cluster1_and_cluster2_tables(self):
        for p in ("bi", "bank-a", "bank-b"):
            for name, a in self.aliases(p).items():
                self.assertEqual(a, self.want(C1), (p, name))
        for name, a in self.aliases("bank-c").items():
            self.assertEqual(a, self.want(C2), name)

    def test_every_name_once_and_complete(self):
        for p in PARTIES:
            for a in self.aliases(p).values():
                names = [h for e in a for h in e["hostnames"]]
                self.assertEqual(sorted(names), sorted(f"{r}-{n}.arma.rd" for r in ROLES for n in (1, 2, 3, 4)))
                self.assertEqual(len(names), len(set(names)))
                ips = [e["ip"] for e in a]
                self.assertEqual(len(ips), len(set(ips)))                    # one entry per IP
                for e in a:
                    self.assertEqual(len(e["hostnames"]), 4)

    def test_ips_file_overrides(self):
        f = os.path.join(self.tmp.name, "ips.yaml")
        new1 = {1: "10.1.1.1", 2: "10.1.1.2", 3: "10.1.1.3", 4: "203.0.113.4"}
        new2 = {1: "198.51.100.1", 2: "198.51.100.2", 3: "198.51.100.3", 4: "10.2.2.4"}
        with open(f, "w") as fh:
            yaml.safe_dump({"cluster1": new1, "cluster2": new2}, fh)
        self.assertEqual(next(iter(self.aliases("bank-a", ips=f).values())), self.want(new1))
        self.assertEqual(next(iter(self.aliases("bank-c", ips=f).values())), self.want(new2))
        r = self.cli(*self.cli_args("bank-b", ips=f))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("10.1.1.3", r.stdout)

    def test_bad_ips_file_refused(self):
        good = {1: "10.1.1.1", 2: "10.1.1.2", 3: "10.1.1.3", 4: "10.1.1.4"}
        bad = [
            {"cluster1": {**good, 2: "10.1.1"}, "cluster2": good},                  # not a full IPv4
            {"cluster1": {**good, 2: "300.1.1.1"}, "cluster2": good},
            {"cluster1": {**good, 2: "router.example.org"}, "cluster2": good},     # a name is not an address
            {"cluster1": {**good, 2: "::1"}, "cluster2": good},                     # IPv6
            {"cluster1": {**good, 2: "10.1.1.1"}, "cluster2": good},                # two parties on one IP
            {"cluster1": {k: v for k, v in good.items() if k != 4}, "cluster2": good},   # party 4 missing
            {"cluster1": good},                                                    # cluster2 missing
            {"cluster1": {**good, 5: "10.1.1.5"}, "cluster2": good},               # unknown party
            ["10.1.1.1"],
        ]
        for i, doc in enumerate(bad):
            with self.subTest(i=i):
                f = os.path.join(self.tmp.name, f"bad{i}.yaml")
                with open(f, "w") as fh:
                    yaml.safe_dump(doc, fh)
                self.refused("bank-a", ips=f)
                r = self.cli(*self.cli_args("bank-a", ips=f))
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(r.stdout, "")
        self.refused("bank-a", ips=os.path.join(self.tmp.name, "missing.yaml"))

    def test_built_in_table_is_valid_ipv4(self):
        import ipaddress
        for cl in render.IPS.values():
            self.assertEqual(sorted(cl), [1, 2, 3, 4])
            for ip in cl.values():
                ipaddress.IPv4Address(ip)


class NodeConfig(Base):
    def cfg(self, party, role, **over):
        n = PARTIES[party]
        cm = next(x for x in self.docs(party, **over) if x["metadata"]["name"] == f"arma-config-{OBJ[role]}-{n}")
        self.assertEqual(list(cm["data"]), ["node-config.yaml"])
        return cm["data"]["node-config.yaml"]

    def template(self, role):
        with open(os.path.join(TEMPLATES, f"{OBJ[role]}-1.yaml")) as f:
            return f.read()

    def test_substitutions(self):
        for p, n in PARTIES.items():
            for i, r in enumerate(ROLES):
                with self.subTest(party=p, role=r):
                    c = yaml.safe_load(self.cfg(p, r))
                    self.assertEqual(c["PartyID"], n)
                    self.assertEqual(c["General"]["ListenPort"], enroll.PORT_PLAN[r])
                    self.assertEqual(c["Operations"]["ListenPort"], 7060 + i)
                    self.assertEqual(c["General"]["LocalMSPID"], f"org{n}")
                    if r == "batcher1":
                        self.assertEqual(c["Batcher"]["ShardID"], 1)
                    self.assertEqual(c["Operations"]["TLS"]["ClientRootCAs"], ["/config/tls/ca.crt"])
                    self.assertNotIn("prometheus/ca.crt", self.cfg(p, r))
                    # paths the pod contract mounts
                    self.assertEqual(c["General"]["Bootstrap"]["File"], "/config/genesis.block")
                    self.assertEqual(c["General"]["TLS"]["PrivateKey"], "/config/tls/server.key")
                    self.assertEqual(c["General"]["LocalMSPDir"], "/config/msp")
                    self.assertEqual(c["FileStore"]["Location"], "/data/v2/store")

    def test_msp_id_format_option(self):
        self.assertEqual(yaml.safe_load(self.cfg("bank-b", "router", msp_id_format="OrdererOrg{n}"))["General"]["LocalMSPID"], "OrdererOrg3")
        for bad in ("OrdererOrg", "Org{x}", "a b{n}", ""):
            self.refused(msp_id_format=bad)

    def test_rest_of_template_unchanged(self):
        allowed = ("PartyID:", "  ListenPort:", "  LocalMSPID:", "  ShardID:", "      - /config/mtls/prometheus/ca.crt")
        for p in PARTIES:
            for r in ROLES:
                with self.subTest(party=p, role=r):
                    old, new = self.template(r).splitlines(), self.cfg(p, r).splitlines()
                    changed = [l[1:] for l in difflib.unified_diff(old, new, lineterm="", n=0) if l[:1] in "+-" and l[:3] not in ("+++", "---")]
                    self.assertTrue(changed)
                    for l in changed:
                        self.assertTrue(l.startswith(allowed), l)
                    removed = [l[1:] for l in difflib.unified_diff(old, new, lineterm="", n=0) if l.startswith("-") and not l.startswith("---")]
                    self.assertIn("      - /config/mtls/prometheus/ca.crt", removed)
                    # comments survive byte for byte
                    self.assertEqual([l for l in old if l.lstrip().startswith("#")], [l for l in new if l.lstrip().startswith("#")])

    def test_template_drift_is_refused(self):
        # a template that lost a line the render must substitute: fail loudly, never print a half-substituted config
        with self.assertRaises(SystemExit):
            render.node_config("PartyID: 1\nGeneral:\n  ListenPort: 1\n", "router", 1, "org1", 7060)


class PublicAndGenesis(Base):
    def cm(self, party, name):
        return next(x for x in self.docs(party) if x["kind"] == "ConfigMap" and x["metadata"]["name"] == name)

    def test_public_configmap(self):
        for p, n in PARTIES.items():
            d = self.cm(p, f"arma-public-{n}")["data"]
            self.assertEqual(sorted(d), ["msp-admincert.pem", "msp-cacert.pem", "tls-ca-bundle.crt"])
            self.assertEqual(d["msp-cacert.pem"], cert(f"CA{n}"))                     # this org only
            self.assertEqual(d["msp-admincert.pem"], cert(f"ADMIN{n}"))               # this org's admin cert only (public)
            self.assertEqual(d["tls-ca-bundle.crt"], "".join(cert(f"TLSCA{m}") for m in (1, 2, 3, 4)))   # all four orgs

    def test_genesis_configmap(self):
        for p in PARTIES:
            cm = self.cm(p, "genesis-block")
            self.assertEqual(list(cm["binaryData"]), ["genesis.block"])
            self.assertEqual(base64.b64decode(cm["binaryData"]["genesis.block"]), GENESIS)
            self.assertNotIn("data", cm)

    def test_encoded_genesis_configmap_stays_under_the_object_limit(self):
        big = os.path.join(self.tmp.name, "maxblock")
        with open(big, "wb") as f:
            f.write(b"x" * (700 * 1024))
        sha = hashlib.sha256(b"x" * (700 * 1024)).hexdigest()
        out = render.render("bi", **self.kw("bi", genesis=big, genesis_sha256=sha))
        cm = next(d for d in yaml.safe_load_all(out) if d["metadata"]["name"] == "genesis-block")
        self.assertLess(len(yaml.safe_dump(cm)), 1024 * 1024)

    def test_genesis_checks(self):
        self.refused(genesis_sha256="0" * 64)                       # mismatch
        self.refused(genesis_sha256=GEN_SHA.upper())                # not lowercase hex
        self.refused(genesis_sha256=GEN_SHA[:-1])                   # short
        self.refused(genesis_sha256="g" * 64)
        self.refused(genesis=os.path.join(self.tmp.name, "nope"))
        big = os.path.join(self.tmp.name, "big")
        # binaryData is base64 (x 4/3) and the whole ConfigMap must stay under the 1 MiB object limit: 700 KiB raw -> ~934 KiB encoded
        for size, ok in ((700 * 1024, True), (700 * 1024 + 1, False)):
            with open(big, "wb") as f:
                f.write(b"x" * size)
            sha = hashlib.sha256(b"x" * size).hexdigest()
            if ok:
                render.render("bi", **self.kw("bi", genesis=big, genesis_sha256=sha))
            else:
                self.refused(genesis=big, genesis_sha256=sha)
        r = self.cli(*self.cli_args("bi", genesis_sha256="0" * 64))
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")

    def test_unclean_exchange_refused(self):
        tce.write(os.path.join(self.ex, "org3"), "orderers/party3/router/tls/server.key", "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n")
        self.refused()
        r = self.cli(*self.cli_args("bi"))
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")

    def test_missing_org_and_manifest_refused(self):
        os.rename(os.path.join(self.ex, "org4"), os.path.join(self.tmp.name, "gone"))
        self.refused()

    def test_endpoints_must_match_the_name_plan(self):
        d = os.path.join(self.ex, "org2")
        tce.write(d, "endpoints.yaml", yaml.safe_dump({r: {"Host": f"{r}-2.example.org", "Port": enroll.PORT_PLAN[r]} for r in ROLES}))
        tce.manifest(d)
        self.refused()
        tce.write(d, "endpoints.yaml", yaml.safe_dump({r: {"Host": f"{r}-2.arma.rd", "Port": 7050} for r in ROLES}))
        tce.manifest(d)
        self.refused()


class Image(Base):
    def test_digest_required(self):
        for bad in ("docker.io/hyperledger/fabric-x-orderer:1.0.4", "docker.io/hyperledger/fabric-x-orderer@sha256:abc",
                    "docker.io/hyperledger/fabric-x-orderer@sha256:" + "A" * 64, "@sha256:" + "a" * 64, "x y@sha256:" + "a" * 64, ""):
            with self.subTest(image=bad):
                self.refused(image=bad)
        other = "ghcr.io/x/y@sha256:" + "a" * 64
        self.assertEqual({s["spec"]["template"]["spec"]["containers"][0]["image"] for s in self.sts("bi", image=other).values()}, {other})
        r = self.cli(*self.cli_args("bi", image="docker.io/hyperledger/fabric-x-orderer:1.0.4"))
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")


class Placement(Base):
    def spec(self, party, **over):
        return next(iter(self.sts(party, **over).values()))["spec"]

    def test_cluster1_defaults(self):
        for p in ("bi", "bank-a", "bank-b"):
            s = self.spec(p)
            self.assertEqual(s["template"]["spec"]["nodeSelector"], {"topology.kubernetes.io/zone": "ap-southeast-5b"})
            self.assertEqual(s["volumeClaimTemplates"][0]["spec"]["storageClassName"], "alicloud-essd-wffc")
            na = s["template"]["spec"]["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"]
            self.assertEqual(na, [{"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "NotIn", "values": ["member-16033-node", "member-16034-node"]}]}])
        s = self.spec("bi", zone="ap-southeast-5a", storage_class="other-sc")
        self.assertEqual(s["template"]["spec"]["nodeSelector"], {"topology.kubernetes.io/zone": "ap-southeast-5a"})
        self.assertEqual(s["volumeClaimTemplates"][0]["spec"]["storageClassName"], "other-sc")

    def test_avoid_nodes_match_k8s_py(self):
        src = open(os.path.join(os.path.dirname(os.path.dirname(HERE)), "panurus-itest", "scripts", "k8s.py")).read()
        self.assertIn('AVOID_NODES = ["member-16033-node", "member-16034-node"]', src)

    def test_bank_c_needs_storage_class_and_has_no_zone_pin_by_default(self):
        s = self.spec("bank-c")
        self.assertNotIn("nodeSelector", s["template"]["spec"])                       # zone 1a had no pod/volume room; the class binds on first consumer
        pinned = self.spec("bank-c", zone="ap-southeast-1b")                           # an explicit zone still pins
        self.assertEqual(pinned["template"]["spec"]["nodeSelector"], {"topology.kubernetes.io/zone": "ap-southeast-1b"})
        self.assertEqual(s["volumeClaimTemplates"][0]["spec"]["storageClassName"], "fabricx-essd")
        self.assertNotIn("nodeAffinity", s["template"]["spec"]["affinity"])           # cluster 2: other node names
        with self.assertRaises(SystemExit):
            render.render("bank-c", exchange=self.ex, genesis=self.gen, genesis_sha256=GEN_SHA, zone="ap-southeast-1a")   # class is never guessed
        r = self.cli("bank-c", "--exchange", self.ex, "--genesis", self.gen, "--genesis-sha256", GEN_SHA, "--zone", "ap-southeast-1a")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")

    def test_zone_and_storage_class_names_validated(self):
        for bad in ("", "a b", "x:y"):
            self.refused("bank-a", zone=bad)
        for bad in ("", "a b", "x/y"):
            self.refused("bank-a", storage_class=bad)

    def test_soft_anti_affinity_within_the_party(self):
        for p, n in PARTIES.items():
            aa = self.spec(p)["template"]["spec"]["affinity"]["podAntiAffinity"]
            self.assertNotIn("requiredDuringSchedulingIgnoredDuringExecution", aa)
            (t,) = aa["preferredDuringSchedulingIgnoredDuringExecution"]
            self.assertEqual(t["weight"], 100)
            self.assertEqual(t["podAffinityTerm"]["topologyKey"], "kubernetes.io/hostname")
            self.assertEqual(t["podAffinityTerm"]["labelSelector"], {"matchLabels": {"rd-fabricx/arma-party": str(n)}})
            self.assertNotIn("namespaceSelector", t["podAffinityTerm"])


class Hardening(Base):
    def test_pss_restricted_and_resources(self):
        for p in PARTIES:
            for name, s in self.sts(p).items():
                with self.subTest(sts=name):
                    ps = s["spec"]["template"]["spec"]
                    sc = ps["securityContext"]
                    self.assertIs(sc["runAsNonRoot"], True)
                    self.assertEqual(sc["runAsUser"], 10001)
                    self.assertEqual(sc["fsGroup"], 10001)
                    self.assertEqual(sc["seccompProfile"], {"type": "RuntimeDefault"})
                    self.assertNotIn("initContainers", ps)
                    for c in ps["containers"]:
                        self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False)
                        self.assertEqual(c["securityContext"]["capabilities"], {"drop": ["ALL"]})
                        for side in ("requests", "limits"):
                            for res in ("cpu", "memory", "ephemeral-storage"):
                                self.assertIn(res, c["resources"][side], (side, res))

    def test_orderer_requests_resized_limits_unchanged(self):
        # GO resize (orchestrator, 2026-11-12): requests 50m/128Mi -> 30m/64Mi for all four roles; limits and ephemeral-storage unchanged
        for p in PARTIES:
            for name, s in self.sts(p).items():
                c = s["spec"]["template"]["spec"]["containers"][0]
                self.assertEqual(c["resources"]["requests"], {"cpu": "30m", "memory": "64Mi", "ephemeral-storage": "64Mi"}, name)
                self.assertEqual(c["resources"]["limits"], {"cpu": "1", "memory": "512Mi", "ephemeral-storage": "512Mi"}, name)

    def test_secrets_mounted_with_the_four_keys(self):
        for p, n in PARTIES.items():
            for r in ROLES:
                with self.subTest(party=p, role=r):
                    ps = self.sts(p)[f"orderer-{OBJ[r]}-{n}"]["spec"]["template"]["spec"]
                    c = ps["containers"][0]
                    vol = {v["name"]: v for v in ps["volumes"]}
                    sec = [v for v in ps["volumes"] if "secret" in v]
                    self.assertEqual(len(sec), 1)
                    self.assertEqual(sec[0]["secret"]["secretName"], f"orderer-{OBJ[r]}-{n}-secret")
                    self.assertEqual(sec[0]["secret"]["defaultMode"], 0o400)
                    self.assertEqual(sorted(i["key"] for i in sec[0]["secret"]["items"]),
                                     ["msp-keystore-priv_sk", "msp-signcert.pem", "tls-server.crt", "tls-server.key"])
                    mounts = {m["mountPath"]: m for m in c["volumeMounts"]}
                    path_of = {i["key"]: i["path"] for i in sec[0]["secret"]["items"]}
                    want = {"msp-keystore-priv_sk": "/config/msp/keystore/priv_sk", "msp-signcert.pem": f"/config/msp/signcerts/{r}-cert.pem",
                            "tls-server.key": "/config/tls/server.key", "tls-server.crt": "/config/tls/server.crt"}
                    for key, mp in want.items():
                        self.assertEqual(mounts[mp]["name"], sec[0]["name"])
                        self.assertEqual(mounts[mp]["subPath"], path_of[key])
                        self.assertIs(mounts[mp]["readOnly"], True)
                    # config, genesis and public material
                    self.assertEqual(vol[mounts["/config/genesis.block"]["name"]]["configMap"]["name"], "genesis-block")
                    self.assertEqual(vol[mounts["/config/node_config.yaml"]["name"]]["configMap"]["name"], f"arma-config-{OBJ[r]}-{n}")
                    self.assertEqual(vol[mounts["/config/tls/ca.crt"]["name"]]["configMap"]["name"], f"arma-public-{n}")
                    self.assertEqual(vol[mounts["/config/msp/cacerts/ca.pem"]["name"]]["configMap"]["name"], f"arma-public-{n}")
                    # the node's local MSP needs an admin (fabric-x-common msp/mspimplsetup.go:211: panic without admincerts or NodeOU admin class)
                    self.assertEqual(vol[mounts["/config/msp/admincerts/admin.pem"]["name"]]["configMap"]["name"], f"arma-public-{n}")
                    self.assertEqual(mounts["/config/msp/admincerts/admin.pem"]["subPath"], "msp-admincert.pem")
                    pub = vol[mounts["/config/tls/ca.crt"]["name"]]["configMap"]["items"]
                    self.assertIn({"key": "tls-ca-bundle.crt", "path": mounts["/config/tls/ca.crt"]["subPath"]}, pub)
                    # every mount has a volume, every volume is mounted
                    self.assertEqual({m["name"] for m in c["volumeMounts"]} - {"data"}, set(vol))


class ExchangeNeedsAdmin(Base):
    def test_tree_without_admincerts_refused(self):
        import shutil
        shutil.rmtree(os.path.join(self.ex, "org2", "msp", "admincerts"))
        tce.manifest(os.path.join(self.ex, "org2"))
        with self.assertRaises(SystemExit):
            render.render("bi", **self.kw("bi"))


class NetworkPolicyTests(Base):
    def np(self, party):
        return next(x for x in self.docs(party) if x["kind"] == "NetworkPolicy")

    def test_cluster1(self):
        for p, n in PARTIES.items():
            x = self.np(p)
            self.assertEqual(x["spec"]["podSelector"], {"matchLabels": {"rd-fabricx/arma-party": str(n)}})
            self.assertEqual(x["spec"]["policyTypes"], ["Ingress"])
            (rule,) = x["spec"]["ingress"]
            self.assertEqual([q["port"] for q in rule["ports"]], [8011, 8012, 8013, 8014])
            self.assertEqual({q["protocol"] for q in rule["ports"]}, {"TCP"})
            ns = {"namespaceSelector": {"matchLabels": {"part-of": "rd-fabricx"}}}
            if p == "bank-c":
                self.assertEqual(rule["from"], [{"ipBlock": {"cidr": "8.215.62.92/32"}}])       # the cluster-1 egress; no other namespace on cluster 2
            else:
                self.assertEqual(rule["from"], [ns, {"ipBlock": {"cidr": "47.237.84.150/32"}}])  # the cluster-2 egress

    def test_clb_health_cidr_is_opt_in_and_exactly_100_64(self):
        for p in PARTIES:
            default = self.np(p)["spec"]["ingress"][0]["from"]
            self.assertNotIn({"ipBlock": {"cidr": "100.64.0.0/10"}}, default)                    # S10b rule: only AFTER the ACL read-back
            x = next(d for d in self.docs(p, clb_health_cidr="100.64.0.0/10") if d["kind"] == "NetworkPolicy")
            self.assertEqual(x["spec"]["ingress"][0]["from"], default + [{"ipBlock": {"cidr": "100.64.0.0/10"}}])   # one more element, nothing else changes
        for bad in ("0.0.0.0/0", "100.64.0.0/16", "10.0.0.0/8", ""):
            with self.assertRaises(SystemExit):
                render.render("bi", **self.kw("bi", clb_health_cidr=bad))

    def test_ports_follow_the_port_plan(self):
        self.assertEqual([q["port"] for q in self.np("bi")["spec"]["ingress"][0]["ports"]], sorted(enroll.PORT_PLAN.values()))
