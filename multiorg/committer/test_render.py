"""Offline tests for multiorg/committer/render.py (fabricx S12: committer per org). No cluster, no files outside the repo.

  python3 -m unittest discover -s multiorg/committer        (needs PyYAML)
"""
import difflib, importlib.util, os, shutil, subprocess, sys, tempfile, unittest
from unittest import mock
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import render

PARTIES = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
# k8s.py:37-38 (panurus-itest/scripts/k8s.py): the digests the cluster runs today
COMMITTER = "docker.io/hyperledger/fabric-x-committer@sha256:b5bc4c6c010f54843dfb023cb1f18f56d4cd9b958565efd243e20a0a35b5a13d"
PG = "docker.io/library/postgres@sha256:7958605b474b3d264a969cb3a123d6aa00ad1e1fe9da8a69984dabb704d93317"
SVC_PORT = {"verifier": 5110, "vc": 5100, "coordinator": 5120, "sidecar": 5130, "query": 5140}
MON_PORT = {"verifier": 5210, "vc": 5200, "coordinator": 5220, "sidecar": 5230, "query": 5240}
C1 = {1: "10.200.55.11", 2: "10.200.27.215", 3: "10.200.63.143", 4: "47.236.199.240"}
C2 = {1: "8.215.24.249", 2: "8.215.30.255", 3: "147.139.133.68", 4: "10.210.48.103"}
# Secrets are NOT rendered: names and keys the parent creates in a separate approved step (RUNBOOK-S12.md)
EXTERNAL_SECRETS = {"committer-db-tls": {"server.crt", "server.key", "ca.crt"},
                    "committer-db-credentials": {"password"},
                    "committer-tls": {"server.crt", "server.key", "ca.crt"},
                    "committer-sidecar-msp": {"keystore-priv_sk", "signcert.pem", "cacert.pem"}}
EXTERNAL_CONFIGMAPS = {"genesis-block": {"genesis.block"}}   # made by multiorg/arma/render.py in every namespace
CONFIGS = ("verifier", "vc", "coordinator", "sidecar", "query")


def load(path):
    with open(path) as f:
        return f.read()


class Base(unittest.TestCase):
    def kw(self, party, **over):
        kw = {}
        if party == "bank-c":
            kw.update(zone="ap-southeast-1a", storage_class="fabricx-essd")
        kw.update(over)
        return kw

    def docs(self, party="bi", **over):
        return list(yaml.safe_load_all(render.render(party, **self.kw(party, **over))))

    def by(self, party="bi", kind=None, **over):
        return {x["metadata"]["name"]: x for x in self.docs(party, **over) if kind is None or x["kind"] == kind}

    def workloads(self, party="bi", **over):
        return {x["metadata"]["name"]: x for x in self.docs(party, **over) if x["kind"] in ("Deployment", "StatefulSet")}

    def cfg(self, party, svc, **over):
        return yaml.safe_load(self.by(party, "ConfigMap", **over)[f"committer-config-{svc}"]["data"][f"{svc}.yaml"])

    def cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(HERE, "render.py"), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)

    def refused(self, party="bi", **over):
        with self.assertRaises(SystemExit):
            render.render(party, **self.kw(party, **over))


class Objects(Base):
    def test_names_kinds_and_order(self):
        for p, ns in ((p, f"rd-fabricx-{p}") for p in PARTIES):
            with self.subTest(party=p):
                d = self.docs(p)
                got = [(x["kind"], x["metadata"]["name"]) for x in d]
                want = [("ConfigMap", f"committer-config-{s}") for s in CONFIGS] + [("ConfigMap", "committer-msp-config"), ("NetworkPolicy", "committer-traffic")]
                want += [("Service", n) for n in ("committer-db", "committer-verifier", "committer-vc", "committer-coordinator",
                                                  "committer-sidecar", "committer-query-service")]
                want += [("StatefulSet", "committer-db"), ("Deployment", "committer-verifier"), ("Deployment", "committer-vc"),
                         ("Deployment", "committer-coordinator"), ("StatefulSet", "committer-sidecar"), ("Deployment", "committer-query")]
                self.assertEqual(got, want)
                self.assertEqual({x["metadata"]["namespace"] for x in d}, {ns})
                for x in d:
                    self.assertEqual(x["metadata"]["labels"], {"app.kubernetes.io/part-of": "rd-fabricx", "party": p, "rd-fabricx/committer": "true"})

    def test_no_secret_object_and_no_credential(self):
        for p in PARTIES:
            text = render.render(p, **self.kw(p))
            self.assertNotIn("Secret", {x["kind"] for x in yaml.safe_load_all(text)})
            for bad in ("PRIVATE KEY", "BEGIN CERT", "password: set-by-environment-not"):
                self.assertNotIn(bad, text)
        self.assertIn("set-by-environment", render.render("bi"))   # the old placeholder, the value comes from a Secret by env

    def test_cli_prints_the_same_documents(self):
        r = self.cli("bank-a")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stderr, "")
        self.assertEqual(list(yaml.safe_load_all(r.stdout)), self.docs("bank-a"))

    def test_unknown_party_refused(self):
        with self.assertRaises(SystemExit):
            render.render("bank-z")
        r = self.cli("bank-z")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")

    def test_services_are_clusterip_with_named_ports(self):
        want = {"committer-db": ("pg", 5432), "committer-verifier": ("verifier", 5110), "committer-vc": ("vc", 5100),
                "committer-coordinator": ("coordinator", 5120), "committer-sidecar": ("sidecar", 5130),
                "committer-query-service": ("query", 5140)}
        wl = self.workloads()
        for name, s in self.by("bi", "Service").items():
            with self.subTest(service=name):
                self.assertEqual(s["spec"].get("type", "ClusterIP"), "ClusterIP")      # query-service too: no public address
                self.assertNotIn("loadBalancerSourceRanges", s["spec"])
                pn, port = want[name]
                self.assertEqual(s["spec"]["ports"], [{"name": pn, "port": port, "targetPort": pn, "protocol": "TCP"}])
                # the selector matches exactly one workload and that workload declares the named port
                (w,) = [w for w in wl.values() if all(w["spec"]["template"]["metadata"]["labels"].get(k) == v for k, v in s["spec"]["selector"].items())]
                ports = {c["name"]: c["containerPort"] for c in w["spec"]["template"]["spec"]["containers"][0]["ports"]}
                self.assertEqual(ports[pn], port)

    def test_container_ports_named_and_monitoring(self):
        for svc in CONFIGS:
            w = self.workloads()["committer-" + svc]
            ports = {c["name"]: c["containerPort"] for c in w["spec"]["template"]["spec"]["containers"][0]["ports"]}
            self.assertEqual(ports, {svc: SVC_PORT[svc], "mon": MON_PORT[svc]})
            cfg = self.cfg("bi", svc)
            self.assertEqual(cfg["server"]["endpoint"], f":{SVC_PORT[svc]}")
            self.assertEqual(cfg["monitoring"]["endpoint"], f":{MON_PORT[svc]}")

    def test_workload_shape(self):
        wl = self.workloads()
        self.assertEqual(wl["committer-db"]["kind"], "StatefulSet")
        self.assertEqual(wl["committer-sidecar"]["kind"], "StatefulSet")
        for n, w in wl.items():
            self.assertEqual(w["spec"]["replicas"], 1)
            self.assertEqual(w["spec"]["selector"]["matchLabels"], {"app.kubernetes.io/name": n})
            self.assertEqual(w["spec"]["template"]["metadata"]["labels"]["app.kubernetes.io/name"], n)
            if w["kind"] == "StatefulSet":
                self.assertEqual(w["spec"]["serviceName"], n)
            else:
                self.assertEqual(w["spec"]["strategy"], {"type": "Recreate"})
        for svc in ("verifier", "vc", "coordinator", "query"):
            c = wl["committer-" + svc]["spec"]["template"]["spec"]["containers"]
            self.assertEqual(len(c), 1)
            self.assertEqual(c[0]["args"], ["start", svc, f"--config=/config/{svc}.yaml"])    # k8s.py:216, proven live
            self.assertNotIn("command", c[0])
        c = wl["committer-sidecar"]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["args"], ["start", "sidecar", "--config=/config/sidecar.yaml"])

    def test_pvcs(self):
        wl = self.workloads()
        v = wl["committer-db"]["spec"]["volumeClaimTemplates"]
        self.assertEqual([(x["metadata"]["name"], x["spec"]["resources"]["requests"]["storage"]) for x in v], [("data", "5Gi")])
        v = wl["committer-sidecar"]["spec"]["volumeClaimTemplates"]
        self.assertEqual([x["metadata"]["name"] for x in v], ["ledger"])
        for w in wl.values():
            for x in w["spec"].get("volumeClaimTemplates", []):
                self.assertEqual(x["spec"]["accessModes"], ["ReadWriteOnce"])
                self.assertEqual(x["spec"]["storageClassName"], "alicloud-essd-wffc")
        self.assertIn({"name": "ledger", "mountPath": "/data"}, wl["committer-sidecar"]["spec"]["template"]["spec"]["containers"][0]["volumeMounts"])


class Images(Base):
    def test_by_digest(self):
        for p in PARTIES:
            for n, w in self.workloads(p).items():
                for c in w["spec"]["template"]["spec"]["containers"]:
                    self.assertEqual(c["image"], PG if n == "committer-db" else COMMITTER, n)
        self.assertNotIn(":latest", render.render("bi"))   # (the config key latest-known-config-block-path is no tag)

    def test_override_by_digest_and_refused_tags(self):
        other = "registry.example/x/committer@sha256:" + "a" * 64
        pg = "registry.example/x/pg@sha256:" + "b" * 64
        wl = self.workloads("bi", image=other, pg_image=pg)
        self.assertEqual(wl["committer-vc"]["spec"]["template"]["spec"]["containers"][0]["image"], other)
        self.assertEqual(wl["committer-db"]["spec"]["template"]["spec"]["containers"][0]["image"], pg)
        for bad in ("docker.io/hyperledger/fabric-x-committer:1.0.4", "x/y:latest", "x/y@sha256:abc", "x/y@sha256:" + "A" * 64, "", None):
            self.refused(image=bad)
            self.refused(pg_image=bad)
        r = self.cli("bi", "--image", "x/y:latest")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")


class Pods(Base):
    def test_security_context_on_every_pod(self):
        for p in PARTIES:
            for n, w in self.workloads(p).items():
                with self.subTest(party=p, workload=n):
                    spec = w["spec"]["template"]["spec"]
                    uid = 999 if n == "committer-db" else 10001    # the postgres image user (k8s.py: runAsUser 999); the committer image USER 10001
                    self.assertEqual(spec["securityContext"], {"runAsNonRoot": True, "runAsUser": uid, "fsGroup": uid, "seccompProfile": {"type": "RuntimeDefault"}})
                    for k in ("hostNetwork", "hostPID", "hostIPC"):
                        self.assertNotIn(k, spec)
                    for v in spec["volumes"]:
                        self.assertNotIn("hostPath", v)
                    for c in spec["containers"]:
                        self.assertEqual(c["securityContext"], {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}})
                        self.assertNotIn("privileged", c["securityContext"])
        self.assertNotIn("hostPath", render.render("bi"))
        self.assertNotIn("privileged", render.render("bi"))

    def test_resources_on_every_container(self):
        for n, w in self.workloads().items():
            for c in w["spec"]["template"]["spec"]["containers"]:
                for side in ("requests", "limits"):
                    self.assertEqual(set(c["resources"][side]), {"cpu", "memory", "ephemeral-storage"}, f"{n} {side}")

    def test_every_mount_has_a_volume_and_every_volume_is_mounted(self):
        for n, w in self.workloads().items():
            spec = w["spec"]["template"]["spec"]
            vols = {v["name"] for v in spec["volumes"]} | {v["metadata"]["name"] for v in w["spec"].get("volumeClaimTemplates", [])}
            mounted = {m["name"] for c in spec["containers"] for m in c["volumeMounts"]}
            self.assertEqual(vols, mounted, n)
            paths = [m["mountPath"] for c in spec["containers"] for m in c["volumeMounts"]]
            self.assertEqual(len(paths), len(set(paths)), f"{n}: two mounts on one path")

    def test_secrets_and_configmaps_referenced_exist(self):
        rendered = {n: set(c.get("data", {})) for n, c in self.by("bi", "ConfigMap").items()}
        for n, w in self.workloads().items():
            spec = w["spec"]["template"]["spec"]
            for v in spec["volumes"]:
                if "secret" in v:
                    s = v["secret"]
                    self.assertIn(s["secretName"], EXTERNAL_SECRETS, n)
                    self.assertTrue({i["key"] for i in s["items"]} <= EXTERNAL_SECRETS[s["secretName"]], n)
                    self.assertEqual(s["defaultMode"], 0o400)
                elif "configMap" in v:
                    c = v["configMap"]
                    known = rendered.get(c["name"]) or EXTERNAL_CONFIGMAPS.get(c["name"])
                    self.assertIsNotNone(known, f"{n}: ConfigMap {c['name']} is neither rendered nor external")
                    self.assertTrue({i["key"] for i in c["items"]} <= known, n)
            for c in spec["containers"]:
                for e in c.get("env", []):
                    ref = e.get("valueFrom", {}).get("secretKeyRef")
                    if ref:
                        self.assertIn(ref["key"], EXTERNAL_SECRETS[ref["name"]], n)

    def test_subpath_mounts_match_a_volume_item(self):
        for n, w in self.workloads().items():
            spec = w["spec"]["template"]["spec"]
            items = {v["name"]: {i["path"] for i in (v.get("secret") or v.get("configMap")).get("items", [])} for v in spec["volumes"] if "secret" in v or "configMap" in v}
            for c in spec["containers"]:
                for m in c["volumeMounts"]:
                    if m["name"] in items:
                        self.assertIn(m["subPath"], items[m["name"]], f"{n} {m['mountPath']}")
                        self.assertTrue(m["readOnly"])


class Config(Base):
    def test_vc_and_query_database_tls(self):
        for p in PARTIES:
            for svc in ("vc", "query"):
                with self.subTest(party=p, svc=svc):
                    db = self.cfg(p, svc)["database"]
                    self.assertEqual(db["tls"], {"mode": "tls", "ca-cert-path": "/config/db-tls/ca.crt"})   # upstream samples: vc.yaml:62-67; docs tls-configurations.md:129-136
                    self.assertEqual(db["endpoints"], ["committer-db:5432"])
                    text = self.by(p, "ConfigMap")[f"committer-config-{svc}"]["data"][f"{svc}.yaml"]
                    self.assertNotIn("mode: none", text)            # the old no-TLS line, vc.yaml:19
                    self.assertNotIn("without TLS", text)
                    self.assertEqual(db["password"], "set-by-environment")
                    self.assertEqual(db["username"], "committer")
                    w = self.workloads(p)[f"committer-{svc}"]["spec"]["template"]["spec"]
                    m = {x["mountPath"]: x for x in w["containers"][0]["volumeMounts"]}
                    self.assertIn("/config/db-tls/ca.crt", m)
                    vol = {v["name"]: v for v in w["volumes"]}[m["/config/db-tls/ca.crt"]["name"]]
                    self.assertEqual(vol["secret"]["secretName"], "committer-db-tls")
                    self.assertEqual(m["/config/db-tls/ca.crt"]["subPath"], "ca.crt")
                    env = {e["name"]: e["valueFrom"]["secretKeyRef"] for e in w["containers"][0]["env"]}
                    self.assertEqual(env, {f"SC_{svc.upper()}_DATABASE_PASSWORD": {"name": "committer-db-credentials", "key": "password"}})

    def test_postgres_serves_tls(self):
        spec = self.workloads()["committer-db"]["spec"]["template"]["spec"]
        c = spec["containers"][0]
        args = c["args"]
        self.assertEqual(args[0], "postgres")
        pairs = [args[i + 1] for i, a in enumerate(args) if a == "-c"]
        self.assertEqual(sorted(pairs), ["ssl=on", "ssl_cert_file=/tls/server.crt", "ssl_key_file=/tls/server.key"])
        m = {x["mountPath"]: x for x in c["volumeMounts"]}
        vols = {v["name"]: v for v in spec["volumes"]}
        for path, key in (("/tls/server.crt", "server.crt"), ("/tls/server.key", "server.key")):
            self.assertEqual((vols[m[path]["name"]]["secret"]["secretName"], m[path]["subPath"]), ("committer-db-tls", key))
        self.assertNotIn("/tls/ca.crt", m)                                       # the CA is for clients, the server does not need it
        env = {e["name"]: e.get("value") or e["valueFrom"]["secretKeyRef"] for e in c["env"]}
        self.assertEqual(env["POSTGRES_USER"], "committer")
        self.assertEqual(env["POSTGRES_DB"], "committer")
        self.assertEqual(env["POSTGRES_PASSWORD"], {"name": "committer-db-credentials", "key": "password"})
        self.assertEqual(env["PGDATA"], "/var/lib/postgresql/data/pgdata")       # a subdirectory: the volume root holds lost+found
        self.assertEqual(m["/var/lib/postgresql/data"]["name"], "data")

    def test_sidecar_mtls_bft_and_config_block(self):
        for p, n in PARTIES.items():
            with self.subTest(party=p):
                cfg = self.cfg(p, "sidecar")
                self.assertEqual(cfg["server"]["tls"]["mode"], "mtls")
                self.assertEqual(cfg["monitoring"]["tls"]["mode"], "mtls")
                o = cfg["orderer"]
                self.assertEqual(o["fault-tolerance-level"], "BFT")                           # upstream sample sidecar.yaml:69
                self.assertEqual(o["latest-known-config-block-path"], "/config/config-block.pb.bin")   # sample sidecar.yaml:74
                self.assertEqual(o["tls"]["mode"], "mtls")
                self.assertEqual(o["identity"]["msp-dir"], "/config/msp")
                self.assertEqual(cfg["committer"]["endpoint"], "committer-coordinator:5120")
                self.assertEqual(cfg["committer"]["tls"]["mode"], "mtls")
                self.assertEqual(cfg["ledger"]["path"], "/data/ledger")
                spec = self.workloads(p)["committer-sidecar"]["spec"]["template"]["spec"]
                c = spec["containers"][0]
                m = {x["mountPath"]: x for x in c["volumeMounts"]}
                vols = {v["name"]: v for v in spec["volumes"]}
                cb = vols[m["/config/config-block.pb.bin"]["name"]]["configMap"]
                self.assertEqual((cb["name"], m["/config/config-block.pb.bin"]["subPath"]), ("genesis-block", "config-block.pb.bin"))
                self.assertEqual(cb["items"], [{"key": "genesis.block", "path": "config-block.pb.bin"}])
                for path, key in (("/config/msp/keystore/priv_sk", "keystore-priv_sk"), ("/config/msp/signcerts/cert.pem", "signcert.pem"),
                                  ("/config/msp/cacerts/ca.pem", "cacert.pem")):
                    self.assertEqual((vols[m[path]["name"]]["secret"]["secretName"], {i["key"]: i["path"] for i in vols[m[path]["name"]]["secret"]["items"]}[key]),
                                     ("committer-sidecar-msp", m[path]["subPath"]))
                self.assertEqual(vols[m["/config/msp/config.yaml"]["name"]]["configMap"]["name"], "committer-msp-config")
                env = {e["name"]: e["value"] for e in c["env"]}
                self.assertEqual(env, {"SC_SIDECAR_ORDERER_IDENTITY_MSP_ID": f"org{n}"})     # compose.yaml:31; arma default MSP id org<N>
        env = {e["name"]: e["value"] for e in self.workloads("bi", msp_id_format="OrdererOrg{n}MSP")["committer-sidecar"]["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["SC_SIDECAR_ORDERER_IDENTITY_MSP_ID"], "OrdererOrg1MSP")
        self.refused(msp_id_format="nope")
        self.refused(msp_id_format="{n} bad")

    def test_msp_config_names_the_mounted_ca(self):
        m = yaml.safe_load(self.by("bi", "ConfigMap")["committer-msp-config"]["data"]["config.yaml"])["NodeOUs"]
        self.assertTrue(m["Enable"])
        for ou in ("client", "peer", "admin", "orderer"):
            self.assertEqual(m[f"{ou.capitalize()}OUIdentifier"], {"Certificate": "cacerts/ca.pem", "OrganizationalUnitIdentifier": ou})

    def test_internal_endpoints_use_the_committer_service_names(self):
        co = self.cfg("bi", "coordinator")
        self.assertEqual(co["verifier"]["endpoints"], ["committer-verifier:5110"])
        self.assertEqual(co["validator-committer"]["endpoints"], ["committer-vc:5100"])
        services = set(self.by("bi", "Service"))
        for ep in (co["verifier"]["endpoints"] + co["validator-committer"]["endpoints"] + [self.cfg("bi", "sidecar")["committer"]["endpoint"]]):
            self.assertIn(ep.split(":")[0], services)

    def test_only_the_planned_lines_differ_from_the_old_config(self):
        want = {"verifier": 0, "vc": 3, "query": 2, "coordinator": 2, "sidecar": 1}       # changed old lines per file
        for svc, k in want.items():
            old = load(os.path.join(HERE, "config", f"{svc}.yaml")).splitlines()
            new = self.by("bi", "ConfigMap")[f"committer-config-{svc}"]["data"][f"{svc}.yaml"].splitlines()
            gone = [d for d in difflib.unified_diff(old, new, lineterm="", n=0) if d.startswith("-") and not d.startswith("---")]
            self.assertEqual(len(gone), k, f"{svc}: {gone}")
        self.assertEqual(load(os.path.join(HERE, "config", "verifier.yaml")),
                         self.by("bi", "ConfigMap")["committer-config-verifier"]["data"]["verifier.yaml"])


class Drift(Base):
    """A template whose rule lines changed is refused (rule must hit exactly once), nothing printed."""

    def patched(self, name, old, new):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        for f in os.listdir(os.path.join(HERE, "config")):
            shutil.copy(os.path.join(HERE, "config", f), d)
        p = os.path.join(d, name)
        text = load(p)
        self.assertIn(old, text)
        with open(p, "w") as f:
            f.write(text.replace(old, new))
        return mock.patch.object(render, "CONFIG_DIR", d)

    def test_modified_rule_line_dies(self):
        for name, old, new in (("vc.yaml", "  tls: {mode: none}", "  tls: {mode: none, x: 1}"),
                               ("vc.yaml", "  endpoints: [db:5432]", "  endpoints: [db:5433]"),
                               ("query.yaml", "  tls: {mode: none}", "  tls: {mode: tls}"),
                               ("coordinator.yaml", "  endpoints: [vc:5100]", "  endpoints: [vc:5101]"),
                               ("sidecar.yaml", "  endpoint: coordinator:5120", "  endpoint: coordinator:5121")):
            with self.subTest(file=name, old=old), self.patched(name, old, new):
                self.refused()

    def test_duplicated_rule_line_dies(self):
        with self.patched("vc.yaml", "  tls: {mode: none}\n", "  tls: {mode: none}\n  tls: {mode: none}\n"):
            self.refused()

    def test_missing_template_dies(self):
        with mock.patch.object(render, "CONFIG_DIR", tempfile.gettempdir() + "/no-such-config-dir"):
            self.refused()

    def test_unrelated_line_change_is_carried_over(self):
        with self.patched("verifier.yaml", "parallelism: 8", "parallelism: 4"):
            self.assertEqual(self.cfg("bi", "verifier")["parallelism"], 4)


class Placement(Base):
    def test_cluster1_defaults(self):
        for p in ("bi", "bank-a", "bank-b"):
            for n, w in self.workloads(p).items():
                spec = w["spec"]["template"]["spec"]
                self.assertEqual(spec["nodeSelector"], {"topology.kubernetes.io/zone": "ap-southeast-5b"})
                self.assertEqual(spec["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"][0]["matchExpressions"][0]["values"],
                                 ["member-16033-node", "member-16034-node"])
                for x in w["spec"].get("volumeClaimTemplates", []):
                    self.assertEqual(x["spec"]["storageClassName"], "alicloud-essd-wffc")
                self.assertEqual({a["ip"] for a in spec.get("hostAliases", [])}, set(C1.values()) if n == "committer-sidecar" else set())

    def test_bank_c_requires_zone_and_storage_class(self):
        for over in ({}, {"zone": "ap-southeast-1a"}, {"storage_class": "fabricx-essd"}):
            with self.assertRaises(SystemExit):
                render.render("bank-c", **over)
        r = self.cli("bank-c")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")
        r = self.cli("bank-c", "--zone", "ap-southeast-1a")
        self.assertNotEqual(r.returncode, 0)
        r = self.cli("bank-c", "--zone", "ap-southeast-1a", "--storage-class", "fabricx-essd")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_bank_c_cluster2_values(self):
        for n, w in self.workloads("bank-c").items():
            spec = w["spec"]["template"]["spec"]
            self.assertEqual(spec["nodeSelector"], {"topology.kubernetes.io/zone": "ap-southeast-1a"})
            self.assertNotIn("affinity", spec)                                   # the cluster-1 node names do not exist there
            for x in w["spec"].get("volumeClaimTemplates", []):
                self.assertEqual(x["spec"]["storageClassName"], "fabricx-essd")
        al = self.workloads("bank-c")["committer-sidecar"]["spec"]["template"]["spec"]["hostAliases"]
        self.assertEqual({a["ip"] for a in al}, set(C2.values()))
        self.assertEqual({h: a["ip"] for a in al for h in a["hostnames"]}["assembler-4.arma.rd"], "10.210.48.103")

    def test_bad_zone_and_class_refused(self):
        self.refused(zone="Bad Zone")
        self.refused(storage_class="Bad_Class")

    def test_storage_class_is_never_created(self):
        for p in PARTIES:
            self.assertNotIn("StorageClass", {x["kind"] for x in self.docs(p)})


class Network(Base):
    def test_sidecar_resolves_the_arma_names(self):
        for p, n in PARTIES.items():
            table = C2 if p == "bank-c" else C1
            al = self.workloads(p)["committer-sidecar"]["spec"]["template"]["spec"]["hostAliases"]
            self.assertEqual(al, [{"ip": table[m], "hostnames": [f"{r}-{m}.arma.rd" for r in ("router", "batcher1", "consenter", "assembler")]} for m in (1, 2, 3, 4)])
            self.assertIn(f"assembler-{n}.arma.rd", next(a for a in al if a["ip"] == table[n])["hostnames"])   # the own assembler

    def test_networkpolicy(self):
        for p, n in PARTIES.items():
            table = C2 if p == "bank-c" else C1
            np = self.by(p, "NetworkPolicy")["committer-traffic"]
            s = np["spec"]
            self.assertEqual(s["podSelector"], {"matchLabels": {"rd-fabricx/committer": "true"}})
            self.assertEqual(s["policyTypes"], ["Ingress", "Egress"])
            self.assertEqual(s["ingress"], [{"from": [{"podSelector": {}}]}])        # same namespace only: no namespaceSelector, no ipBlock
            eg = s["egress"]
            self.assertEqual(eg[0], {"to": [{"podSelector": {}}]})
            self.assertEqual(eg[1], {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                                     "ports": [{"protocol": p_, "port": 53} for p_ in ("UDP", "TCP")]})
            blocks = [t["ipBlock"]["cidr"] for r in eg[2:] for t in r["to"]]
            self.assertEqual(sorted(blocks), sorted(f"{ip}/32" for ip in table.values()))   # the four assemblers (BFT headers), own included
            self.assertIn(f"{table[n]}/32", blocks)
            for r in eg[2:]:
                self.assertEqual(r["ports"], [{"protocol": "TCP", "port": 8011}])            # the assembler port only
            for rule in s["ingress"] + eg:
                for t in rule["to" if "to" in rule else "from"]:
                    self.assertNotIn("0.0.0.0/0", str(t))

    def test_ips_file_replaces_the_table(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "ips.yaml")
        with open(path, "w") as f:
            yaml.safe_dump({"cluster1": {1: "10.1.0.1", 2: "10.1.0.2", 3: "10.1.0.3", 4: "10.1.0.4"},
                            "cluster2": {1: "10.2.0.1", 2: "10.2.0.2", 3: "10.2.0.3", 4: "10.2.0.4"}}, f)
        al = self.workloads("bi", ips=path)["committer-sidecar"]["spec"]["template"]["spec"]["hostAliases"]
        self.assertEqual([a["ip"] for a in al], ["10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4"])
        with open(path, "w") as f:
            f.write("cluster1: {}\n")
        self.refused(ips=path)


if __name__ == "__main__":
    unittest.main()
