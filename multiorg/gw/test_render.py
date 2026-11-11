"""Offline tests for multiorg/gw/render.py (fabricx S16: the fx-gw-<N> gateway of one org). No cluster, no key read.

  python3 -m unittest discover -s multiorg/gw
"""
import importlib.util, os, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("gw_render", os.path.join(HERE, "render.py"))   # fca/arma/committer/fsc all have a render.py
render = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render)

PARTIES = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
NODE = {"bi": "issuer", "bank-a": "bank2", "bank-b": "bank3", "bank-c": "bank4"}
DIG = lambda c: f"example.io/img/{c}@sha256:" + c * 64
IMG, ENVOY, OPA = DIG("a"), DIG("b"), DIG("c")
CERT = "-----BEGIN CERTIFICATE-----\nMIIgw\n-----END CERTIFICATE-----\n"
OPA_CFG = """plugins:
  envoy_ext_authz_grpc:
    addr: 127.0.0.1:9191
    path: gw/allow
    dry-run: false
services:
  bundle-server:
    url: http://bundle-server
  sink:
    url: http://bundle-server:8081
    credentials:
      bearer:
        token_path: /sink-token/token
bundles:
  bi:
    service: bundle-server
    signing: {keyid: bi}
  bank:
    service: bundle-server
    signing: {keyid: bi}
decision_logs:
  console: true
  service: sink
status:
  service: sink
keys:
  bi:
    algorithm: RS256
    key: |
      -----BEGIN PUBLIC KEY-----
      MIIBpub
      -----END PUBLIC KEY-----
"""
GW_IPS = {"cluster1": {1: "10.0.1.1", 2: "10.0.1.2", 3: "10.0.1.3"}, "cluster2": {4: "8.8.8.4"}}


def write_roots(root):
    for m in (1, 2, 3, 4):
        p = f"{root}/tlsx/org{m}/msp/tlscacerts/tlsca.pem"
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(CERT.replace("MIIgw", f"ROOT{m}"))


def make_inputs(root):
    for n in ("issuer", "bank2", "bank3", "bank4"):
        os.makedirs(f"{root}/live/{n}")
        with open(f"{root}/live/{n}/client-config.yaml", "w") as f:
            yaml.safe_dump({"version": 0, "address": "127.0.0.1:5103", "tlsconfig": {"certpath": "", "keypath": "", "peercacertpath": f"/old/{n}/tls/ca.crt", "timeout": "10m0s"},
                            "signerconfig": {"mspid": "", "identitypath": f"/old/{n}/signcert.pem", "keypath": f"/old/{n}/priv_sk"}}, f)
    with open(f"{root}/live/issuer-identity.bin", "wb") as f:
        f.write(b"\x00\x01issuer\xff")
    with open(f"{root}/opa-config.yaml", "w") as f:
        f.write(OPA_CFG)
    with open(f"{root}/gw.pem", "w") as f:
        f.write(CERT)
    write_roots(root)
    with open(f"{root}/gw-ips.yaml", "w") as f:
        yaml.safe_dump(GW_IPS, f)


def build(root, party, **kw):
    a = dict(templates=f"{root}/live", image=IMG, envoy_image=ENVOY, opa_image=OPA, opa_config=f"{root}/opa-config.yaml", gw_cert=f"{root}/gw.pem",
             gw_ips=f"{root}/gw-ips.yaml", tls_exchange=f"{root}/tlsx")
    a.update(kw)
    return list(yaml.safe_load_all(render.render(party, **a)))


def by(docs, kind, name=None):
    r = [d for d in docs if d["kind"] == kind and (name is None or d["metadata"]["name"] == name)]
    assert len(r) == 1, (kind, name, [d["metadata"]["name"] for d in docs])
    return r[0]


class GwRender(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        make_inputs(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_objects_per_party(self):
        for p, n in PARTIES.items():
            docs = build(self.root, p)
            kinds = sorted((d["kind"], d["metadata"]["name"]) for d in docs)
            self.assertIn(("Deployment", f"fx-gw-{n}"), kinds)
            self.assertIn(("Service", f"fx-gw-{n}"), kinds)
            self.assertIn(("ConfigMap", f"fx-gw-{n}-envoy"), kinds)
            self.assertIn(("ConfigMap", f"fx-gw-{n}-opa"), kinds)
            self.assertIn(("ConfigMap", f"fx-gw-{n}-client"), kinds)
            self.assertIn(("NetworkPolicy", f"fx-gw-{n}"), kinds)
            for d in docs:
                self.assertEqual(d["metadata"]["namespace"], f"rd-fabricx-{p}")
            self.assertFalse([d for d in docs if d["kind"] == "Secret"], "no Secret is rendered")
            self.assertFalse([d for d in docs if d["kind"] == "Service" and d["spec"].get("type") == "LoadBalancer"], "no LB without --lb-acl")

    def test_digests_required(self):
        for k in ("image", "envoy_image", "opa_image"):
            with self.assertRaises(SystemExit):
                build(self.root, "bi", **{k: "example.io/x:latest"})
        text = render.render("bi", templates=f"{self.root}/live", image=IMG, envoy_image=ENVOY, opa_image=OPA, opa_config=f"{self.root}/opa-config.yaml",
                             gw_cert=f"{self.root}/gw.pem", gw_ips=f"{self.root}/gw-ips.yaml", tls_exchange=f"{self.root}/tlsx")
        self.assertNotIn(":latest", text)

    def test_envoy_forwards_verified_client_cert_to_opa(self):
        env = yaml.safe_load(by(build(self.root, "bank-a"), "ConfigMap", "fx-gw-2-envoy")["data"]["envoy.yaml"])
        lst = env["static_resources"]["listeners"][0]
        self.assertEqual(lst["address"]["socket_address"]["port_value"], 8443)
        fc = lst["filter_chains"][0]
        tls = fc["transport_socket"]["typed_config"]
        self.assertTrue(tls["require_client_certificate"])
        self.assertEqual(tls["common_tls_context"]["validation_context"]["trusted_ca"]["filename"], "/client-ca/ca.crt")
        self.assertEqual(tls["common_tls_context"]["tls_certificates"][0]["certificate_chain"]["filename"], "/mtls/tls.crt")
        hcm = fc["filters"][0]["typed_config"]
        self.assertEqual(hcm["forward_client_cert_details"], "SANITIZE_SET")
        self.assertEqual(hcm["set_current_client_cert_details"], {"cert": True, "subject": True})
        authz = hcm["http_filters"][0]["typed_config"]
        self.assertFalse(authz["failure_mode_allow"])
        self.assertEqual(authz["with_request_body"]["max_request_bytes"], 65536)
        ext = hcm["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"]["envoy.filters.http.ext_authz"]["check_settings"]["context_extensions"]
        self.assertEqual(ext, {"target": "fabricx", "node": "node2"})
        clusters = {c["name"]: c for c in env["static_resources"]["clusters"]}
        self.assertEqual(clusters["fxapi"]["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["socket_address"], {"address": "127.0.0.1", "port_value": 8080})
        self.assertEqual(clusters["opa"]["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["socket_address"], {"address": "127.0.0.1", "port_value": 9191})

    def test_opa_bundles_read_side_only(self):
        for p, n in PARTIES.items():
            docs = build(self.root, p)
            op = yaml.safe_load(by(docs, "ConfigMap", f"fx-gw-{n}-opa")["data"]["opa.yaml"])
            self.assertEqual(op["services"]["bundle-server"]["url"], f"http://bundle-server.rd-zeto-{p}.svc.cluster.local:8080")
            self.assertNotIn("sink", op["services"])
            self.assertNotIn("service", op["decision_logs"])
            self.assertEqual(op["decision_logs"]["console"], True)
            self.assertEqual(op["status"], {"console": True})
            self.assertIn("keys", op)
            dep = by(docs, "Deployment", f"fx-gw-{n}")
            opa = [c for c in dep["spec"]["template"]["spec"]["containers"] if c["name"] == "opa"][0]
            self.assertIn(f"--set=bundles.bank.signing.keyid={p}", opa["args"])
            self.assertIn("--set=bundles.bi.resource=bi/latest.tar.gz", opa["args"])
            self.assertIn("--set=bundles.bank.resource=bank/latest.tar.gz", opa["args"])
            self.assertNotIn("8081", yaml.safe_dump(docs))
            self.assertNotIn("sink", yaml.safe_dump(docs))

    def test_opa_config_must_hold_public_keys_only(self):
        with open(f"{self.root}/bad.yaml", "w") as f:
            f.write(OPA_CFG + "# -----BEGIN PRIVATE KEY-----\n")
        with self.assertRaises(SystemExit):
            build(self.root, "bi", opa_config=f"{self.root}/bad.yaml")
        with open(f"{self.root}/nokeys.yaml", "w") as f:
            f.write(OPA_CFG.split("keys:")[0])
        with self.assertRaises(SystemExit):
            build(self.root, "bi", opa_config=f"{self.root}/nokeys.yaml")

    def test_pod_hardening_and_volumes(self):
        docs = build(self.root, "bank-b")
        dep = by(docs, "Deployment", "fx-gw-3")
        spec = dep["spec"]["template"]["spec"]
        self.assertEqual(spec["securityContext"]["seccompProfile"], {"type": "RuntimeDefault"})
        self.assertTrue(spec["securityContext"]["runAsNonRoot"])
        self.assertEqual(sorted(c["name"] for c in spec["containers"]), ["envoy", "fxapi", "opa"])
        for c in spec["containers"]:
            sc = c["securityContext"]
            self.assertFalse(sc["allowPrivilegeEscalation"])
            self.assertTrue(sc["readOnlyRootFilesystem"])
            self.assertEqual(sc["capabilities"], {"drop": ["ALL"]})
            self.assertRegex(c["image"], r"@sha256:[0-9a-f]{64}$")
        secrets = sorted(v["secret"]["secretName"] for v in spec["volumes"] if "secret" in v)
        self.assertEqual(secrets, ["fx-gw-3-client-ca", "fx-gw-3-server"])
        proj = sorted(s["secret"]["name"] for v in spec["volumes"] if "projected" in v for s in v["projected"]["sources"] if "secret" in s)
        self.assertEqual(proj, ["fx-gw-3-client", "fx-gw-3-peer"])
        fx = [c for c in spec["containers"] if c["name"] == "fxapi"][0]
        self.assertEqual(fx["command"], ["rdbi-driver", "serve", "bank3", "127.0.0.1:8080"])
        env = {e["name"]: e["value"] for e in fx["env"]}
        self.assertEqual(env["FXGW_TLS"], "/peer")
        self.assertEqual(env["HOME"], "/home/rdbi")
        self.assertEqual(env["RDBI_REDELIVER_INTERVAL"], "60s")
        self.assertEqual(dep["spec"]["strategy"]["type"], "Recreate")
        self.assertEqual(dep["spec"]["replicas"], 1)

    def test_redelivery_tick_is_60s_on_every_gateway(self):
        # S17: the report redeliverer runs in fxapi; empty = 60 s default, "0" = OFF (redeliver.go redeliverInterval). Pin it explicitly, never empty or 0.
        for p, n in PARTIES.items():
            fx = [c for c in by(build(self.root, p), "Deployment", f"fx-gw-{n}")["spec"]["template"]["spec"]["containers"] if c["name"] == "fxapi"][0]
            vals = [e["value"] for e in fx["env"] if e["name"] == "RDBI_REDELIVER_INTERVAL"]
            self.assertEqual(vals, ["60s"], p)

    def test_peer_volume_has_one_root_per_org_never_a_bundle(self):
        for p, n in PARTIES.items():
            docs = build(self.root, p)
            cm = by(docs, "ConfigMap", f"fx-gw-{n}-peer-ca")
            self.assertEqual(sorted(cm["data"]), ["ca-1.crt", "ca-2.crt", "ca-3.crt", "ca-4.crt"])
            for m in (1, 2, 3, 4):
                self.assertEqual(cm["data"][f"ca-{m}.crt"].count("BEGIN CERTIFICATE"), 1)
                self.assertIn(f"ROOT{m}", cm["data"][f"ca-{m}.crt"])
            vol = [v for v in by(docs, "Deployment", f"fx-gw-{n}")["spec"]["template"]["spec"]["volumes"] if v["name"] == "peer"][0]
            srcs = vol["projected"]["sources"]
            self.assertEqual([s["secret"]["name"] for s in srcs if "secret" in s], [f"fx-gw-{n}-peer"])
            cms = [s["configMap"] for s in srcs if "configMap" in s]
            self.assertEqual([c["name"] for c in cms], [f"fx-gw-{n}-peer-ca"])
            self.assertEqual([i["path"] for i in cms[0]["items"]], ["ca-1.crt", "ca-2.crt", "ca-3.crt", "ca-4.crt"])
            self.assertNotIn("ca-bundle.pem", yaml.safe_dump(vol))   # no bundle in /peer

    def test_peer_roots_must_be_one_public_root_per_org(self):
        os.remove(f"{self.root}/tlsx/org3/msp/tlscacerts/tlsca.pem")
        with self.assertRaises(SystemExit):
            build(self.root, "bi")
        write_roots(self.root)
        with open(f"{self.root}/tlsx/org2/msp/tlscacerts/tlsca.pem", "a") as f:
            f.write(CERT.replace("MIIgw", "SECOND"))   # two certificates in one org file
        with self.assertRaises(SystemExit):
            build(self.root, "bi")
        write_roots(self.root)
        with open(f"{self.root}/tlsx/org1/msp/tlscacerts/tlsca.pem", "a") as f:
            f.write("-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n")
        with self.assertRaises(SystemExit):
            build(self.root, "bi")

    def test_client_config_points_at_the_gw_identity(self):
        docs = build(self.root, "bank-a")
        cm = by(docs, "ConfigMap", "fx-gw-2-client")
        cc = yaml.safe_load(cm["data"]["client-config.yaml"])
        self.assertEqual(cc["address"], "bank2:5103")
        self.assertEqual(cc["signerconfig"]["identitypath"], "/home/rdbi/.fabricx-token/gw/bank2-gw.pem")
        self.assertEqual(cc["signerconfig"]["keypath"], "/home/rdbi/.fabricx-token/gw/bank2-gw.key")
        self.assertEqual(cc["tlsconfig"]["peercacertpath"], "/home/rdbi/.fabricx-token/live/bank2/tls-ca.crt")
        self.assertEqual(cm["data"]["bank2-gw.pem"], CERT)
        self.assertNotIn("old", yaml.safe_dump(cc))
        self.assertNotIn("binaryData", cm)

    def test_issuer_identity_for_bi_only(self):
        bi = by(build(self.root, "bi"), "ConfigMap", "fx-gw-1-client")
        self.assertEqual(len(bi["binaryData"]["issuer-identity.bin"]), len(__import__("base64").b64encode(b"\x00\x01issuer\xff").decode()))
        for p in ("bank-a", "bank-b", "bank-c"):
            self.assertNotIn("binaryData", by(build(self.root, p), "ConfigMap", f"fx-gw-{PARTIES[p]}-client"))
        os.remove(f"{self.root}/live/issuer-identity.bin")
        with self.assertRaises(SystemExit):
            build(self.root, "bi")

    def test_peer_names(self):
        # cluster 1 parties: same-cluster peers by ExternalName Service, bank-c (cluster 2) by hostAliases with the --gw-ips address
        for p in ("bi", "bank-a", "bank-b"):
            docs = build(self.root, p)
            n = PARTIES[p]
            ext = {d["metadata"]["name"]: d["spec"]["externalName"] for d in docs if d["kind"] == "Service" and d["spec"].get("type") == "ExternalName"}
            want = {f"fx-gw-{m}": f"fx-gw-{m}.rd-fabricx-{q}.svc.cluster.local" for q, m in PARTIES.items() if m != n and m != 4}
            self.assertEqual(ext, want)
            ha = by(docs, "Deployment", f"fx-gw-{n}")["spec"]["template"]["spec"]["hostAliases"]
            self.assertEqual(ha, [{"ip": "8.8.8.4", "hostnames": ["fx-gw-4"]}])
        docs = build(self.root, "bank-c")
        self.assertFalse([d for d in docs if d["kind"] == "Service" and d["spec"].get("type") == "ExternalName"])
        ha = by(docs, "Deployment", "fx-gw-4")["spec"]["template"]["spec"]["hostAliases"]
        self.assertEqual(ha, [{"ip": f"10.0.1.{m}", "hostnames": [f"fx-gw-{m}"]} for m in (1, 2, 3)])

    def test_gw_ips_must_cover_the_cross_cluster_peers(self):
        with open(f"{self.root}/short.yaml", "w") as f:
            yaml.safe_dump({"cluster1": {1: "10.0.1.1"}, "cluster2": {}}, f)
        with self.assertRaises(SystemExit):
            build(self.root, "bi", gw_ips=f"{self.root}/short.yaml")
        with self.assertRaises(SystemExit):
            build(self.root, "bank-c", gw_ips=f"{self.root}/short.yaml")

    def test_network_policy_8443_open_like_zeto(self):
        for p, n in PARTIES.items():
            np = by(build(self.root, p), "NetworkPolicy", f"fx-gw-{n}")
            self.assertEqual(np["spec"]["policyTypes"], ["Ingress"])
            self.assertEqual(np["spec"]["podSelector"], {"matchLabels": {"app.kubernetes.io/name": f"fx-gw-{n}"}})
            self.assertEqual(np["spec"]["ingress"], [{"ports": [{"protocol": "TCP", "port": 8443}]}])   # no from-list: mTLS + OPA are the control (zeto bank-gw-ingress)

    def test_lensa_nodeport_on_cluster1_only(self):
        for p, n in PARTIES.items():
            ext = [d for d in build(self.root, p) if d["metadata"]["name"] == f"fx-gw-{n}-ext"]
            if p == "bank-c":
                self.assertEqual(ext, [])
                continue
            self.assertEqual(len(ext), 1)
            sp = ext[0]["spec"]
            self.assertEqual((sp["type"], sp["externalTrafficPolicy"]), ("NodePort", "Cluster"))
            self.assertEqual(sp["selector"], {"app.kubernetes.io/name": f"fx-gw-{n}"})
            self.assertEqual([(x["port"], x["targetPort"]) for x in sp["ports"]], [(8443, 8443)])
            self.assertNotIn("nodePort", sp["ports"][0])

    def test_lb_only_with_existing_acl(self):
        docs = build(self.root, "bank-c", lb={"acl_id": "acl-abc123", "ranges": ["47.237.84.150/32"]})
        lb = by(docs, "Service", "fx-gw-4-lb")
        a = lb["metadata"]["annotations"]
        self.assertEqual(a["service.beta.kubernetes.io/alibaba-cloud-loadbalancer-acl-id"], "acl-abc123")
        self.assertEqual(a["service.beta.kubernetes.io/alibaba-cloud-loadbalancer-acl-status"], "on")
        self.assertEqual(a["service.beta.kubernetes.io/backend-type"], "eni")
        self.assertEqual(lb["spec"]["type"], "LoadBalancer")
        self.assertEqual(lb["spec"]["externalTrafficPolicy"], "Cluster")
        self.assertEqual(lb["spec"]["loadBalancerSourceRanges"], ["47.237.84.150/32"])
        self.assertEqual(lb["spec"]["ports"][0]["port"], 8443)
        for bad in ({"acl_id": "x", "ranges": ["1.1.1.1/32"]}, {"acl_id": "acl-abc", "ranges": ["1.1.1.0/24"]}, {"acl_id": "acl-abc", "ranges": []}):
            with self.assertRaises(SystemExit):
                build(self.root, "bank-c", lb=bad)

    def test_party_must_be_known(self):
        with self.assertRaises(SystemExit):
            build(self.root, "bank-d")

    def test_cli_prints_yaml_and_applies_nothing(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "render.py"), "bi", "--templates", f"{self.root}/live", "--image", IMG, "--envoy-image", ENVOY, "--opa-image", OPA,
                            "--opa-config", f"{self.root}/opa-config.yaml", "--gw-cert", f"{self.root}/gw.pem", "--gw-ips", f"{self.root}/gw-ips.yaml", "--tls-exchange", f"{self.root}/tlsx"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sum(1 for d in yaml.safe_load_all(r.stdout) if d and d["kind"] == "Deployment"), 1)


if __name__ == "__main__":
    unittest.main()
