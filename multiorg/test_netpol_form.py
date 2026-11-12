"""Egress form audit (orchestrator decision 2026-11-12, all tracks): every egress rule of the S14/S13 Job and probe renders, the FSC pod render (rdbi-traffic, 4 parties, R17)
and the gateway render (fx-gw-<N>, 4 parties, --restrict-egress, R17) is one of
  - same-namespace pod: podSelector with matchLabels only (never {});
  - another namespace's pod: namespaceSelector (exact kubernetes.io/metadata.name) AND podSelector (matchLabels) in ONE rule;
  - ipBlock only as a single /32 host (the other cluster's LB IP, the API-server endpoints);
  - DNS: kube-system by exact name AND the CoreDNS pod selector (k8s-app=kube-dns), port 53.
No wildcard namespaceSelector, no empty podSelector, no CIDR wider than /32. (Reason: ipBlock does not match in-cluster pod endpoints on this CNI, probes 2026-11-11.)

  python3 -m unittest discover -s multiorg
"""
import importlib.util, os, subprocess, sys, tempfile, unittest
import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
IMG = "ghcr.io/example/x@sha256:" + "5" * 64


def run(*a):
    r = subprocess.run([sys.executable, "-I", *a], capture_output=True, text=True)
    assert r.returncode == 0, (a, r.stderr)
    return [d for d in yaml.safe_load_all(r.stdout) if d]


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def pod_renders():
    """The R17 key-holder pods: NetworkPolicy of the FSC render and of the gateway render for all four parties (inputs = the fixtures of their own test files)."""
    out = []
    ft = load("fsc/test_render.py", "fsc_test_render")
    for p in ft.PARTIES:
        t = ft.Base("setUp")
        t.setUp()
        try:
            out += [d for d in t.r(p) if d["kind"] == "NetworkPolicy"]
        finally:
            t.tmp.cleanup()
    gt = load("gw/test_render.py", "gw_test_render")
    with tempfile.TemporaryDirectory() as root:
        gt.make_inputs(root)
        for p in gt.PARTIES:
            out += [d for d in gt.build(root, p, restrict_egress=True) if d["kind"] == "NetworkPolicy"]
    return out


def renders():
    d = tempfile.mkdtemp()
    for f, t in (("tx", "{}"), ("ca", "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n")):
        open(f"{d}/{f}", "w").write(t)
    cer = os.path.join(ROOT, "ceremony", "render.py")
    fsc = os.path.join(ROOT, "fsc", "reenroll_render.py")
    out = []
    out += run(cer, "job", "bank-b", "--tx", f"{d}/tx", "--cacert", f"{d}/ca", "--image", IMG, "--tx-name", "t1")
    out += run(cer, "submit", "bi", "--tx", f"{d}/tx", "--cacert", f"{d}/ca", "--mspca", f"{d}/ca", "--image", IMG, "--tx-name", "t1")
    out += run(cer, "readback", "bi", "--cacert", f"{d}/ca", "--mspca", f"{d}/ca", "--image", IMG, "--tx-name", "t1")
    out += run(cer, "setuppp", "bi", "--image", IMG, "--name", "p1")
    out += run(cer, "probe", "bi", "--image", IMG, "--name", "x1", "--try", "a=1.1.1.1:443", "--allow", "pod=orderer-router-1:8013", "--allow", "dns", "--allow", "ip=1.1.1.1/32:443",
               "--allow", "nspod=rd-fabricx-bank-a/rdbi-bank2:5104")
    for mode in ("run", "dry-run", "remove-prev", "restore-prev", "restore-prev-dry-run"):
        out += run(fsc, "job", "bank-c", "bank4", "--image", IMG, "--name", "g1", "--api-ips", "172.28.18.47,172.28.47.223", "--mode", mode)
    return [d for d in out if d["kind"] == "NetworkPolicy"]


def selector_ok(sel):
    return isinstance(sel, dict) and bool(sel.get("matchLabels")) and not sel.get("matchExpressions")


def rule_problems(to):
    ns, pod, ip = to.get("namespaceSelector"), to.get("podSelector"), to.get("ipBlock")
    if ip is not None:
        if ns is not None or pod is not None or "except" in ip or not ip.get("cidr", "").endswith("/32"):
            return "ipBlock must stand alone and be one /32 host"
        return None
    if ns is not None:
        ml = ns.get("matchLabels", {})
        if list(ml) != ["kubernetes.io/metadata.name"] or not ml["kubernetes.io/metadata.name"] or ns.get("matchExpressions"):
            return "namespaceSelector must be exactly kubernetes.io/metadata.name=<one name>"
        if not selector_ok(pod):
            return "a namespaceSelector rule needs a non-empty podSelector.matchLabels"
        return None
    if not selector_ok(pod):
        return "same-namespace rule needs a non-empty podSelector.matchLabels"
    return None


class Form(unittest.TestCase):
    def test_every_egress_rule_of_the_job_and_probe_renders_has_the_decided_form(self):
        nps = renders()
        self.assertGreaterEqual(len(nps), 10)
        self.audit(nps, 6)

    def test_the_fsc_pod_and_gateway_renders_of_all_four_parties_have_the_decided_form(self):
        nps = pod_renders()
        self.assertEqual(sorted(n["metadata"]["name"] for n in nps), sorted(["rdbi-traffic"] * 4 + [f"fx-gw-{n}" for n in (1, 2, 3, 4)]))
        for np in nps:
            self.assertIn("Egress", np["spec"]["policyTypes"], np["metadata"]["name"])
        self.audit(nps, 8)

    def audit(self, nps, min_dns):
        seen_dns = 0
        for np in nps:
            for rule in np["spec"].get("egress", []):
                self.assertTrue(rule.get("to"), (np["metadata"]["name"], rule))
                self.assertTrue(rule.get("ports"), (np["metadata"]["name"], "a rule without ports opens every port"))
                for to in rule["to"]:
                    self.assertIsNone(rule_problems(to), (np["metadata"]["name"], to))
                    if to.get("namespaceSelector", {}).get("matchLabels", {}).get("kubernetes.io/metadata.name") == "kube-system":
                        seen_dns += 1
                        self.assertEqual(to["podSelector"], {"matchLabels": {"k8s-app": "kube-dns"}})
                        self.assertEqual(sorted(p["port"] for p in rule["ports"]), [53, 53])
        self.assertGreaterEqual(seen_dns, min_dns)

    def test_the_checker_catches_the_old_forms(self):
        for bad in ({"podSelector": {}}, {"namespaceSelector": {}}, {"namespaceSelector": {"matchLabels": {"part-of": "rd-fabricx"}}, "podSelector": {"matchLabels": {"a": "b"}}},
                    {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "x"}}}, {"ipBlock": {"cidr": "10.0.0.0/24"}}, {"ipBlock": {"cidr": "0.0.0.0/0"}},
                    {"ipBlock": {"cidr": "1.1.1.1/32"}, "podSelector": {"matchLabels": {"a": "b"}}}):
            self.assertIsNotNone(rule_problems(bad), bad)
        for good in ({"podSelector": {"matchLabels": {"a": "b"}}}, {"ipBlock": {"cidr": "1.1.1.1/32"}},
                     {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "x"}}, "podSelector": {"matchLabels": {"a": "b"}}}):
            self.assertIsNone(rule_problems(good), good)


if __name__ == "__main__":
    unittest.main()
