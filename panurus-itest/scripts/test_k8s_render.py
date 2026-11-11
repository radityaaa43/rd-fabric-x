"""Offline test for `k8s.py render` (fabricx PLAN S2): a fake $RDBI_HOME, no cluster, no kubectl.

  python3 -m unittest discover -s panurus-itest/scripts        (needs PyYAML)
"""
import base64, os, re, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
K8S = os.path.join(HERE, "k8s.py")
DIGEST = "ghcr.io/radityaaa43/rdbi-node@sha256:" + "a" * 64
MARKER = "SECRET-MARKER-DO-NOT-PRINT"
NODES = {"issuer": 1, "bank2": 2, "bank3": 3, "bank4": 4, "endorser-1": 1, "endorser-2": 2, "endorser-3": 3, "endorser-4": 4}
AVOID = {"member-16033-node", "member-16034-node"}


def make_home(h):
    def w(rel, data):
        p = os.path.join(h, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb" if isinstance(data, bytes) else "w") as f:
            f.write(data)
    for i, n in enumerate(NODES):
        base = 5100 + 10 * i
        w(f"live/{n}/core.yaml", yaml.safe_dump({
            "fsc": {"grpc": {"address": f"127.0.0.1:{base + 3}"}, "p2p": {"listenAddress": f"/ip4/0.0.0.0/tcp/{base + 4}"},
                    "web": {"address": f"0.0.0.0:{base + 5}"},
                    "endpoint": {"resolvers": [{"name": m, "addresses": {"P2P": f"127.0.0.1:{5100 + 10 * j + 1}"}} for j, m in enumerate(NODES)]}},
            "fabric": {"default": {"peers": [{"address": "127.0.0.1:25130"}],
                                   "notificationService": {"endpoints": [{"address": "127.0.0.1:25130"}]},
                                   "queryService": {"endpoints": [{"address": "127.0.0.1:25140"}]}}},
            "token": {"key": f"{h}/live/{n}/wallet.pem"}}))
        w(f"live/{n}/role", "bank")
        w(f"live/{n}/wallet.pem", MARKER)
    for b, org in (("bank2", 2), ("bank3", 3), ("bank4", 4)):
        w(f"ids/committer-{b}/tls/signcerts/cert.pem", "CERT")
        w(f"ids/committer-{b}/tls/keystore/key_sk", MARKER)
        w(f"ids/committer-{b}/msp/cacerts/ca.pem", "CA")
        w(f"fca-orderer-org{org}-ca.pem", "CA")
    w("multiorg/genesis-multiorg.block", b"\x00")


def run_render(h, *args, image=DIGEST):
    env = {"PATH": os.environ["PATH"], "RDBI_HOME": h, "IMAGE": image}
    return subprocess.run([sys.executable, "-I", K8S, "render", *args], capture_output=True, text=True, env=env)


class Render(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        make_home(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def docs(self, org):
        r = run_render(self.tmp.name, "--org", org, "--ns", f"rd-fabricx-{org}")
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout, list(yaml.safe_load_all(r.stdout))

    def pods(self, docs):
        return [d["spec"]["template"]["spec"] for d in docs if d["kind"] == "Deployment"]

    def test_bank_a_render(self):
        out, docs = self.docs("bank-a")
        self.assertEqual(len(re.findall(r"namespace: fabricx$", out, re.M)), 0)
        self.assertEqual({d["metadata"]["namespace"] for d in docs}, {"rd-fabricx-bank-a"})
        self.assertEqual({d["metadata"]["name"] for d in docs if d["kind"] == "Deployment"}, {"rdbi-bank2"})
        self.assertNotIn("rdbi-driver", out)
        self.assertNotIn("fabricx.svc", out)

    def test_every_container_has_requests_and_digest(self):
        for org in ("bi", "bank-a", "bank-b"):
            out, docs = self.docs(org)
            for pod in self.pods(docs):
                for c in pod["initContainers"] + pod["containers"]:
                    with self.subTest(org=org, container=c["name"]):
                        self.assertIn("requests", c["resources"])
                        self.assertRegex(c["image"], r"@sha256:[0-9a-f]{64}$")
            self.assertEqual(len(re.findall(r"image:.*@sha256:[0-9a-f]{64}$", out, re.M)), sum(
                len(p["initContainers"]) + len(p["containers"]) for p in self.pods(docs)))

    def test_no_workload_starts(self):
        for d in self.docs("bank-b")[1]:
            if d["kind"] == "Deployment":
                self.assertEqual(d["spec"]["replicas"], 0)

    def test_affinity(self):
        for org in ("bi", "bank-a", "bank-b"):
            out, docs = self.docs(org)
            for pod in self.pods(docs):
                terms = pod["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"]
                bad = {v for t in terms for e in t["matchExpressions"] if e["operator"] == "NotIn" for v in e["values"]}
                self.assertEqual(bad, AVOID)
                anti = pod["affinity"]["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"][0]["podAffinityTerm"]
                self.assertEqual(anti["topologyKey"], "kubernetes.io/hostname")
                self.assertIn(org, str(anti["labelSelector"]))  # excludes its own party, repels the others
                self.assertEqual(pod["nodeSelector"]["topology.kubernetes.io/zone"], "ap-southeast-5b")

    def test_secret_data_redacted(self):
        out, docs = self.docs("bank-a")
        self.assertNotIn(MARKER, out)
        for d in docs:
            if d["kind"] == "Secret":
                self.assertEqual({base64.b64decode(v) for v in d["data"].values()}, {b"redacted"})

    def test_bi_has_no_committer(self):
        _, docs = self.docs("bi")
        names = {c["name"] for p in self.pods(docs) for c in p["containers"]}
        self.assertEqual(names, {"issuer", "endorser-1"})

    def test_refusals(self):
        h = self.tmp.name
        for args in (("--org", "bank-c", "--ns", "rd-fabricx-bank-c"),      # cluster 2: S18
                     ("--org", "bank-d", "--ns", "rd-fabricx-bank-d"),
                     ("--org", "bank-a", "--ns", "fabricx"),                 # the old namespace
                     ("--org", "bank-a", "--ns", "rd-fabricx-bank-b"),
                     ("--org", "bank-a"), ()):
            with self.subTest(args=args):
                r = run_render(h, *args)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(r.stdout, "")
        r = run_render(h, "--org", "bank-a", "--ns", "rd-fabricx-bank-a", image="ghcr.io/radityaaa43/rdbi-node:71e3b678")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("digest", r.stderr)


if __name__ == "__main__":
    unittest.main()
