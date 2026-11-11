"""Offline tests for multiorg/fca (fabricx S9): CA manifests and the enroll layout. No cluster, no fabric-ca-client.

  python3 -m unittest discover -s multiorg/fca        (needs PyYAML)
"""
import os, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import enroll, render
import check_exchange

PARTIES = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
DIGEST = "ghcr.io/hyperledger/fabric-ca@sha256:87c36f0b655838e2c3b00379cafc6efb36dc6f8d88b2cec9c707fd47e93b1c63"


def docs(party):
    return list(yaml.safe_load_all(render.render(party, zone="test-zone" if party == "bank-c" else None)))


class Manifests(unittest.TestCase):
    def test_objects_and_names(self):
        for p, n in PARTIES.items():
            with self.subTest(party=p):
                d = {(x["kind"], x["metadata"]["name"]): x for x in docs(p)}
                self.assertEqual(set(d), {("Service", f"fca-org{n}"), ("PersistentVolumeClaim", f"fca-org{n}-data"),
                                          ("Deployment", f"fca-org{n}")})
                self.assertEqual({x["metadata"]["namespace"] for x in d.values()}, {f"rd-fabricx-{p}"})

    def test_restricted_and_pinned(self):
        for p in PARTIES:
            dep = next(x for x in docs(p) if x["kind"] == "Deployment")
            spec = dep["spec"]["template"]["spec"]
            self.assertIs(spec["securityContext"]["runAsNonRoot"], True)
            self.assertEqual(spec["securityContext"]["seccompProfile"], {"type": "RuntimeDefault"})
            self.assertIn("fsGroup", spec["securityContext"])
            for c in spec["containers"]:
                self.assertEqual(c["image"], DIGEST)
                self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False)
                self.assertEqual(c["securityContext"]["capabilities"]["drop"], ["ALL"])
                self.assertIn("cpu", c["resources"]["limits"])
                self.assertIn("ephemeral-storage", c["resources"]["limits"])
                self.assertIn("requests", c["resources"])
            self.assertEqual(dep["spec"]["strategy"], {"type": "Recreate"})   # one PVC, ReadWriteOnce

    def test_zone_pinned(self):
        # WaitForFirstConsumer binds the disk to the zone of its first pod; the nodes with free disk slots are in 5b (k8s.py ZONE)
        sel = lambda p, **kw: next(x for x in list(yaml.safe_load_all(render.render(p, **kw))) if x["kind"] == "Deployment")["spec"]["template"]["spec"].get("nodeSelector")
        for p in ("bi", "bank-a", "bank-b"):
            self.assertEqual(sel(p), {"topology.kubernetes.io/zone": "ap-southeast-5b"})        # default
            self.assertEqual(sel(p, zone="ap-southeast-5a"), {"topology.kubernetes.io/zone": "ap-southeast-5a"})
        self.assertEqual(sel("bank-c", zone="ap-southeast-1b"), {"topology.kubernetes.io/zone": "ap-southeast-1b"})
        with self.assertRaises(SystemExit):
            render.render("bank-c")                      # cluster 2: the zone comes from the PRE, never guessed
        r = subprocess.run([sys.executable, os.path.join(HERE, "render.py"), "bank-c", "--zone", "ap-southeast-1b"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ap-southeast-1b", r.stdout)
        for bad in ("", "a b", "x:y"):
            with self.assertRaises(SystemExit):
                render.render("bank-a", zone=bad)

    def test_no_secret_material_in_manifest(self):
        out = render.render("bank-a")
        self.assertNotIn("Secret", [x["kind"] for x in docs("bank-a")])
        self.assertNotIn("PRIVATE KEY", out)
        # the admin password is a Secret created at enroll time, referenced by name only
        env = next(x for x in docs("bank-a") if x["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["env"]
        self.assertTrue(any("valueFrom" in e and e["valueFrom"]["secretKeyRef"]["name"] == "fca-org2-admin" for e in env))

    def test_cluster2_label_and_refusals(self):
        self.assertEqual(next(x for x in yaml.safe_load_all(render.render("bank-c", zone="z")) if x["kind"] == "Deployment")["metadata"]["namespace"], "rd-fabricx-bank-c")
        for bad in ("bank-d", "fabricx", ""):
            with self.assertRaises(SystemExit):
                render.render(bad)


class Enroll(unittest.TestCase):
    def fake_enrolled(self, root, n=2):
        """what fabric-ca-client leaves per role after `enroll` (msp profile) and `enroll --enrollment.profile tls`"""
        for role in enroll.ROLES:
            for sub, files in (("msp", ["signcerts/cert.pem", "cacerts/ca.pem", "keystore/abc_sk"]),
                               ("tls", ["signcerts/cert.pem", "tlscacerts/tlsca.pem", "keystore/def_sk"])):
                for f in files:
                    p = os.path.join(root, role, sub, f)
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    with open(p, "w") as fh:
                        fh.write("-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n" if f.endswith("_sk") else
                                 "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n")

    def test_layout_passes_checker_and_secrets_hold_the_keys(self):
        with tempfile.TemporaryDirectory() as t:
            self.fake_enrolled(os.path.join(t, "enrolled"))
            ex = os.path.join(t, "exchange", "org2")
            secrets = enroll.build(os.path.join(t, "enrolled"), ex, 2, "rd-fabricx-bank-a", {r: f"{r}-2.rd-fabricx-bank-a.svc.cluster.local" for r in enroll.ROLES})
            self.assertEqual(check_exchange.problems(ex, 2), [])
            self.assertEqual({s["metadata"]["name"] for s in secrets},
                             {f"orderer-{r}-2-secret" for r in ("router", "batcher", "consenter", "assembler")})
            for s in secrets:
                self.assertEqual(s["metadata"]["namespace"], "rd-fabricx-bank-a")
                self.assertIn("msp-keystore-priv_sk", s["stringData"])      # node reads keystore/priv_sk (config/config.go:308)
                self.assertIn("tls-server.key", s["stringData"])            # config/generate/local_config_gen.go:195
            blob = subprocess.run(["grep", "-r", "PRIVATE KEY", ex], capture_output=True, text=True).stdout
            self.assertEqual(blob, "")

    def test_work_dir_must_be_tmpfs_and_private(self):
        for bad in ("/home/ecs-user/w", "/tmp/w", "/dev/shmx/w", "relative/w", "/dev/shm/../tmp/w"):
            with self.subTest(work=bad):
                with self.assertRaises(SystemExit):
                    enroll.check_work(bad)
        self.assertEqual(enroll.check_work("/dev/shm/s9-bank-a"), "/dev/shm/s9-bank-a")
        old = os.umask(0o022)
        try:
            enroll.check_work("/dev/shm/s9-bank-a")
            cur = os.umask(old)
            self.assertEqual(cur & 0o077, 0o077)      # umask 077 set by the guard
        finally:
            os.umask(old)

    def test_destroy_leaves_nothing(self):
        d = tempfile.mkdtemp(dir="/dev/shm")
        os.makedirs(os.path.join(d, "a", "b"))
        for f in ("x", "a/y", "a/b/z"):
            with open(os.path.join(d, f), "w") as fh:
                fh.write("PRIVATE KEY")
        enroll.destroy(d)
        self.assertFalse(os.path.exists(d))

    def test_wrong_namespace_or_party_refused(self):
        for args in (("bank-a", "rd-fabricx-bi"), ("bank-a", "fabricx"), ("bank-x", "rd-fabricx-bank-x")):
            with self.assertRaises(SystemExit):
                enroll.check_target(*args)
        self.assertEqual(enroll.check_target("bank-c", "rd-fabricx-bank-c"), 4)


FCA_STUB = r"""#!/bin/sh
# stub fabric-ca-client: records argv and the URL env; register prints a generated password like the real client
echo "$@" >> "$STUB_LOG/argv.log"
echo "$FABRIC_CA_CLIENT_URL" >> "$STUB_LOG/url.log"
case "$1" in
  register) echo "Password: ROLESECRET$(echo "$@" | sed 's/.*--id.name \([a-z0-9-]*\).*/\1/')"; exit 0;;
esac
if [ -n "$STUB_FAIL" ] && echo "$@" | grep -q "$STUB_FAIL"; then
  echo "Error: Response from server: bad credentials for $FABRIC_CA_CLIENT_URL" >&2; exit 1
fi
M=""; prev=""; for a in "$@"; do [ "$prev" = "-M" ] && M="$a"; prev="$a"; done
case "$M" in
  */tls) sub=tlscacerts; k=def_sk;; *) sub=cacerts; k=abc_sk;;
esac
mkdir -p "$M/signcerts" "$M/$sub" "$M/keystore"
printf -- '-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n' > "$M/signcerts/cert.pem"
printf -- '-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n' > "$M/$sub/ca.pem"
printf -- '-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n' > "$M/keystore/$k"
"""
KUBECTL_STUB = "#!/bin/sh\necho \"$@\" >> \"$STUB_LOG/kubectl.log\"\ncase \"$*\" in *\" -f -\"*) cat >> \"$STUB_LOG/kubectl-stdin.log\";; esac\nexit 0\n"


class EnrollFlow(unittest.TestCase):
    """enroll.init / enroll.enroll against stub binaries: where do the secrets travel, and what does a failure print"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bin, self.log = os.path.join(self.tmp.name, "bin"), os.path.join(self.tmp.name, "log")
        os.makedirs(self.bin)
        os.makedirs(self.log)
        for name, body in (("fabric-ca-client", FCA_STUB), ("kubectl", KUBECTL_STUB)):
            p = os.path.join(self.bin, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
        self.env = {k: os.environ.get(k) for k in ("PATH", "STUB_LOG", "STUB_FAIL")}
        os.environ["PATH"] = self.bin + ":" + os.environ["PATH"]
        os.environ["STUB_LOG"] = self.log
        os.environ.pop("STUB_FAIL", None)
        self.work = tempfile.mkdtemp(dir="/dev/shm")
        os.rmdir(self.work)
        self.out = os.path.join(self.tmp.name, "exchange", "org2")

    def tearDown(self):
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        if os.path.exists(self.work):
            enroll.destroy(self.work)
        self.tmp.cleanup()

    def logtext(self, name):
        p = os.path.join(self.log, name)
        return open(p).read() if os.path.exists(p) else ""

    def test_secrets_never_in_argv(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        pw = open(os.path.join(self.work, "admin.pass")).read().strip()
        enroll.enroll("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.out)
        argv = self.logtext("argv.log") + self.logtext("kubectl.log")
        self.assertNotIn(pw, argv)
        self.assertNotIn("ROLESECRET", argv)
        self.assertNotIn("--id.secret", argv)
        self.assertNotIn("@localhost", argv)                       # no user:pass@host URL on a command line
        self.assertIn(f"admin:{pw}@localhost", self.logtext("url.log"))   # it travels in the env instead
        self.assertIn("ROLESECRETrouter-2", self.logtext("url.log"))
        self.assertFalse(os.path.exists(self.work))                # destroyed
        self.assertEqual(check_exchange.problems(self.out, 2), [])

    def test_failure_text_has_no_secret(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        pw = open(os.path.join(self.work, "admin.pass")).read().strip()
        os.environ["STUB_FAIL"] = "tls"                            # fails on the first tls enrollment, after register
        with self.assertRaises(SystemExit) as cm:
            enroll.enroll("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.out)
        msg = str(cm.exception.code)
        for secret in (pw, "ROLESECRETrouter-2"):
            self.assertNotIn(secret, msg)
        self.assertIn("fabric-ca-client", msg)
        self.assertIn("***", msg)
        self.assertFalse(os.path.exists(self.work))                # keys destroyed on error too

    def test_scrub_covers_every_secret(self):
        self.assertEqual(enroll.scrub("a S1 b S2 c", ["S1", "S2"]), "a *** b *** c")
        self.assertEqual(enroll.scrub("x", []), "x")


if __name__ == "__main__":
    unittest.main()
