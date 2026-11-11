"""Offline tests for multiorg/fca (fabricx S9): CA manifests and the enroll layout. No cluster, no fabric-ca-client.

  python3 -m unittest discover -s multiorg/fca        (needs PyYAML)
"""
import os, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import b3san_plan, enroll, render
import check_exchange

PARTIES = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
DIGEST = "ghcr.io/hyperledger/fabric-ca@sha256:87c36f0b655838e2c3b00379cafc6efb36dc6f8d88b2cec9c707fd47e93b1c63"


def docs(party):
    return list(yaml.safe_load_all(render.render(party, zone="test-zone" if party == "bank-c" else None, storage_class="test-sc" if party == "bank-c" else None)))


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
        self.assertEqual(sel("bank-c", zone="ap-southeast-1b", storage_class="sc"), {"topology.kubernetes.io/zone": "ap-southeast-1b"})
        with self.assertRaises(SystemExit):
            render.render("bank-c")                      # cluster 2: the zone comes from the PRE, never guessed
        r = subprocess.run([sys.executable, os.path.join(HERE, "render.py"), "bank-c", "--zone", "ap-southeast-1b", "--storage-class", "sc"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ap-southeast-1b", r.stdout)
        for bad in ("", "a b", "x:y"):
            with self.assertRaises(SystemExit):
                render.render("bank-a", zone=bad)

    def test_storage_class(self):
        # cluster 1 has alicloud-essd-wffc; cluster 2 does not (it has alicloud-essd Immediate, fabricx-essd WaitForFirstConsumer Retain)
        sc = lambda p, **kw: next(x for x in yaml.safe_load_all(render.render(p, **kw)) if x["kind"] == "PersistentVolumeClaim")["spec"]["storageClassName"]
        for p in ("bi", "bank-a", "bank-b"):
            self.assertEqual(sc(p), "alicloud-essd-wffc")                                        # default
            self.assertEqual(sc(p, storage_class="other-sc"), "other-sc")
        self.assertEqual(sc("bank-c", zone="ap-southeast-1a", storage_class="fabricx-essd"), "fabricx-essd")
        with self.assertRaises(SystemExit):
            render.render("bank-c", zone="ap-southeast-1a")      # cluster 2: refused without --storage-class, never guessed
        r = subprocess.run([sys.executable, os.path.join(HERE, "render.py"), "bank-c", "--zone", "ap-southeast-1a", "--storage-class", "fabricx-essd"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("storageClassName: fabricx-essd", r.stdout)
        r = subprocess.run([sys.executable, os.path.join(HERE, "render.py"), "bank-c", "--zone", "ap-southeast-1a"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")
        for bad in ("", "a b", "x/y"):
            with self.assertRaises(SystemExit):
                render.render("bank-a", storage_class=bad)

    def test_anti_affinity_against_other_fca_pods(self):
        # qa placement note: fca-org1/2/3 all landed on member-16044-node. Required anti-affinity on the hostname, across namespaces.
        def selects(sel, labels):
            for e in sel["matchExpressions"]:
                v = labels.get(e["key"])
                ok = (v in e["values"]) if e["operator"] == "In" else (v not in e["values"])
                if not ok:
                    return False
            return True
        for p, n in PARTIES.items():
            spec = next(x for x in docs(p) if x["kind"] == "Deployment")["spec"]["template"]["spec"]
            terms = spec["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
            self.assertEqual(len(terms), 1)
            self.assertEqual(terms[0]["topologyKey"], "kubernetes.io/hostname")
            self.assertEqual(terms[0]["namespaceSelector"], {})
            sel = terms[0]["labelSelector"]
            for m in PARTIES.values():
                labels = {"app.kubernetes.io/name": f"fca-org{m}"}
                self.assertEqual(selects(sel, labels), m != n, f"fca-org{n} must repel fca-org{m} only if m != n")
            self.assertFalse(selects(sel, {"app.kubernetes.io/name": "rdbi-bank2"}))     # unrelated pods are not repelled

    def test_no_secret_material_in_manifest(self):
        out = render.render("bank-a")
        self.assertNotIn("Secret", [x["kind"] for x in docs("bank-a")])
        self.assertNotIn("PRIVATE KEY", out)
        # the admin password is a Secret created at enroll time, referenced by name only
        env = next(x for x in docs("bank-a") if x["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["env"]
        self.assertTrue(any("valueFrom" in e and e["valueFrom"]["secretKeyRef"]["name"] == "fca-org2-admin" for e in env))

    def test_cluster2_label_and_refusals(self):
        self.assertEqual(next(x for x in yaml.safe_load_all(render.render("bank-c", zone="z", storage_class="sc")) if x["kind"] == "Deployment")["metadata"]["namespace"], "rd-fabricx-bank-c")
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

    def test_port_plan_is_the_single_source(self):
        # upstream sample (orderer@dd296e3 deployment/vms/sample-config/config.yaml:8-13): assembler 8011, consenter 8012, router 8013, batcher shards 8014+
        self.assertEqual(enroll.PORT_PLAN, {"assembler": 8011, "consenter": 8012, "router": 8013, "batcher1": 8014})
        with tempfile.TemporaryDirectory() as t:
            self.fake_enrolled(os.path.join(t, "enrolled"))
            ex = os.path.join(t, "ex", "org2")
            enroll.build(os.path.join(t, "enrolled"), ex, 2, "rd-fabricx-bank-a", {r: f"{r}-2.rd-fabricx-bank-a.svc.cluster.local" for r in enroll.ROLES})
            ep = yaml.safe_load(open(os.path.join(ex, "endpoints.yaml")))
            self.assertEqual({r: v["Port"] for r, v in ep.items()}, enroll.PORT_PLAN)

    def test_parse_extra_sans(self):
        self.assertEqual(enroll.parse_extra_sans([]), {r: [] for r in enroll.ROLES})
        got = enroll.parse_extra_sans(["lb.example.org", "router=198.51.100.7", "assembler=lb2.example.org"])
        self.assertEqual(got["router"], ["lb.example.org", "198.51.100.7"])           # no prefix = every role of the party
        self.assertEqual(got["assembler"], ["lb.example.org", "lb2.example.org"])
        self.assertEqual(got["consenter"], ["lb.example.org"])
        for bad in ("", "a,b", "no spaces.example", "nosuchrole=lb.example", "-bad.example", "x" * 300, "300.1.1.1.1.1"):
            with self.subTest(san=bad):
                with self.assertRaises(SystemExit):
                    enroll.parse_extra_sans([bad])

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


class B3SanPlan(unittest.TestCase):
    def test_plan_lists_every_org_and_role_without_secrets(self):
        out = b3san_plan.plan("{role}-{n}.lb.{party}")
        self.assertIn("WARNING: placeholder LB hosts", out.splitlines()[0])
        for party, n in PARTIES.items():
            self.assertIn(f"enroll.py enroll {party} rd-fabricx-{party}", out)
            self.assertIn(f"--extra-san router=router-{n}.lb.{party}", out)
            self.assertIn(f"--extra-san batcher1=batcher1-{n}.lb.{party}", out)
            self.assertIn(f"fca-org{n}-admin", out)
        self.assertEqual(out.count("--generation san1"), 4)
        self.assertNotIn("Password", out)
        self.assertNotIn("://admin", out)
        self.assertLess(out.index("rd-fabricx-bi"), out.index("rd-fabricx-bank-a"))          # sequential, bi first

    def test_real_hosts_have_no_warning_and_bad_input_is_refused(self):
        self.assertNotIn("WARNING", b3san_plan.plan("{role}-{n}.fabricx.example.org"))
        for bad in ("fixed.example.org", "{role}-{n} bad.example"):
            with self.assertRaises(SystemExit):
                b3san_plan.plan(bad)
        with self.assertRaises(SystemExit):
            b3san_plan.plan("{role}-{n}.example.org", generation="UP")

    def test_cli(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "b3san_plan.py"), "--lb-host-template", "{role}-{n}.example.org"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(subprocess.run([sys.executable, os.path.join(HERE, "b3san_plan.py")], capture_output=True, text=True).returncode, 1)


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

    def test_extra_sans_reach_csr_hosts_of_the_right_roles(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        enroll.enroll("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.out,
                      extra_sans=["lb.example.org", "router=203.0.113.5"])
        lines = [l for l in self.logtext("argv.log").splitlines() if l.startswith("enroll") and "--csr.hosts" in l]
        self.assertEqual(len(lines), 8)                                                  # 4 roles x (msp, tls)
        router = [l for l in lines if "router-2." in l]
        self.assertTrue(all("router-2.rd-fabricx-bank-a.svc.cluster.local,lb.example.org,203.0.113.5" in l for l in router) and len(router) == 2)
        other = [l for l in lines if "router-2." not in l]
        self.assertTrue(all("lb.example.org" in l and "203.0.113.5" not in l for l in other))
        self.assertIn("--csr.hosts", self.logtext("argv.log"))

    def test_generation_registers_new_identities_and_replaces_secrets(self):
        # B3-SAN: the first-run role secrets were never stored and identities cannot be removed (allowremove false):
        # new identity names carry the generation tag; the SAME Secret names are overwritten with `kubectl replace`.
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        enroll.enroll("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.out,
                      extra_sans=["lb.example.org"], generation="san1", replace_secrets=True)
        argv = self.logtext("argv.log")
        for role in enroll.ROLES:
            self.assertIn(f"--id.name {role}-2-san1", argv)
            self.assertNotIn(f"--id.name {role}-2 ", argv + " ")
        k = self.logtext("kubectl.log")
        self.assertEqual(k.count("replace -f -"), 4)
        self.assertNotIn("create -f -", k.replace("secret generic", ""))
        self.assertIn("orderer-router-2-secret", self.logtext("kubectl-stdin.log"))        # same Secret names as B3
        self.assertNotIn("san1-secret", self.logtext("kubectl-stdin.log"))
        self.assertEqual(check_exchange.problems(self.out, 2), [])

    def test_generation_is_validated(self):
        for bad in ("", "a b", "UP", "x" * 20, "-a"):
            with self.subTest(g=bad):
                with self.assertRaises(SystemExit):
                    enroll.check_generation(bad)
        self.assertEqual(enroll.check_generation("san1"), "san1")

    def test_default_run_is_unchanged(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        enroll.enroll("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.out)
        self.assertEqual(self.logtext("kubectl.log").count("create -f -"), 4)
        self.assertIn("--id.name router-2 ", self.logtext("argv.log") + " ")

    def test_no_extra_sans_keeps_the_cluster_name_only(self):
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        enroll.enroll("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, self.out)
        lines = [l for l in self.logtext("argv.log").splitlines() if "--csr.hosts" in l]
        self.assertTrue(all(l.rstrip().endswith(".svc.cluster.local") for l in lines))

    def make_tree(self, name="src"):
        import test_check_exchange as tce
        root = os.path.join(self.tmp.name, name, "org2")
        tce.good_tree(root, 2)
        return root

    def test_admin_identity_adds_admincerts_and_one_secret(self):
        """PLAN S8: per org one CA identity admin-<N> (type admin): cert into the PUBLIC tree msp/admincerts/, key only as Secret orderer-admin-<N>-secret."""
        src, dst = self.make_tree(), os.path.join(self.tmp.name, "dst", "org2")
        before = open(os.path.join(src, "MANIFEST.sha256")).read()
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        pw = open(os.path.join(self.work, "admin.pass")).read().strip()
        enroll.admin("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, src, dst)
        argv = self.logtext("argv.log")
        self.assertIn("--id.name admin-2 ", argv + " ")
        self.assertIn("--id.type admin", argv)
        self.assertNotIn("--id.secret", argv)
        self.assertNotIn(pw, argv + self.logtext("kubectl.log"))
        self.assertNotIn("ROLESECRET", argv)
        self.assertIn("ROLESECRETadmin-2", self.logtext("url.log"))                    # the generated password travelled in the env only
        out = self.logtext("kubectl-stdin.log")
        self.assertIn("name: orderer-admin-2-secret", out)
        self.assertIn("msp-keystore-priv_sk", out)
        self.assertIn("msp-signcert.pem", out)
        self.assertNotIn("orderer-router", out)                                           # the role Secrets are not touched
        self.assertEqual(self.logtext("kubectl.log").count("create -f -"), 1)
        cert = open(os.path.join(dst, "msp", "admincerts", "admin-2-cert.pem")).read()
        self.assertIn("BEGIN CERTIFICATE", cert)
        self.assertNotIn("PRIVATE KEY", cert)
        self.assertEqual(check_exchange.problems(dst, 2, require_admin=True), [])
        self.assertEqual(open(os.path.join(src, "MANIFEST.sha256")).read(), before)       # the source tree is untouched
        self.assertFalse(os.path.exists(os.path.join(src, "msp", "admincerts")))
        self.assertFalse(os.path.exists(self.work))                                       # destroyed

    def test_admin_refusals(self):
        src, dst = self.make_tree(), os.path.join(self.tmp.name, "dst", "org2")

        def refused(*a, **k):
            enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)     # every call destroys the work dir (finally): start each from a fresh one
            with self.assertRaises(SystemExit):
                enroll.admin(*a, **k)
            self.assertFalse(os.path.exists(self.work))

        os.makedirs(dst)
        refused("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, src, dst)     # destination exists
        os.rmdir(dst)
        refused("bank-a", "rd-fabricx-bi", "/k", "http://localhost:7054", self.work, src, dst)         # wrong namespace
        with open(os.path.join(src, "orderers", "party2", "router", "tls", "server.key"), "w") as f:
            f.write("-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n")
        import test_check_exchange as tce
        tce.manifest(src)
        refused("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, src, dst)     # unclean source tree
        self.assertFalse(os.path.exists(dst))
        self.assertNotIn("create -f -", self.logtext("kubectl.log"))                                    # nothing was created in any refusal

    def test_endorser_identity_goes_to_knowncerts_and_its_own_secret(self):
        """lead Q1: known_certs carries the FSC ENDORSER certs: CA identity endorser-<N> (type client), cert in msp/knowncerts/, key as Secret fsc-endorser-<N>-secret."""
        src, dst = self.make_tree(), os.path.join(self.tmp.name, "dst", "org2")
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        enroll.identity("endorser", "bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, src, dst)
        argv = self.logtext("argv.log")
        self.assertIn("--id.name endorser-2 ", argv + " ")
        self.assertIn("--id.type client", argv)
        self.assertNotIn("--id.type admin", argv)
        out = self.logtext("kubectl-stdin.log")
        self.assertIn("name: fsc-endorser-2-secret", out)
        self.assertNotIn("orderer-admin", out)
        self.assertIn("BEGIN CERTIFICATE", open(os.path.join(dst, "msp", "knowncerts", "endorser-2-cert.pem")).read())
        self.assertFalse(os.path.exists(os.path.join(dst, "msp", "admincerts")))
        self.assertEqual(check_exchange.problems(dst, 2, require_known=True), [])
        self.assertIn("missing msp/knowncerts/*.pem", check_exchange.problems(src, 2, require_known=True))   # the source had none

    def test_both_kinds_chain_on_one_tree_and_unknown_kind_is_refused(self):
        src = self.make_tree()
        mid, dst = os.path.join(self.tmp.name, "mid", "org2"), os.path.join(self.tmp.name, "dst", "org2")
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        enroll.identity("admin", "bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, src, mid)
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        enroll.identity("endorser", "bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, mid, dst)
        self.assertEqual(check_exchange.problems(dst, 2, require_admin=True, require_known=True), [])
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        with self.assertRaises(SystemExit):
            enroll.identity("auditor", "bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, src, os.path.join(self.tmp.name, "x"))
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        with self.assertRaises(SystemExit):                                               # an endorser already in the source: new tree needs a new generation
            enroll.identity("endorser", "bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, dst, os.path.join(self.tmp.name, "y"))

    def test_admin_with_generation_and_existing_admincerts(self):
        src, dst = self.make_tree(), os.path.join(self.tmp.name, "dst", "org2")
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        enroll.admin("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, src, dst, generation="g2")
        self.assertIn("--id.name admin-2-g2 ", self.logtext("argv.log") + " ")
        self.assertIn("name: orderer-admin-2-secret", self.logtext("kubectl-stdin.log"))
        enroll.init("bank-a", "rd-fabricx-bank-a", "/k", self.work)
        with self.assertRaises(SystemExit):                                               # already has admincerts: new generation, new tree
            enroll.admin("bank-a", "rd-fabricx-bank-a", "/k", "http://localhost:7054", self.work, dst, os.path.join(self.tmp.name, "dst2"))

    def test_scrub_covers_every_secret(self):
        self.assertEqual(enroll.scrub("a S1 b S2 c", ["S1", "S2"]), "a *** b *** c")
        self.assertEqual(enroll.scrub("x", []), "x")


if __name__ == "__main__":
    unittest.main()
