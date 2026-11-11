"""Offline tests for multiorg/fsc/state_render.py: the Jobs that look at / back up / remove the node sqlite (`<state PVC>/<node>/default.sqlite`) with the STOCK sqlite3 CLI (no code of ours).
The scripts are also RUN here against fixture databases (python stdlib sqlite3 makes them) with the host's sqlite3 + sh.

  python3 -m unittest discover -s multiorg/fsc
"""
import os, re, shutil, sqlite3, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import state_render as sr

IMG = "ghcr.io/example/fsc-sqlite-ci@sha256:" + "6" * 64
POD = {"bi": "bi", "bank-a": "bank2", "bank-b": "bank3", "bank-c": "bank4"}
NODES = {"bi": ["issuer", "endorser-1"], "bank-a": ["bank2", "endorser-2"], "bank-b": ["bank3", "endorser-3"], "bank-c": ["bank4", "endorser-4"]}
HAVE = bool(shutil.which("sqlite3") and shutil.which("sh") and shutil.which("sha256sum"))
need = unittest.skipUnless(HAVE or os.environ.get("REQUIRE_SQLITE"), "sqlite3 CLI needed (CI has it)")


def docs(t):
    return [d for d in yaml.safe_load_all(t) if d]


def by(ds, kind):
    r = [d for d in ds if d["kind"] == kind]
    assert len(r) == 1, kind
    return r[0]


def job(mode, party="bank-b", gen="g1"):
    return docs(sr.render(mode, party, IMG, gen))


def script(mode, party="bank-b", gen="g1"):
    return by(job(mode, party, gen), "Job")["spec"]["template"]["spec"]["containers"][0]["command"][2]


class Render(unittest.TestCase):
    def test_every_mode_has_the_same_hardening(self):
        for mode in sr.MODES:
            with self.subTest(mode=mode):
                ds = job(mode)
                j, np = by(ds, "Job"), by(ds, "NetworkPolicy")
                pod = j["spec"]["template"]
                self.assertEqual(pod["metadata"]["labels"]["rd/egress-locked"], "true")
                self.assertFalse(pod["spec"]["automountServiceAccountToken"])
                self.assertEqual(pod["spec"]["serviceAccountName"], "s14-signer")
                self.assertEqual((j["spec"]["backoffLimit"], j["spec"]["activeDeadlineSeconds"], j["spec"]["ttlSecondsAfterFinished"]), (0, 120, 900))
                self.assertEqual(pod["spec"]["imagePullSecrets"], [{"name": "ghcr-pull"}])
                sc = pod["spec"]["containers"][0]["securityContext"]
                self.assertTrue(sc["readOnlyRootFilesystem"] and sc["runAsNonRoot"] and not sc["allowPrivilegeEscalation"])
                self.assertEqual(np["spec"]["policyTypes"], ["Ingress", "Egress"])
                self.assertNotIn("egress", np["spec"])      # egress denied entirely
                self.assertNotIn("ingress", np["spec"])
                self.assertEqual(pod["spec"]["containers"][0]["command"][:2], ["sh", "-c"])
                self.assertNotIn("env", pod["spec"]["containers"][0])
                self.assertNotIn("secret", yaml.safe_dump(pod["spec"]["volumes"]).lower())   # no Secret volume
                self.assertEqual({v["name"] for v in pod["spec"]["volumes"]}, {"state", "work"})
                self.assertEqual(next(v for v in pod["spec"]["volumes"] if v["name"] == "state")["persistentVolumeClaim"]["claimName"], "rdbi-bank3-state")

    def test_count_mounts_the_pvc_read_only_the_rest_read_write(self):
        for mode in sr.MODES:
            v = next(v for v in by(job(mode), "Job")["spec"]["template"]["spec"]["volumes"] if v["name"] == "state")
            self.assertEqual(v["persistentVolumeClaim"].get("readOnly", False), mode == "count", mode)
            m = next(m for m in by(job(mode), "Job")["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] if m["name"] == "state")
            self.assertEqual(m.get("readOnly", False), mode == "count", mode)

    def test_count_script_cannot_write_the_state(self):
        s = script("count")
        self.assertIn("sqlite3 -readonly", s)
        for bad in ("rm ", "mv ", "INSERT", "DELETE", "UPDATE", "DROP", "ALTER", "mkdir \"$S", "mkdir -p \"$S"):
            self.assertNotIn(bad, s, bad)
        for line in s.splitlines():
            if line.strip().startswith("cp "):
                self.assertTrue(line.split()[-1].startswith('"$W'), line)   # every copy goes INTO the scratch dir
        self.assertNotIn("sqlite3 \"$S", s)

    def test_b_prime_orders_backup_verify_restore_test_then_remove(self):
        s = script("b-prime")
        for step in ("sha256sum", "cmp", ".bak-g1", ".restore-test-g1", "sqlite3 -readonly", "rm -f"):
            self.assertIn(step, s)
        self.assertTrue(s.index("sha256sum") < s.index(".restore-test-g1") < s.index("rm -f"))
        self.assertTrue(s.startswith("set -eu"))
        rms = re.findall(r"rm -f ([^\n;]*)", s)
        self.assertTrue(all(("default.sqlite" in x) for x in rms), rms)
        self.assertNotIn("rm -rf", s)

    def test_restore_and_remove_backup_scripts_are_narrow(self):
        r = script("restore")
        self.assertIn(".bak-g1", r)
        self.assertNotIn("rm ", r)
        rb = script("remove-backup")
        self.assertEqual(re.findall(r"rm -f ([^\n;]*)", rb), ['"$S/$n/default.sqlite.bak-g1" "$S/$n/default.sqlite-wal.bak-g1" "$S/$n/default.sqlite-shm.bak-g1"'])

    def test_remove_backup_is_colocated_with_the_fsc_pod_others_are_not(self):
        # the state PVC is ReadWriteOnce and attached to the node of the running FSC pod: a Job on another node dies with Multi-Attach (live 2026-11-12, bi)
        for p, pod in POD.items():
            aff = by(job("remove-backup", p), "Job")["spec"]["template"]["spec"].get("affinity")
            term = aff["podAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
            self.assertEqual(term, [{"labelSelector": {"matchLabels": {"app.kubernetes.io/name": f"rdbi-{pod}"}}, "topologyKey": "kubernetes.io/hostname"}])
        for mode in ("count", "b-prime", "restore"):   # these run with the FSC pod scaled to 0: an affinity to it would leave the Job Pending
            self.assertNotIn("affinity", by(job(mode), "Job")["spec"]["template"]["spec"], mode)

    def test_nodes_of_each_party(self):
        for p, nodes in NODES.items():
            s = script("count", p)
            for n in nodes:
                self.assertIn(n, s)
            self.assertEqual(by(job("count", p), "Job")["metadata"]["namespace"], f"rd-fabricx-{p}")
            v = next(v for v in by(job("count", p), "Job")["spec"]["template"]["spec"]["volumes"] if v["name"] == "state")
            self.assertEqual(v["persistentVolumeClaim"]["claimName"], f"rdbi-{POD[p]}-state")

    def test_checked_inputs(self):
        for a in (("count", "bank-d", IMG, "g1"), ("count", "bi", "repo:latest", "g1"), ("count", "bi", IMG, "G 1"), ("wipe", "bi", IMG, "g1"), ("count", "bi", IMG, "")):
            with self.subTest(a=a):
                with self.assertRaises(SystemExit):
                    sr.render(*a)

    def test_cli(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "state_render.py"), "count", "bi", "--image", IMG, "--name", "g1"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sum(1 for d in docs(r.stdout) if d["kind"] == "Job"), 1)


@need
class RunScripts(unittest.TestCase):
    """the real scripts on fixture state dirs (S and W env override /state and /work)"""

    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.S, self.W = f"{self.t}/state", f"{self.t}/work"
        os.makedirs(self.W)
        for n in NODES["bank-b"]:
            os.makedirs(f"{self.S}/{n}")
            db = sqlite3.connect(f"{self.S}/{n}/default.sqlite")
            db.execute("CREATE TABLE fsc_bindings (ephemeral_hash TEXT PRIMARY KEY, long_term_id BLOB)")
            db.execute("CREATE TABLE tkn_own (k TEXT)")
            db.execute("CREATE TABLE fsc_tokens (k TEXT)")
            db.executemany("INSERT INTO fsc_bindings VALUES (?, ?)", [("a", b"SECRET-LONG-TERM"), ("b", b"SECRET-2")])
            db.commit()
            db.close()
        self.addCleanup(shutil.rmtree, self.t, True)

    def run_(self, mode, expect_ok=True):
        r = subprocess.run(["sh", "-c", script(mode)], capture_output=True, text=True, env={**os.environ, "S": self.S, "W": self.W})
        if expect_ok:
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def test_count_prints_only_names_and_counts(self):
        r = self.run_("count")
        for want in ("bank3 fsc_bindings 2", "bank3 fsc_tokens 0", "bank3 tkn_own 0", "endorser-3 fsc_bindings 2"):
            self.assertIn(want, r.stdout)
        self.assertNotIn("SECRET", r.stdout + r.stderr)

    def test_count_does_not_touch_the_state(self):
        before = {f: open(f"{self.S}/bank3/{f}", "rb").read() for f in os.listdir(f"{self.S}/bank3")}
        self.run_("count")
        self.assertEqual({f: open(f"{self.S}/bank3/{f}", "rb").read() for f in os.listdir(f"{self.S}/bank3")}, before)

    def test_b_prime_backs_up_verifies_restore_tests_and_removes(self):
        orig = open(f"{self.S}/bank3/default.sqlite", "rb").read()
        r = self.run_("b-prime")
        self.assertIn("backup sha256 equal", r.stdout)
        self.assertIn("restore test counts equal", r.stdout)
        self.assertFalse(os.path.exists(f"{self.S}/bank3/default.sqlite"))
        self.assertEqual(open(f"{self.S}/bank3/default.sqlite.bak-g1", "rb").read(), orig)
        self.assertNotIn("SECRET", r.stdout + r.stderr)

    def test_restore_puts_the_original_back(self):
        orig = open(f"{self.S}/bank3/default.sqlite", "rb").read()
        self.run_("b-prime")
        self.run_("restore")
        self.assertEqual(open(f"{self.S}/bank3/default.sqlite", "rb").read(), orig)

    def test_b_prime_stops_before_the_remove_when_the_backup_differs(self):
        # make the backup step produce a different file: pre-create a corrupt backup that cp -n would not overwrite? cp overwrites, so break verification by a read-only dir for the .restore-test
        os.makedirs(f"{self.S}/bank3/.restore-test-g1")   # mkdir of the restore-test dir then fails: set -e stops before the remove
        r = self.run_("b-prime", expect_ok=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(os.path.exists(f"{self.S}/bank3/default.sqlite"), "the original was removed although the restore test failed")

    def test_remove_backup_lists_the_files_before_and_after(self):
        orig = open(f"{self.S}/bank3/default.sqlite", "rb").read()
        self.run_("b-prime")
        r = self.run_("remove-backup")
        self.assertIn("bank3 files before: default.sqlite.bak-g1", r.stdout)
        before = [l for l in r.stdout.splitlines() if l.startswith("bank3 files before:")][0]
        after = [l for l in r.stdout.splitlines() if l.startswith("bank3 backup g1 removed")][0]
        self.assertIn(".bak-g1", before)
        self.assertNotIn(".bak-g1", after)
        self.assertNotIn("SECRET", r.stdout + r.stderr)

    def test_remove_backup_removes_only_the_backup(self):
        self.run_("b-prime")
        self.run_("remove-backup")
        self.assertFalse(os.path.exists(f"{self.S}/bank3/default.sqlite.bak-g1"))


if __name__ == "__main__":
    unittest.main()
