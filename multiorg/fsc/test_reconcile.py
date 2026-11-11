"""Offline tests for multiorg/fsc/reconcile.py (fabricx S17: BI's read-only completeness check, per org namespace). Stub kubectl on PATH, no cluster.

  python3 -m unittest discover -s multiorg/fsc
"""
import importlib.util, os, sqlite3, stat, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("fsc_reconcile", os.path.join(HERE, "reconcile.py"))
rec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rec)

TX = ["a" * 64, "b" * 64, "c" * 64]
LEDGER = "".join(f"\\000tr\\000{t}\\000\n" for t in TX) + "\\000other\\000x\n"

STUB = """#!/bin/sh
echo "$@" >> "$STUB_LOG"
case "$*" in
  *psql*) cat "$STUB_LEDGER";;
  *"-wal"*) cat "$STUB_SQLITE-wal" 2>/dev/null || true;;
  *"cat /home/rdbi"*) cat "$STUB_SQLITE";;
esac
"""


def make_store(path, rows, ns="rd_dfabi_v2"):
    db = sqlite3.connect(path)
    table = rec.audit_table(ns)
    db.execute(f'create table "{table}" (tx_id text, status int)')
    db.executemany(f'insert into "{table}" values (?, ?)', rows)
    db.commit()
    db.close()


class Pure(unittest.TestCase):
    def test_ledger_keys_take_only_token_request_keys(self):
        self.assertEqual(rec.ledger_txids(LEDGER), set(TX))

    def test_audit_table_name(self):
        self.assertEqual(rec.audit_table("rd_dfabi_v2"), "fsc_default__arma__rd__dfabi__v2__aud_requests")

    def test_gaps_are_unconfirmed_or_missing(self):
        self.assertEqual(rec.gaps(set(TX), {TX[0]: 2, TX[1]: 1}), sorted([TX[1], TX[2]]))
        self.assertEqual(rec.gaps(set(TX), {t: 2 for t in TX}), [])

    def test_namespace_must_be_a_plain_identifier(self):
        for bad in ("a;drop table x", "x y", "", "A-B", "x'--"):
            with self.assertRaises(SystemExit):
                rec.check_namespace(bad)
        self.assertEqual(rec.check_namespace("rd_dfabi_v2"), "rd_dfabi_v2")


class Flow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        os.makedirs(f"{d}/bin")
        with open(f"{d}/bin/kubectl", "w") as f:
            f.write(STUB)
        os.chmod(f"{d}/bin/kubectl", 0o755)
        with open(f"{d}/ledger.txt", "w") as f:
            f.write(LEDGER)
        self.env = {**os.environ, "PATH": f"{d}/bin:" + os.environ["PATH"], "STUB_LOG": f"{d}/log", "STUB_LEDGER": f"{d}/ledger.txt", "STUB_SQLITE": f"{d}/issuer.sqlite"}

    def tearDown(self):
        self.tmp.cleanup()

    def run_it(self, *extra):
        return subprocess.run([sys.executable, "-I", os.path.join(HERE, "reconcile.py"), "--kubeconfig", "/k", "--ns", "rd-fabricx-bi", *extra], capture_output=True, text=True, env=self.env)

    def test_all_confirmed_exit_0(self):
        make_store(f"{self.tmp.name}/issuer.sqlite", [(t, 2) for t in TX])
        r = self.run_it()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("3 token transactions on the ledger, 3 confirmed", r.stdout)

    def test_gap_exit_1_and_listed(self):
        make_store(f"{self.tmp.name}/issuer.sqlite", [(TX[0], 2), (TX[1], 1)])
        r = self.run_it()
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"UNREPORTED tx {TX[1][:12]} (BI status: 1)", r.stdout)
        self.assertIn(f"UNREPORTED tx {TX[2][:12]} (BI status: no record)", r.stdout)

    def test_only_reads_in_the_own_namespace(self):
        make_store(f"{self.tmp.name}/issuer.sqlite", [(t, 2) for t in TX])
        self.run_it()
        log = open(f"{self.tmp.name}/log").read().splitlines()
        self.assertTrue(log)
        for l in log:
            self.assertIn("--kubeconfig /k -n rd-fabricx-bi exec ", l)                  # one namespace, exec only
            self.assertNotRegex(l, r"\b(apply|create|delete|patch|replace|scale|label|annotate|port-forward)\b")
        sql = [l for l in log if "psql" in l]
        self.assertEqual(len(sql), 1)
        self.assertIn("select encode(key, 'escape') from ns_rd_dfabi_v2", sql[0])
        self.assertNotRegex(sql[0].lower(), r"insert|update|delete|drop|alter")
        self.assertNotIn("-n fabricx ", "\n".join(log))                                  # the old namespace is never named

    def test_password_stays_in_the_pod(self):
        make_store(f"{self.tmp.name}/issuer.sqlite", [(t, 2) for t in TX])
        self.run_it()
        log = open(f"{self.tmp.name}/log").read()
        self.assertIn("$POSTGRES_PASSWORD", log)   # expanded by the shell inside the pod, never by this script

    def test_bad_namespace_refused_before_any_kubectl(self):
        r = self.run_it("--token-ns", "x;y")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(f"{self.tmp.name}/log"))


if __name__ == "__main__":
    unittest.main()
