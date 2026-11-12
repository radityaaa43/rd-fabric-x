"""Offline tests for the `dbread` mode of multiorg/ceremony/render.py: a keyless-to-the-API, egress-locked Job that reads the org's OWN committer DB without exec (analyst/orchestrator: no exec into key holders).
It prints only a status string / integers / column names. No cluster, no secret.

  python3 -m unittest discover -s multiorg/ceremony
"""
import copy, importlib.util, os, re, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("ceremony_render", os.path.join(HERE, "render.py"))
render = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render)

PARTIES = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
TXID = "ab" * 32
PG = "docker.io/library/postgres@sha256:7958605b474b3d264a969cb3a123d6aa00ad1e1fe9da8a69984dabb704d93317"
MODES = {"schema": {}, "status": {"txid": TXID}, "occurrences": {"txid": TXID, "needle": "00000000000003e8"}}
WRITE = re.compile(r"\b(insert|update|delete|drop|create|alter|grant|revoke|truncate|copy|call|vacuum|set|reset|lock|do)\b|;|pg_read_file|lo_import|dblink", re.I)


def docs(party="bi", mode="status", **kw):
    a = dict(MODES[mode]); a.update(kw)
    return list(yaml.safe_load_all(render.render_dbread(party, "t1", mode, **a)))


def split(ds):
    return [d for d in ds if d["kind"] == "NetworkPolicy"][0], [d for d in ds if d["kind"] == "Job"][0]


class Render(unittest.TestCase):
    def test_every_party_and_mode_renders_and_passes_the_audit(self):
        for p in PARTIES:
            for m in MODES:
                with self.subTest(party=p, mode=m):
                    ds = docs(p, m)
                    self.assertEqual([d["kind"] for d in ds], ["NetworkPolicy", "Job"])
                    self.assertEqual(render.audit_dbread(ds, m), [])
                    self.assertEqual({d["metadata"]["namespace"] for d in ds}, {f"rd-fabricx-{p}"})

    def test_job_shape(self):
        np, job = split(docs())
        t = job["spec"]["template"]; c = t["spec"]["containers"][0]
        self.assertEqual(c["image"], PG)
        self.assertEqual(c["command"], ["psql"])   # no shell
        self.assertEqual(t["metadata"]["labels"]["rd/egress-locked"], "true")
        self.assertIs(t["spec"]["automountServiceAccountToken"], False)
        self.assertNotIn("volumes", t["spec"]); self.assertNotIn("volumeMounts", c)
        self.assertEqual((job["spec"]["backoffLimit"], job["spec"]["ttlSecondsAfterFinished"], t["spec"]["restartPolicy"]), (0, 900, "Never"))
        self.assertLessEqual(job["spec"]["activeDeadlineSeconds"], 120)
        env = {e["name"]: e for e in c["env"]}
        self.assertEqual(set(env), {"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGSSLMODE", "PGCONNECT_TIMEOUT", "PGPASSWORD"})
        self.assertEqual(env["PGPASSWORD"]["valueFrom"], {"secretKeyRef": {"name": "committer-db-credentials", "key": "password"}})
        self.assertEqual([n for n, e in env.items() if "valueFrom" in e], ["PGPASSWORD"])
        self.assertEqual((env["PGHOST"]["value"], env["PGPORT"]["value"], env["PGUSER"]["value"], env["PGDATABASE"]["value"]), ("committer-db", "5432", "committer", "committer"))
        sql = c["args"][-1]
        self.assertFalse(WRITE.search(sql), sql)
        self.assertTrue(sql.lstrip().lower().startswith("select "))

    def test_egress_is_dns_and_the_committer_db_only(self):
        np, job = split(docs())
        self.assertEqual(np["spec"]["policyTypes"], ["Ingress", "Egress"]); self.assertNotIn("ingress", np["spec"])
        self.assertEqual(np["spec"]["podSelector"]["matchLabels"], {"app.kubernetes.io/name": "dbread-t1"})
        self.assertEqual(np["spec"]["egress"], [render.egress_rule("dns"), render.egress_rule("pod=committer-db:5432")])

    def test_what_each_mode_can_print(self):
        self.assertIn("information_schema.columns", docs(mode="schema")[1]["spec"]["template"]["spec"]["containers"][0]["args"][-1])
        s = docs(mode="status")[1]["spec"]["template"]["spec"]["containers"][0]["args"][-1].lower()
        self.assertTrue(s.startswith("select status from tx_status where tx_id ="))
        o = docs(mode="occurrences")[1]["spec"]["template"]["spec"]["containers"][0]["args"][-1].lower()
        self.assertTrue(o.startswith("select count(*) from ns_rd_dfabi_v2 where "))

    def test_inputs_are_validated(self):
        bad = [dict(mode="status", txid="AB" * 32), dict(mode="status", txid="ab" * 31), dict(mode="status", txid="zz" * 32), dict(mode="status", txid="ab' or 1=1 --"),
               dict(mode="occurrences", needle="abc"), dict(mode="occurrences", needle="00" * 17), dict(mode="occurrences", needle="zz"), dict(mode="status", namespace="rd_dfabi_v2; drop table x"),
               dict(mode="status", namespace="Rd"), dict(mode="delete"), dict(mode="status", name="UPPER")]
        for kw in bad:
            with self.subTest(kw=kw), self.assertRaises(SystemExit):
                a = dict(MODES.get(kw.get("mode"), {"txid": TXID})); a.update(kw); mode = a.pop("mode"); name = a.pop("name", "t1")
                render.render_dbread("bi", name, mode, **a)

    def test_the_sql_templates_are_pinned(self):
        # changing any statement changes this hash: the GO text quotes it and must be re-approved
        self.assertEqual(render.dbread_template_sha256("rd_dfabi_v2"), "65469cba46f6fc80d8c98d5a00ebc0d50c687f0f8b0ef4346f64c25c5865726c")


class Mutants(unittest.TestCase):
    """The audit must catch each way the Job could stop being a keyless, egress-locked, SELECT-only reader."""

    def setUp(self):
        self.ds = docs("bank-a", "status")

    def audit(self, ds):
        return render.audit_dbread(ds, "status")

    def mutate(self, f):
        ds = copy.deepcopy(self.ds); np, job = split(ds); f(np, job, job["spec"]["template"]["spec"]["containers"][0]); return ds

    def test_clean_is_clean(self):
        self.assertEqual(self.audit(self.ds), [])

    def test_write_sql(self):
        self.assertTrue(self.audit(self.mutate(lambda n, j, c: c["args"].__setitem__(-1, "update tx_status set status = 1"))))

    def test_printing_a_value(self):
        self.assertTrue(self.audit(self.mutate(lambda n, j, c: c["args"].__setitem__(-1, "select value from ns_rd_dfabi_v2"))))

    def test_extra_egress(self):
        self.assertTrue(self.audit(self.mutate(lambda n, j, c: n["spec"]["egress"].append(render.egress_rule("ip=1.1.1.1/32:443")))))

    def test_unpinned_or_other_image(self):
        for img in ("postgres:17", "docker.io/library/postgres@sha256:" + "0" * 64, PG.replace("postgres@", "postgresx@")):
            with self.subTest(img=img):
                self.assertTrue(self.audit(self.mutate(lambda n, j, c: c.__setitem__("image", img))))

    def test_lock_label_removed(self):
        self.assertTrue(self.audit(self.mutate(lambda n, j, c: j["spec"]["template"]["metadata"]["labels"].pop("rd/egress-locked"))))

    def test_shell_command(self):
        self.assertTrue(self.audit(self.mutate(lambda n, j, c: c.__setitem__("command", ["bash", "-c", "psql"]))))

    def test_extra_secret_env_or_volume(self):
        self.assertTrue(self.audit(self.mutate(lambda n, j, c: c["env"].append({"name": "X", "valueFrom": {"secretKeyRef": {"name": "committer-tls", "key": "server.key"}}}))))
        self.assertTrue(self.audit(self.mutate(lambda n, j, c: j["spec"]["template"]["spec"].__setitem__("volumes", [{"name": "v", "secret": {"secretName": "committer-tls"}}]))))

    def test_service_account_token_automounted(self):
        self.assertTrue(self.audit(self.mutate(lambda n, j, c: j["spec"]["template"]["spec"].__setitem__("automountServiceAccountToken", True))))


if __name__ == "__main__":
    unittest.main()
