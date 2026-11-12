"""Tests for multiorg/gw/r32.py (R32 closure tooling): the cross-party 403 Job for the four fx-gw doors, its verdict, and the live bundle revision check.

  python3 -m unittest discover -s multiorg/gw
"""
import importlib.util, json, os, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("gw_r32", os.path.join(HERE, "r32.py"))
r32 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r32)

IMG = "ghcr.io/radityaaa43/rd-lensa-frontend@sha256:" + "c" * 64
URLS = {"BI": "https://fx-gw-1.rd-fabricx-bi.svc.cluster.local:8443", "A": "https://fx-gw-2.rd-fabricx-bank-a.svc.cluster.local:8443",
        "B": "https://fx-gw-3.rd-fabricx-bank-b.svc.cluster.local:8443", "C": "https://43.106.108.143:8443"}
PARTIES = ["BI", "A", "B", "C"]


def docs():
    return {d["kind"]: d for d in yaml.safe_load_all(r32.render_job(IMG, URLS))}


def good_log():
    return "\n".join(f"{c} {t} {200 if c == t else 403}" for c in PARTIES for t in PARTIES) + "\n"


class JobShape(unittest.TestCase):
    def test_only_a_configmap_and_a_job_no_secret_no_rbac(self):
        self.assertEqual(sorted(docs()), ["ConfigMap", "Job"])

    def test_namespace_and_labels_pick_up_the_existing_flow_egress_policy(self):
        d = docs()
        pod = d["Job"]["spec"]["template"]
        self.assertEqual(d["Job"]["metadata"]["namespace"], "rd-lensa")
        self.assertEqual(d["ConfigMap"]["metadata"]["namespace"], "rd-lensa")
        # NetworkPolicy egress-gateways-flow selects app=lensa, role in (flow, probe-flow)
        self.assertEqual(pod["metadata"]["labels"]["app"], "lensa")
        self.assertEqual(pod["metadata"]["labels"]["role"], "probe-flow")

    def test_certs_are_the_four_existing_lensa_secrets_by_name_with_the_lensa_layout(self):
        pod = docs()["Job"]["spec"]["template"]["spec"]
        certs = [v for v in pod["volumes"] if v["name"] == "certs"][0]["projected"]["sources"]
        got = {s["secret"]["name"]: [(i["key"], i["path"]) for i in s["secret"]["items"]] for s in certs}
        want = {f"lensa-gw-mtls-{p.lower()}": [(f, f"{p}/{f}") for f in ("ca.crt", "lensa.crt", "lensa.key")] for p in PARTIES}
        self.assertEqual(got, want)
        mounts = pod["containers"][0]["volumeMounts"]
        self.assertTrue(all(m["readOnly"] for m in mounts))
        self.assertIn("/certs", [m["mountPath"] for m in mounts])

    def test_pod_is_restricted_and_has_no_api_token(self):
        pod = docs()["Job"]["spec"]["template"]["spec"]
        c = pod["containers"][0]
        self.assertIs(pod["automountServiceAccountToken"], False)
        self.assertEqual(pod["restartPolicy"], "Never")
        self.assertIs(pod["securityContext"]["runAsNonRoot"], True)
        self.assertEqual(pod["securityContext"]["seccompProfile"], {"type": "RuntimeDefault"})
        self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False)
        self.assertIs(c["securityContext"]["readOnlyRootFilesystem"], True)
        self.assertEqual(c["securityContext"]["capabilities"], {"drop": ["ALL"]})
        self.assertEqual(pod["imagePullSecrets"], [{"name": "ghcr-pull"}])

    def test_job_is_one_shot_and_short(self):
        j = docs()["Job"]["spec"]
        self.assertEqual(j["backoffLimit"], 0)
        self.assertLessEqual(j["activeDeadlineSeconds"], 300)
        self.assertLessEqual(j["ttlSecondsAfterFinished"], 900)

    def test_image_must_be_pinned_by_digest(self):
        for bad in ("ghcr.io/x/y:latest", "ghcr.io/x/y@sha256:abc", ""):
            with self.assertRaises(SystemExit):
                r32.render_job(bad, URLS)

    def test_all_four_gateways_are_required_and_named_by_party(self):
        for missing in PARTIES:
            u = {k: v for k, v in URLS.items() if k != missing}
            with self.assertRaises(SystemExit):
                r32.render_job(IMG, u)
        with self.assertRaises(SystemExit):
            r32.render_job(IMG, {**URLS, "D": "https://x:1"})
        with self.assertRaises(SystemExit):
            r32.render_job(IMG, {**URLS, "A": "http://plain:8443"})

    def test_config_is_a_read_op_with_servername_per_gateway(self):
        cfg = json.loads(docs()["ConfigMap"]["data"]["matrix.json"])
        self.assertIn(cfg["body"]["op"], r32.READS)
        self.assertEqual(cfg["body"]["op"], "balance")
        self.assertEqual({p: (t["url"], t["servername"]) for p, t in cfg["targets"].items()},
                         {"BI": (URLS["BI"], "fx-gw-1"), "A": (URLS["A"], "fx-gw-2"), "B": (URLS["B"], "fx-gw-3"), "C": (URLS["C"], "fx-gw-4")})
        self.assertEqual(cfg["callers"], PARTIES)

    def test_script_sends_no_write_op_and_reads_only_certs(self):
        script = docs()["ConfigMap"]["data"]["probe.mjs"]
        for w in ("issue", "award", "transfer", "swap", "redeem", "precheck"):
            self.assertNotIn(f'"{w}"', script)
            self.assertNotIn(f"'{w}'", script)
        self.assertIn("/certs/", script)
        self.assertNotIn("process.env", script)
        self.assertNotIn("rejectUnauthorized: false", script)

    def test_script_prints_one_line_per_pair_in_the_verdict_format(self):
        script = docs()["ConfigMap"]["data"]["probe.mjs"]
        self.assertIn("console.log(`${caller} ${target} ${status}`)", script)


class Verdict(unittest.TestCase):
    def test_the_expected_matrix_passes(self):
        ok, rep = r32.verdict(good_log())
        self.assertTrue(ok, rep)

    def test_a_cross_pair_that_is_not_403_fails_and_is_named(self):
        for bad in ("200", "400", "ERR", "401"):
            log = good_log().replace("A C 403", f"A C {bad}")
            ok, rep = r32.verdict(log)
            self.assertFalse(ok)
            self.assertIn("A C", "\n".join(rep))

    def test_an_own_leaf_denied_or_unreachable_fails(self):
        for bad in ("403", "ERR"):
            ok, rep = r32.verdict(good_log().replace("B B 200", f"B B {bad}"))
            self.assertFalse(ok)
            self.assertIn("B B", "\n".join(rep))

    def test_own_leaf_any_http_answer_but_403_is_a_pass(self):
        # the request body is minimal: the backend may answer 400; what matters is that the door let it through
        for s in ("200", "400", "404", "500"):
            ok, _ = r32.verdict(good_log().replace("C C 200", f"C C {s}"))
            self.assertTrue(ok, s)

    def test_a_missing_or_duplicated_pair_fails(self):
        lines = good_log().splitlines()
        ok, _ = r32.verdict("\n".join(lines[:-1]))
        self.assertFalse(ok)
        ok, _ = r32.verdict("\n".join(lines + [lines[0]]))
        self.assertFalse(ok)

    def test_noise_lines_are_ignored_but_an_empty_log_fails(self):
        ok, _ = r32.verdict("starting\n" + good_log() + "done\n")
        self.assertTrue(ok)
        ok, _ = r32.verdict("")
        self.assertFalse(ok)


def status_line(bi_rev, bank_rev, bank_name="bank"):
    return json.dumps({"bundles": {"bi": {"active_revision": bi_rev, "last_successful_activation": "2026-11-12T07:02:32Z"},
                                   bank_name: {"active_revision": bank_rev, "last_successful_activation": "2026-11-12T07:02:32Z"}},
                       "labels": {"gateway": "fx-gw-1"}})


class Revisions(unittest.TestCase):
    def test_last_status_line_wins_and_noise_is_skipped(self):
        log = "\n".join(['{"level":"info","msg":"x"}', "not json", status_line("bi-A", "bank-A"), status_line("bi-B", "bank-B"), '{"level":"info"}'])
        self.assertEqual(r32.revisions(log), {"bi": "bi-B", "bank": "bank-B"})

    def test_no_bundle_status_is_an_error(self):
        with self.assertRaises(SystemExit):
            r32.revisions('{"level":"info","msg":"x"}\n')

    def test_both_bundles_are_required(self):
        one = json.dumps({"bundles": {"bi": {"active_revision": "bi-A", "last_successful_activation": "t"}}})
        with self.assertRaises(SystemExit):
            r32.revisions(one)

    def test_a_bundle_without_an_activation_is_an_error(self):
        l = json.dumps({"bundles": {"bi": {"active_revision": "bi-A", "last_successful_activation": "t"}, "bank": {"last_error": "boom"}}})
        with self.assertRaises(SystemExit):
            r32.revisions(l)

    def test_table_quotes_every_gateway_and_flags_a_mismatch_with_the_expected_fabricx_revision(self):
        logs = {f"fx-gw-{n}": status_line("bi-zeto.41-noto.11-fabricx.13-iroha3.1-lensaca.1", f"bank{n}-zeto.1-noto.1-fabricx.{n}-iroha3.1") for n in (1, 2, 3, 4)}
        ok, rep = r32.revision_table(logs, expect_fabricx_bi=13)
        self.assertTrue(ok)
        self.assertEqual(len([l for l in rep if l.startswith("fx-gw-")]), 4)
        logs["fx-gw-3"] = status_line("bi-zeto.41-noto.11-fabricx.12-iroha3.1-lensaca.1", "bank3-zeto.1-noto.1-fabricx.3-iroha3.1")
        ok, rep = r32.revision_table(logs, expect_fabricx_bi=13)
        self.assertFalse(ok)
        self.assertTrue(any("fx-gw-3" in l and "MISMATCH" in l for l in rep))

    def test_all_four_gateways_are_required(self):
        logs = {f"fx-gw-{n}": status_line("bi-fabricx.13", "bank-fabricx.1") for n in (1, 2, 3)}
        ok, rep = r32.revision_table(logs, expect_fabricx_bi=13)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
