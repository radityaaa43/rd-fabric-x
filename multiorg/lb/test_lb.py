"""Offline tests for multiorg/lb (fabricx S16 input): per-role LoadBalancer Services render. No cluster.

  python3 -m unittest discover -s multiorg/lb        (needs PyYAML)
"""
import os, subprocess, sys, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "fca"))   # enroll (PORT_PLAN); fca/render.py has the same name, so HERE goes first
sys.path.insert(0, HERE)
import enroll, render

PREFIX = "service.beta.kubernetes.io/alibaba-cloud-loadbalancer-"
ACL = "acl-abc123"
RANGES = ["203.0.113.7/32", "198.51.100.9/32"]


def docs(party, acl=ACL, ranges=RANGES):
    return list(yaml.safe_load_all(render.render(party, acl, ranges)))


def cli(*args):
    r = subprocess.run([sys.executable, os.path.join(HERE, "render.py"), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    return r


class Services(unittest.TestCase):
    def test_four_services_names_ports_ns(self):
        for p, n in enroll.PARTY_N.items():
            with self.subTest(party=p):
                d = docs(p)
                self.assertEqual({x["metadata"]["name"] for x in d}, {f"lb-{r}-{n}" for r in enroll.PORT_PLAN})
                for x in d:
                    role = x["metadata"]["name"][len("lb-"):-len(f"-{n}")]
                    self.assertEqual(x["metadata"]["namespace"], f"rd-fabricx-{p}")
                    self.assertEqual(x["spec"]["ports"], [{"name": role, "port": enroll.PORT_PLAN[role], "targetPort": enroll.PORT_PLAN[role], "protocol": "TCP"}])
                    self.assertEqual(x["spec"]["selector"], {"app.kubernetes.io/name": f"{role}-{n}"})
                    self.assertEqual(x["metadata"]["labels"], {"app.kubernetes.io/part-of": "rd-fabricx", "party": p})

    def test_only_loadbalancer_services(self):
        for p in enroll.PARTY_N:
            for x in docs(p):
                self.assertEqual((x["apiVersion"], x["kind"], x["spec"]["type"]), ("v1", "Service", "LoadBalancer"))
                self.assertNotIn("externalTrafficPolicy", x["spec"])    # not justified by a doc we read: open question in the runbook

    def test_ports_distinct_per_role(self):
        self.assertEqual(len(set(enroll.PORT_PLAN.values())), len(enroll.PORT_PLAN))   # a per-party LB could carry all four
        self.assertEqual({x["spec"]["ports"][0]["port"] for x in docs("bi")}, set(enroll.PORT_PLAN.values()))

    def test_acl_first_annotations(self):
        for p in enroll.PARTY_N:
            for x in docs(p):
                self.assertEqual(x["metadata"]["annotations"], {
                    PREFIX + "acl-status": "on", PREFIX + "acl-id": ACL, PREFIX + "acl-type": "white", PREFIX + "address-type": "internet"})

    def test_source_ranges_copied_and_deduped(self):
        for x in docs("bank-c"):
            self.assertEqual(x["spec"]["loadBalancerSourceRanges"], RANGES)
        for x in docs("bi", ranges=["203.0.113.7/32", "203.0.113.7/32"]):
            self.assertEqual(x["spec"]["loadBalancerSourceRanges"], ["203.0.113.7/32"])

    def test_cli_yaml_stdout(self):
        for p in enroll.PARTY_N:
            r = cli(p, "--acl-id", ACL, "--source-range", RANGES[0], "--source-range", RANGES[1])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(len(list(yaml.safe_load_all(r.stdout))), 4)
        dup = cli("bi", "--acl-id", ACL, "--source-range", RANGES[0], "--source-range", RANGES[0])
        self.assertEqual(dup.returncode, 0, dup.stderr)


class Refusals(unittest.TestCase):
    def refused(self, *args):
        r = cli(*args)
        self.assertNotEqual(r.returncode, 0, args)
        self.assertEqual(r.stdout, "", args)

    def test_missing_required(self):
        self.refused("bi", "--source-range", RANGES[0])                 # no --acl-id
        self.refused("bi", "--acl-id", ACL)                             # no --source-range
        self.refused("bi")

    def test_bad_acl_id(self):
        for bad in ("abc123", "acl-", "acl-ABC", "acl-a b", "acl-a_b", "acl-abc/1"):
            with self.subTest(acl=bad):
                self.refused("bi", "--acl-id", bad, "--source-range", RANGES[0])

    def test_bad_or_wide_ranges(self):
        for bad in ("0.0.0.0/0", "10.0.0.0/24", "203.0.113.7/31", "203.0.113.7", "203.0.113.7/33", "999.1.1.1/32",
                    "::1/128", "2001:db8::1/32", "a.b.c.d/32", ""):
            with self.subTest(rng=bad):
                self.refused("bi", "--acl-id", ACL, "--source-range", bad)
        self.refused("bi", "--acl-id", ACL, "--source-range", RANGES[0], "--source-range", "0.0.0.0/0")   # one bad poisons the set

    def test_unknown_party_and_extra_args(self):
        self.refused("bank-d", "--acl-id", ACL, "--source-range", RANGES[0])
        self.refused("bi", "bank-a", "--acl-id", ACL, "--source-range", RANGES[0])
        self.refused("bi", "--acl-id", ACL, "--source-range", RANGES[0], "--bogus", "x")

    def test_render_function_refuses(self):
        for args in (("nope", ACL, RANGES), ("bi", "bad", RANGES), ("bi", ACL, []), ("bi", ACL, ["0.0.0.0/0"])):
            with self.assertRaises(SystemExit):
                render.render(*args)


if __name__ == "__main__":
    unittest.main()
