"""Offline tests for multiorg/lb (fabricx Arma party endpoints, PLAN S11/S18): per-party LoadBalancer Service render (per-role as an option). No cluster.

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


def docs(party, acl=ACL, ranges=RANGES, per_role=False):
    return list(yaml.safe_load_all(render.render(party, acl, ranges, per_role=per_role)))


def cli(*args):
    r = subprocess.run([sys.executable, os.path.join(HERE, "render.py"), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    return r


# S11 pod contract (named in the PR body): the four Arma role pods of a party carry this shared label and declare these NAMED container ports.
# Named targetPorts make a role's port reach only the pods that declare it (a numeric targetPort would route to every selected pod).
POD_LABELS = lambda p: {"rd-fabricx/arma-party": str(enroll.PARTY_N[p])}   # lead: one shared label on all four role pods of party N
ANNOTATIONS = {PREFIX + "acl-status": "on", PREFIX + "acl-type": "white", PREFIX + "address-type": "internet", PREFIX + "scheduler": "wrr"}


class PerParty(unittest.TestCase):
    """DECIDED (lead): one LoadBalancer Service lb-<N> per party carries the four listeners: one CLB, one ACL."""

    def test_one_service_four_listeners(self):
        for p, n in enroll.PARTY_N.items():
            with self.subTest(party=p):
                d = docs(p)
                self.assertEqual(len(d), 1)
                x = d[0]
                self.assertEqual((x["apiVersion"], x["kind"], x["spec"]["type"]), ("v1", "Service", "LoadBalancer"))
                self.assertEqual((x["metadata"]["name"], x["metadata"]["namespace"]), (f"lb-{n}", f"rd-fabricx-{p}"))
                self.assertEqual(x["metadata"]["labels"], {"app.kubernetes.io/part-of": "rd-fabricx", "party": p})
                self.assertEqual(x["spec"]["ports"], [{"name": r, "port": port, "targetPort": r, "protocol": "TCP"} for r, port in enroll.PORT_PLAN.items()])
                self.assertEqual({q["port"] for q in x["spec"]["ports"]}, {8011, 8012, 8013, 8014})
                self.assertEqual(len({q["name"] for q in x["spec"]["ports"]}), 4)

    def test_selector_is_the_s11_pod_contract(self):
        for p in enroll.PARTY_N:
            self.assertEqual(docs(p)[0]["spec"]["selector"], POD_LABELS(p))
        self.assertNotEqual(docs("bi")[0]["spec"]["selector"], docs("bank-a")[0]["spec"]["selector"])   # never selects another party

    def test_external_traffic_policy_local_with_wrr(self):
        # docs (ACK managed CLB page): Local mounts only the nodes where pods reside, and "requires" the wrr scheduler
        for p in enroll.PARTY_N:
            x = docs(p)[0]
            self.assertEqual(x["spec"]["externalTrafficPolicy"], "Local")
            self.assertEqual(x["metadata"]["annotations"][PREFIX + "scheduler"], "wrr")

    def test_acl_first_annotations_one_acl(self):
        for p in enroll.PARTY_N:
            ann = docs(p)[0]["metadata"]["annotations"]
            self.assertEqual(ann, {**ANNOTATIONS, PREFIX + "acl-id": ACL})
            self.assertEqual(ann[PREFIX + "acl-status"], "on")                 # the listener is never open

    def test_source_ranges_copied_and_deduped(self):
        self.assertEqual(docs("bank-c")[0]["spec"]["loadBalancerSourceRanges"], RANGES)
        self.assertEqual(docs("bi", ranges=["203.0.113.7/32", "203.0.113.7/32"])[0]["spec"]["loadBalancerSourceRanges"], ["203.0.113.7/32"])

    def test_cli_default_is_per_party(self):
        for p in enroll.PARTY_N:
            r = cli(p, "--acl-id", ACL, "--source-range", RANGES[0], "--source-range", RANGES[1])
            self.assertEqual(r.returncode, 0, r.stderr)
            out = list(yaml.safe_load_all(r.stdout))
            self.assertEqual([x["metadata"]["name"] for x in out], [f"lb-{enroll.PARTY_N[p]}"])
        dup = cli("bi", "--acl-id", ACL, "--source-range", RANGES[0], "--source-range", RANGES[0])
        self.assertEqual(dup.returncode, 0, dup.stderr)


class PerRoleOption(unittest.TestCase):
    """The per-role split stays a documented option (--per-role): four Services, one CLB each."""

    def test_four_services(self):
        for p, n in enroll.PARTY_N.items():
            with self.subTest(party=p):
                d = docs(p, per_role=True)
                self.assertEqual({x["metadata"]["name"] for x in d}, {f"lb-{r}-{n}" for r in enroll.PORT_PLAN})
                for x in d:
                    role = x["metadata"]["name"][len("lb-"):-len(f"-{n}")]
                    self.assertEqual(x["spec"]["ports"], [{"name": role, "port": enroll.PORT_PLAN[role], "targetPort": role, "protocol": "TCP"}])
                    self.assertEqual(x["spec"]["selector"], POD_LABELS(p))
                    self.assertEqual(x["spec"]["externalTrafficPolicy"], "Local")
                    self.assertEqual(x["metadata"]["annotations"], {**ANNOTATIONS, PREFIX + "acl-id": ACL})

    def test_cli_flag(self):
        r = cli("bi", "--per-role", "--acl-id", ACL, "--source-range", RANGES[0])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(list(yaml.safe_load_all(r.stdout))), 4)


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
            for per_role in (False, True):
                with self.assertRaises(SystemExit):
                    render.render(*args, per_role=per_role)


if __name__ == "__main__":
    unittest.main()
