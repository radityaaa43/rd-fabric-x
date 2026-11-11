"""Offline tests for build_genesis.py (fabricx S10 prep): a stub armageddon, fake exchange trees, no cluster.

  python3 -m unittest discover -s multiorg/s10        (needs PyYAML)
"""
import hashlib, os, subprocess, sys, tempfile, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import build_genesis
import regen_endpoints
import test_check_exchange as tce

STUB = r"""#!/bin/sh
# stub armageddon: `generate` writes a fake bootstrap/shared_config.yaml with defaults; `createBlock` checks what it is given
echo "$@" >> "$STUB_LOG/argv.log"
pwd >> "$STUB_LOG/cwd.log"
case "$1" in
generate)
  for a in "$@"; do case "$a" in --output=*) out="${a#--output=}";; esac; done
  mkdir -p "$out/bootstrap"
  printf 'Parties: []\nConsensus:\n  BFTConfig:\n    LeaderHeartbeatCount: 10\nBatching:\n  RequestMaxBytes: 1048576\nMaxPartyID: 4\n' > "$out/bootstrap/shared_config.yaml"
  mkdir -p "$out/crypto"; printf -- '-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n' > "$out/crypto/throwaway.key";;
createBlock)
  for a in "$@"; do case "$a" in --sharedConfigYaml=*) sc="${a#--sharedConfigYaml=}";; --blockOutput=*) bo="${a#--blockOutput=}";; esac; done
  # every path in the shared config must exist relative to the cwd, and no private key may be below the cwd
  grep -E '^\s*(- )?(SignCert|TLSCert|CACerts|TLSCACerts)?:? *crypto/' "$sc" | sed 's/.*\(crypto\/[^ ]*\)/\1/' | while read p; do [ -f "$p" ] || { echo "missing $p" >&2; exit 3; }; done || exit 3
  if grep -rl "PRIVATE KEY" . >/dev/null 2>&1; then echo "private key below baseDir" >&2; exit 4; fi
  mkdir -p "$bo"; echo "FAKE BLOCK" > "$bo/bootstrap.block";;
esac
"""


def make_exchange(root, parties=(1, 2, 3, 4)):
    for n in parties:
        d = os.path.join(root, f"org{n}")
        tce.good_tree(d, n)
        # a real build only accepts the port plan and real hosts: the fixture tree from the checker test has neither
        PORTS = {"router": 8013, "batcher1": 8014, "consenter": 8012, "assembler": 8011}
        ep = {r: {"Host": f"{r}-{n}.fabricx.example.org", "Port": p} for r, p in PORTS.items()}
        with open(os.path.join(d, "endpoints.yaml"), "w") as f:
            yaml.safe_dump(ep, f)
        tce.manifest(d)


class Build(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.ex, self.out, self.log = os.path.join(t, "ex"), os.path.join(t, "out"), os.path.join(t, "log")
        os.makedirs(self.log)
        make_exchange(self.ex)
        self.arma = os.path.join(t, "armageddon")
        with open(self.arma, "w") as f:
            f.write(STUB)
        os.chmod(self.arma, 0o755)
        os.makedirs(os.path.join(t, "sample"))
        self.sample = os.path.join(t, "sample")
        os.environ["STUB_LOG"] = self.log

    def tearDown(self):
        os.environ.pop("STUB_LOG", None)
        self.tmp.cleanup()

    def run_build(self, **kw):
        return build_genesis.build(self.ex, self.arma, self.sample, self.out, **kw)

    def test_builds_block_and_reports_hash(self):
        r = self.run_build()
        block = os.path.join(self.out, "block", "bootstrap.block")
        self.assertEqual(r["sha256"], hashlib.sha256(open(block, "rb").read()).hexdigest())
        cwd = open(os.path.join(self.log, "cwd.log")).read().split()
        self.assertEqual(cwd[-1], os.path.realpath(os.path.join(self.out, "base")))     # createBlock ran INSIDE the base dir
        self.assertEqual(r["parties"], [1, 2, 3, 4])

    def test_shared_config_uses_endpoints_and_cert_paths_only(self):
        self.run_build()
        sc = yaml.safe_load(open(os.path.join(self.out, "base", "bootstrap", "shared_config.yaml")))
        self.assertEqual(sc["MaxPartyID"], 4)
        self.assertEqual(sc["Consensus"]["BFTConfig"]["LeaderHeartbeatCount"], 10)      # defaults come from the upstream generator
        p2 = next(p for p in sc["Parties"] if p["PartyID"] == 2)
        self.assertEqual(p2["RouterConfig"]["Host"], "router-2.fabricx.example.org")
        self.assertEqual(p2["RouterConfig"]["Port"], 8013)
        self.assertTrue(p2["CACerts"][0].startswith("crypto/ordererOrganizations/org2/msp/cacerts/"))
        self.assertTrue(p2["ConsenterConfig"]["SignCert"].endswith("consenter/msp/signcerts/consenter-cert.pem"))
        self.assertEqual(p2["BatchersConfig"][0]["ShardID"], 1)
        self.assertEqual(p2["BatchersConfig"][0]["SignCert"].split("/")[-1], "batcher1-cert.pem")

    def test_no_private_key_below_base_dir(self):
        self.run_build()
        r = subprocess.run(["grep", "-rl", "PRIVATE KEY", os.path.join(self.out, "base")], capture_output=True, text=True)
        self.assertEqual(r.stdout, "")
        self.assertFalse(os.path.exists(os.path.join(self.out, "gen")))                  # the scratch generate dir (throwaway keys) is gone

    def test_unclean_exchange_is_refused_before_anything_runs(self):
        with open(os.path.join(self.ex, "org3", "orderers", "party3", "router", "tls", "server.key"), "w") as f:
            f.write("-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n")
        with self.assertRaises(SystemExit):
            self.run_build()
        self.assertFalse(os.path.exists(os.path.join(self.log, "argv.log")))             # armageddon was never started

    def test_missing_or_wrong_party_refused(self):
        import shutil
        shutil.rmtree(os.path.join(self.ex, "org4"))
        with self.assertRaises(SystemExit):
            self.run_build()

    def test_real_build_refuses_placeholder_hosts_and_off_plan_ports(self):
        for mutate, why in ((lambda ep: ep["router"].update(Host="router-2.lb.bank-a"), "placeholder host"),
                            (lambda ep: ep["router"].update(Port=7050), "port outside the plan")):
            with self.subTest(why=why):
                t = tempfile.TemporaryDirectory()
                ex = os.path.join(t.name, "ex")
                make_exchange(ex)
                p = os.path.join(ex, "org2", "endpoints.yaml")
                ep = yaml.safe_load(open(p))
                mutate(ep)
                with open(p, "w") as f:
                    yaml.safe_dump(ep, f)
                tce.manifest(os.path.join(ex, "org2"))
                with self.assertRaises(SystemExit):
                    build_genesis.build(ex, self.arma, self.sample, os.path.join(t.name, "out"))
                self.assertFalse(os.path.exists(os.path.join(self.log, "argv.log")))
                t.cleanup()

    def test_dry_run_accepts_placeholders_and_keeps_no_block(self):
        ex2 = os.path.join(self.tmp.name, "ex2")
        regen_endpoints.regen(self.ex, ex2, "{role}-{n}.lb.{party}")
        out = os.path.join(self.tmp.name, "dry")
        r = build_genesis.build(ex2, self.arma, self.sample, out, dry_run=True)
        self.assertTrue(r["dry_run"])
        self.assertEqual(len(r["sha256"]), 64)
        self.assertFalse(os.path.exists(os.path.join(out, "block", "bootstrap.block")))      # block not kept
        self.assertFalse(os.path.exists(os.path.join(out, "base")))                          # nor the base dir
        self.assertTrue(os.path.exists(os.path.join(self.log, "argv.log")))                  # the pipeline really ran
        with self.assertRaises(SystemExit):
            build_genesis.build(ex2, self.arma, self.sample, os.path.join(self.tmp.name, "real"))

    def test_cli_requires_heads(self):
        # a real build without the announced hashes would skip the check: the CLI refuses it
        args = [sys.executable, os.path.join(HERE, "build_genesis.py"), "--exchange", self.ex, "--armageddon", self.arma,
                "--sample-config", self.sample, "--out", self.out]
        r = subprocess.run(args, capture_output=True, text=True, env={**os.environ})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--heads", r.stderr + r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.log, "argv.log")))
        heads = ",".join(f"{n}={hashlib.sha256(open(os.path.join(self.ex, f'org{n}', 'MANIFEST.sha256'), 'rb').read()).hexdigest()}" for n in (1, 2, 3, 4))
        r = subprocess.run(args + ["--heads", heads], capture_output=True, text=True, env={**os.environ})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("sha256", r.stdout)
        os.makedirs(self.out + "2")
        r = subprocess.run(args[:-1] + [self.out + "2", "--heads", "1=" + "0" * 64 + ",2=x"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)                                              # incomplete or wrong heads

    def test_expected_manifest_hash_mismatch_refused(self):
        heads = {n: hashlib.sha256(open(os.path.join(self.ex, f"org{n}", "MANIFEST.sha256"), "rb").read()).hexdigest() for n in (1, 2, 3, 4)}
        self.run_build(manifest_heads=heads)
        heads[3] = "0" * 64
        with self.assertRaises(SystemExit):
            self.run_build(manifest_heads=heads)


if __name__ == "__main__":
    unittest.main()
