"""Static checks of the fsc-sqlite-image build (stock sqlite3 CLI for the FSC node-DB checks): same gates as rdbi-image.yml / tools-image.yml. No network, no docker.

  python3 -m unittest discover -s multiorg/fsc
"""
import os, re, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WF = os.path.join(ROOT, ".github", "workflows", "fsc-sqlite-image.yml")
DOCKERFILE = os.path.join(HERE, "state", "Dockerfile")
ALLOW = os.path.join(ROOT, "panurus-itest", "k8s", "scan-allow.txt")


def load():
    with open(WF) as f:
        return yaml.safe_load(f)


def steps():
    return load()["jobs"]["image"]["steps"]


class SqliteImage(unittest.TestCase):
    def test_manual_trigger_only_and_minimal_permissions(self):
        wf = load()
        self.assertEqual(sorted(wf[True]), ["workflow_dispatch"])
        self.assertEqual(wf["permissions"], {"contents": "read"})
        self.assertEqual(wf["jobs"]["image"]["permissions"], {"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"})   # the signed attestation step runs now that the repository is public

    def test_every_run_step_is_bash_with_pipefail(self):
        wf = load()
        self.assertEqual(wf["defaults"], {"run": {"shell": "bash"}})
        for s in steps():
            self.assertNotIn("shell", s)
        self.assertNotIn("defaults", wf["jobs"]["image"])

    def test_every_action_is_pinned_by_commit_sha(self):
        for s in steps():
            if "uses" in s:
                self.assertRegex(s["uses"], r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", s["uses"])

    def test_sqlite3_is_a_pinned_debian_package_and_versions_are_recorded(self):
        t = open(DOCKERFILE).read()
        self.assertIn("sqlite3=3.40.1-2+deb12u2", t)
        self.assertIn("libsqlite3-0=3.40.1-2+deb12u2", t)
        rec = [s for s in steps() if s.get("name", "").startswith("Record the installed package versions")][0]["run"]
        self.assertIn("dpkg-query -W sqlite3 libsqlite3-0", rec)

    def test_scan_before_push_with_the_pinned_base_allow_list(self):
        st = steps()
        names = [s.get("name", s.get("uses", "")) for s in st]
        bps = [i for i, s in enumerate(st) if str(s.get("uses", "")).startswith("docker/build-push-action@")]
        self.assertEqual(len(bps), 2)
        local, push = bps
        self.assertTrue(st[local]["with"]["load"])
        self.assertFalse(st[local]["with"]["push"])
        self.assertTrue(st[push]["with"]["push"])
        sc = next(i for i, n in enumerate(names) if n.startswith("Scan the image layers"))
        self.assertLess(local, sc)
        self.assertLess(sc, push)
        run = st[sc]["run"]
        self.assertIn("--allow panurus-itest/k8s/scan-allow.txt", run)
        self.assertIn("--dockerfile multiorg/fsc/state/Dockerfile", run)

    def test_sbom_max_provenance_private_new_package_never_latest_or_the_old_ones(self):
        push = [s for s in steps() if str(s.get("uses", "")).startswith("docker/build-push-action@") and s["with"].get("push")][0]["with"]
        self.assertTrue(push["sbom"])
        self.assertEqual(push["provenance"], "mode=max")
        self.assertEqual(push["file"], "multiorg/fsc/state/Dockerfile")
        self.assertEqual(push["tags"], "ghcr.io/${{ github.repository_owner }}/fsc-sqlite-ci:sha-${{ github.sha }}")
        text = open(WF).read()
        self.assertNotRegex(text, r"ghcr\.io/\S*/rdbi-node")   # never the rdbi packages
        self.assertNotIn(":latest", text)

    def test_attestation_gap_is_conditional_and_stated(self):
        st = steps()
        at = [s for s in st if str(s.get("uses", "")).startswith("actions/attest-build-provenance@")][0]
        self.assertEqual(at["if"], "${{ github.event.repository.private == false }}")
        self.assertIn("no signed attestation", open(WF).read())
        rep = [s for s in st if s.get("name") == "Report the digest"][0]
        self.assertNotIn("if", rep)
        self.assertIn("steps.build.outputs.digest", rep["run"])

    def test_checkout_keeps_no_credentials(self):
        co = [s for s in steps() if str(s.get("uses", "")).startswith("actions/checkout@")]
        self.assertTrue(co and all(s["with"]["persist-credentials"] is False for s in co))


class Dockerfile(unittest.TestCase):
    def test_base_is_the_allow_list_base_pinned_by_digest(self):
        froms = [l.split()[1] for l in open(DOCKERFILE) if l.startswith("FROM ")]
        base = [l.split()[1] for l in open(ALLOW) if l.startswith("base ")]
        self.assertEqual(len(froms), 1)
        self.assertRegex(froms[0], r"^debian:bookworm-slim@sha256:[0-9a-f]{64}$")
        self.assertEqual(froms, base)

    def test_runs_as_non_root_and_copies_no_code_of_ours(self):
        t = open(DOCKERFILE).read()
        self.assertIn("USER 10001", t)
        self.assertEqual(re.findall(r"^(?:COPY|ADD) (.+)$", t, re.M), [])
        self.assertNotIn("curl", t)


if __name__ == "__main__":
    unittest.main()
