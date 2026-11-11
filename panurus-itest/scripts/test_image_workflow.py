"""Static checks of the rdbi-node image build (fabricx S15 gate: CI rebuild with SBOM + provenance). No network, no docker.

  python3 -m unittest discover -s panurus-itest/scripts
"""
import os, re, unittest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WF = os.path.join(ROOT, ".github", "workflows", "rdbi-image.yml")
DOCKERFILE = os.path.join(ROOT, "panurus-itest", "k8s", "Dockerfile")


def load():
    with open(WF) as f:
        return yaml.safe_load(f)


def steps(wf):
    return [s for j in wf["jobs"].values() for s in j["steps"]]


class ImageWorkflow(unittest.TestCase):
    def test_manual_trigger_only(self):
        on = load()[True]   # YAML 1.1 reads the key `on` as True
        self.assertEqual(sorted(on), ["workflow_dispatch"])

    def test_every_action_is_pinned_by_commit_sha(self):
        for s in steps(load()):
            if "uses" in s:
                self.assertRegex(s["uses"], r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", s["uses"])

    def test_panurus_source_is_pinned(self):
        text = open(WF).read()
        self.assertIn("--branch v0.24.0", text)
        self.assertIn("5f3c49e2d9e4507138ef330d34d60ec560fd1525", text)   # the same pin as rdbi.yml

    def test_sbom_and_max_provenance_on_the_pushed_image(self):
        bp = [s for s in steps(load()) if str(s.get("uses", "")).startswith("docker/build-push-action@")]
        self.assertEqual(len(bp), 1)
        w = bp[0]["with"]
        self.assertTrue(w["push"])
        self.assertTrue(w["sbom"])
        self.assertEqual(w["provenance"], "mode=max")
        self.assertEqual(w["file"], "panurus-itest/k8s/Dockerfile")
        self.assertRegex(w["tags"], r"^ghcr\.io/\$\{\{ github\.repository_owner \}\}/rdbi-node:sha-\$\{\{ github\.sha \}\}$")   # an immutable tag per commit, never :latest
        self.assertNotIn("latest", w["tags"])

    def test_signed_attestation_of_the_digest(self):
        at = [s for s in steps(load()) if str(s.get("uses", "")).startswith("actions/attest-build-provenance@")]
        self.assertEqual(len(at), 1)
        self.assertIn("steps.build.outputs.digest", at[0]["with"]["subject-digest"])
        self.assertTrue(at[0]["with"]["push-to-registry"])

    def test_permissions_are_the_minimum(self):
        wf = load()
        self.assertEqual(wf["permissions"], {"contents": "read"})
        job = list(wf["jobs"].values())[0]
        self.assertEqual(job["permissions"], {"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"})

    def test_tests_run_before_the_image_is_built(self):
        names = [s.get("name", s.get("uses", "")) for s in steps(load())]
        t = next(i for i, n in enumerate(names) if "go vet and go test" in n)
        b = next(i for i, n in enumerate(names) if n.startswith("docker/build-push-action"))
        self.assertLess(t, b)

    def test_digest_is_reported(self):
        self.assertIn("GITHUB_STEP_SUMMARY", open(WF).read())
        self.assertIn("steps.build.outputs.digest", open(WF).read())

    def test_checkout_keeps_no_credentials(self):
        co = [s for s in steps(load()) if str(s.get("uses", "")).startswith("actions/checkout@")]
        self.assertTrue(co and all(s["with"]["persist-credentials"] is False for s in co))


class Dockerfile(unittest.TestCase):
    def test_base_image_is_pinned_by_digest(self):
        froms = [l for l in open(DOCKERFILE) if l.startswith("FROM ")]
        self.assertEqual(len(froms), 1)
        self.assertRegex(froms[0], r"^FROM debian:bookworm-slim@sha256:[0-9a-f]{64}\s*$")

    def test_runs_as_uid_10001(self):
        self.assertIn("USER 10001", open(DOCKERFILE).read())


if __name__ == "__main__":
    unittest.main()
