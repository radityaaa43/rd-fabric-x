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
        bp = [s for s in steps(load()) if str(s.get("uses", "")).startswith("docker/build-push-action@") and s.get("with", {}).get("push")]
        self.assertEqual(len(bp), 1)
        w = bp[0]["with"]
        self.assertTrue(w["push"])
        self.assertTrue(w["sbom"])
        self.assertEqual(w["provenance"], "mode=max")
        self.assertEqual(w["file"], "panurus-itest/k8s/Dockerfile")
        self.assertRegex(w["tags"], r"^ghcr\.io/\$\{\{ github\.repository_owner \}\}/rdbi-node-ci:sha-\$\{\{ github\.sha \}\}$")   # an immutable tag per commit, never :latest
        self.assertNotIn("latest", w["tags"])

    def test_new_package_name_and_the_old_one_is_untouched(self):
        text = open(WF).read()
        self.assertNotRegex(text, r"ghcr\.io/\S*/rdbi-node(?!-ci)")   # never push, tag or attest the old registry package rdbi-node
        self.assertIn("ghcr.io/${{ github.repository_owner }}/rdbi-node-ci@${{ steps.build.outputs.digest }}", text)
        at = [s for s in steps(load()) if str(s.get("uses", "")).startswith("actions/attest-build-provenance@")][0]
        self.assertEqual(at["with"]["subject-name"], "ghcr.io/${{ github.repository_owner }}/rdbi-node-ci")

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
        b = next(i for i, n in enumerate(names) if n.startswith("docker/build-push-action") or "docker/build-push-action" in n)
        self.assertLess(t, b)

    def test_patch_set_is_checked_before_anything_is_patched(self):
        names = [s.get("name", s.get("uses", "")) for s in steps(load())]
        c = next(i for i, n in enumerate(names) if n.startswith("Check the patch set"))
        a = next(i for i, n in enumerate(names) if n.startswith("Patch Panurus"))
        self.assertLess(c, a)
        run = [s for s in steps(load()) if s.get("name", "").startswith("Check the patch set")][0]["run"]
        self.assertIn("sha256sum -c", run)
        self.assertIn("ACCEPTED.sha256", run)
        self.assertIn("GITHUB_STEP_SUMMARY", run)   # the list and the hashes are quoted in the run summary

    def test_image_is_scanned_for_private_keys_before_it_is_pushed(self):
        st = steps(load())
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
        self.assertIn("scan_image_keys.py", st[sc]["run"])

    def test_ldd_check_does_not_pipe_ldd(self):
        # run 43082625860 failed here: `ldd bin | grep -q "not a dynamic executable"` under pipefail fails because ldd itself exits 1 for a static binary.
        run = [s for s in steps(load()) if s.get("name", "").startswith("Build rdbi-node and rdbi-driver")][0]["run"]
        self.assertNotRegex(run, r"ldd[^\n|]*\|(?!\|)")   # a single pipe after ldd (|| is fine)
        self.assertIn('|| true)', run)                        # ldd's own exit status is ignored ...
        self.assertIn('grep -q "not a dynamic executable" <<<', run)   # ... and the verdict is a plain command, so -e still fails the step on a dynamic binary

    def test_signed_attestation_only_where_github_offers_it(self):
        # run 43083952563: `Failed to persist attestation: Feature not available for user-owned private repositories`. The image, SBOM and BuildKit
        # provenance were already pushed; the signed attestation is conditional on a non-private repository, and the digest report must not depend on it.
        st = steps(load())
        at = [s for s in st if str(s.get("uses", "")).startswith("actions/attest-build-provenance@")][0]
        self.assertEqual(at["if"], "${{ github.event.repository.private == false }}")
        rep = [s for s in st if s.get("name") == "Report the digest"][0]
        self.assertNotIn("if", rep)   # runs after the push even when the attestation is skipped
        self.assertIn("steps.build.outputs.digest", rep["run"])
        self.assertIn("no signed attestation", open(WF).read())   # the gap is stated where it happens

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
