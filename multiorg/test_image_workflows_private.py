"""Static check (public repo rule): every workflow that pushes a package asserts, after the push, that the package is NOT publicly pullable, and fails the job otherwise. No network.

  python3 -m unittest discover -s multiorg
"""
import os, unittest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF_DIR = os.environ.get("WF_DIR") or os.path.join(ROOT, ".github", "workflows")   # WF_DIR lets the RED run point at the old workflow files
PACKAGES = {"tools-image.yml": "fabricx-tools-ci", "fsc-reenroll-image.yml": "fsc-reenroll-ci", "fsc-sqlite-image.yml": "fsc-sqlite-ci", "rdbi-image.yml": "rdbi-node-ci"}
STEP = "Assert the package is private"


class PackagePrivate(unittest.TestCase):
    def steps(self, wf):
        with open(os.path.join(WF_DIR, wf)) as f:
            (job,) = yaml.safe_load(f)["jobs"].values()
        return job["steps"]

    def test_every_pushing_workflow_asserts_private_after_the_push_and_before_the_report(self):
        for wf, pkg in PACKAGES.items():
            st = self.steps(wf)
            names = [s.get("name") for s in st]
            self.assertIn(STEP, names, wf)
            i, b, r = names.index(STEP), [k for k, s in enumerate(st) if s.get("id") == "build"][0], names.index("Report the digest")
            self.assertTrue(b < i < r, wf)
            s = st[i]
            self.assertEqual(s["env"], {"PKG": pkg, "DIGEST": "${{ steps.build.outputs.digest }}"}, wf)
            run = s["run"]
            self.assertIn("https://ghcr.io/token?scope=repository:", run, wf)
            self.assertIn("/manifests/${DIGEST}", run, wf)
            self.assertNotIn("${{", run, wf)                       # values come through env, never interpolated into the script
            self.assertIn("401|403)", run, wf)                     # private = refused anonymously; 404 (unknown package, token endpoint answers 403 too), 200, 5xx, no answer: all fail closed
            self.assertNotIn("404", run.split("case")[1].split("esac")[0].split("*)")[0], wf)
            self.assertIn("exit 1", run, wf)
            self.assertNotIn("secrets.", run, wf)                  # anonymous request: no credential in the check

    def test_assert_and_pull_test_come_before_the_attestation_so_a_red_attest_cannot_skip_them(self):
        for wf, pkg in PACKAGES.items():
            st = self.steps(wf)
            names = [s.get("name") or s.get("uses", "") for s in st]
            b = [k for k, s in enumerate(st) if s.get("id") == "build"][0]
            a = names.index(STEP)
            pulls = [k for k, s in enumerate(st) if s.get("name", "").startswith("Pull test")]
            att = [k for k, s in enumerate(st) if "attest-build-provenance" in s.get("uses", "")]
            rep = names.index("Report the digest")
            self.assertEqual(len(pulls), 1, wf)
            self.assertEqual(len(att), 1, wf)
            self.assertTrue(b < a < pulls[0] < att[0] < rep, f"{wf}: want build < assert < pull test < attest < report, got {b} {a} {pulls[0]} {att[0]} {rep}")

    def test_pull_test_is_authenticated_by_digest_fail_closed_and_prints_the_image_id(self):
        for wf, pkg in PACKAGES.items():
            (s,) = [s for s in self.steps(wf) if s.get("name", "").startswith("Pull test")]
            self.assertEqual(s["env"], {"PKG": pkg, "DIGEST": "${{ steps.build.outputs.digest }}"}, wf)
            run = s["run"]
            self.assertIn("set -euo pipefail", run, wf)
            self.assertIn('ref="ghcr.io/${GITHUB_REPOSITORY_OWNER,,}/${PKG}@${DIGEST}"', run, wf)      # by DIGEST, never by tag
            self.assertIn('docker pull "$ref"', run, wf)
            self.assertIn("docker image inspect", run, wf)
            self.assertIn("GITHUB_STEP_SUMMARY", run, wf)                                              # the imageID is printed for the later GO text
            self.assertIn('test "$id" = "$DIGEST"', run, wf)                                           # imageID must EQUAL the pushed digest
            self.assertNotIn("${{", run, wf)
            names = [x.get("name") or x.get("uses", "") for x in self.steps(wf)]
            self.assertTrue(any("docker/login-action" in n for n in names[:names.index(s["name"])]), wf)   # authenticated: the login step comes first

    def test_the_four_pushing_workflows_are_all_covered(self):
        pushing = []
        wfdir = WF_DIR
        for wf in sorted(os.listdir(wfdir)):
            if "push: true" in open(os.path.join(wfdir, wf)).read():
                pushing.append(wf)
        self.assertEqual(pushing, sorted(PACKAGES))


class AnyAttestingWorkflow(unittest.TestCase):
    """Hygiene over EVERY workflow file (also future ones): a job that attests provenance has id-token + attestations write, and a job that pushes a package runs the anonymous private assert and
    the authenticated pull test BEFORE the attest step (a red attest must never skip the visibility proof)."""

    def jobs(self):
        for f in sorted(os.listdir(WF_DIR)):
            if f.endswith((".yml", ".yaml")):
                with open(os.path.join(WF_DIR, f)) as fh:
                    for name, job in (yaml.safe_load(fh).get("jobs") or {}).items():
                        yield f, name, job

    def test_attesting_jobs_have_the_permissions(self):
        seen = 0
        for f, name, job in self.jobs():
            if any("attest-build-provenance" in s.get("uses", "") for s in job.get("steps", [])):
                seen += 1
                perms = job.get("permissions") or {}
                self.assertEqual(perms.get("id-token"), "write", f"{f}:{name} attests but has no id-token: write")
                self.assertEqual(perms.get("attestations"), "write", f"{f}:{name} attests but has no attestations: write")
        self.assertGreaterEqual(seen, 4)

    def test_pushing_jobs_prove_private_and_pull_before_they_attest(self):
        seen = 0
        for f, name, job in self.jobs():
            st = job.get("steps", [])
            push = [k for k, s in enumerate(st) if (s.get("with") or {}).get("push") is True or "docker push" in s.get("run", "")]
            if not push:
                continue
            seen += 1
            pulled = [k for k, s in enumerate(st) if "docker pull" in s.get("run", "")]
            assert_ = [k for k, s in enumerate(st) if "ghcr.io/token" in s.get("run", "") or "assert-package-private" in s.get("run", "")]
            att = [k for k, s in enumerate(st) if "attest-build-provenance" in s.get("uses", "")]
            self.assertTrue(assert_ and pulled, f"{f}:{name} pushes a package without the private assert and the authenticated pull test")
            for a in att:
                self.assertTrue(min(assert_) < a and min(pulled) < a, f"{f}:{name}: the private assert and the pull test must run BEFORE the attest step")
        self.assertGreaterEqual(seen, 4)   # the four image workflows


if __name__ == "__main__":
    unittest.main()
