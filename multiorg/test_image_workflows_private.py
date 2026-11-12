"""Static check (public repo rule): every workflow that pushes a package asserts, after the push, that the package is NOT publicly pullable, and fails the job otherwise. No network.

  python3 -m unittest discover -s multiorg
"""
import os, unittest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGES = {"tools-image.yml": "fabricx-tools-ci", "fsc-reenroll-image.yml": "fsc-reenroll-ci", "fsc-sqlite-image.yml": "fsc-sqlite-ci", "rdbi-image.yml": "rdbi-node-ci"}
STEP = "Assert the package is private"


class PackagePrivate(unittest.TestCase):
    def steps(self, wf):
        with open(os.path.join(ROOT, ".github", "workflows", wf)) as f:
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
            self.assertIn("401|403|404", run, wf)                  # private = refused anonymously; anything else (200, 5xx, no answer) fails closed
            self.assertIn("exit 1", run, wf)
            self.assertNotIn("secrets.", run, wf)                  # anonymous request: no credential in the check

    def test_the_four_pushing_workflows_are_all_covered(self):
        pushing = []
        wfdir = os.path.join(ROOT, ".github", "workflows")
        for wf in sorted(os.listdir(wfdir)):
            if "push: true" in open(os.path.join(wfdir, wf)).read():
                pushing.append(wf)
        self.assertEqual(pushing, sorted(PACKAGES))


if __name__ == "__main__":
    unittest.main()
