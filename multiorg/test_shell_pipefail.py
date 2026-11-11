"""Every shell script of the repo sets pipefail (live S16: `cmd | cut` hid a failing step's exit status and a loop went on after an error stop; the same bug made rdbi-image run 1 pass a failed key scan).

  python3 -m unittest discover -s multiorg
"""
import os, re, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP = (".git", ".work", ".worktrees", "node_modules")


def scripts():
    for d, dirs, files in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in SKIP]
        for f in files:
            if f.endswith(".sh"):
                yield os.path.join(d, f)


class Pipefail(unittest.TestCase):
    def test_every_shell_script_sets_pipefail(self):
        found = list(scripts())
        self.assertTrue(found)
        for p in found:
            head = "".join(open(p).readlines()[:30])
            self.assertRegex(head, r"set\s+-[a-z]*o\s+pipefail|set\s+-[a-z]*e[a-z]*u?o\s+pipefail|set -euo pipefail", os.path.relpath(p, ROOT))


if __name__ == "__main__":
    unittest.main()
