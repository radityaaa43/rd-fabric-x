#!/usr/bin/env python3
"""Rule (orchestrator, 2026-11-12): no script reads a Secret's content into the client. Names-only = `kubectl get secret[s]` (default table) or `-o name`.
`-o json|yaml|jsonpath|go-template|custom-columns` and `describe secret` on a Secret bring the values into the client. Value comparisons run in-pod, in the owner's namespace.
This test scans every tracked-style python/shell file (tests and .worktrees excluded) line by line.

  python3 -m unittest discover -s panurus-itest/scripts -p 'test_no_secret_value_reads.py'
"""
import os, re, unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VALUE_FLAG = re.compile(r"""(-o\s*=?\s*['"]?(json|yaml|jsonpath|go-template|custom-columns)|["']-o["']\s*,\s*["'](json|yaml|jsonpath|go-template|custom-columns)|--output\s*=?\s*(json|yaml|jsonpath|go-template)|jsonpath=|go-template=)""")
SECRET = re.compile(r"""(\bget\b|["']get["'])[^\n]*\bsecrets?\b|kubectl_json\(\s*["']secret["']|\bdescribe\b[^\n]*\bsecrets?\b|["']describe["']\s*,\s*["']secrets?["']""")


def offenders():
    bad = []
    for d, dirs, files in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in (".git", ".worktrees", "node_modules")]
        for f in files:
            if not f.endswith((".py", ".sh")) or f.startswith("test_"):
                continue
            p = os.path.join(d, f)
            for n, line in enumerate(open(p, errors="replace"), 1):
                if line.lstrip().startswith("#"):
                    continue
                if SECRET.search(line) and (VALUE_FLAG.search(line) or re.search(r"\bdescribe\b", line) or "kubectl_json" in line):
                    bad.append(f"{os.path.relpath(p, ROOT)}:{n}: {line.strip()[:120]}")
    return bad


class NoSecretValueReads(unittest.TestCase):
    def test_no_script_reads_secret_values(self):
        self.assertEqual(offenders(), [])

    def test_detector_sees_the_known_forms(self):
        for line in ('kubectl("get", "secret", "x", "-o", "json")', "kubectl get secret x -o jsonpath='{.data.a}'", "kubectl -n a get secrets -o go-template='{{.}}'",
                     "kubectl describe secret x", 'subprocess.check_output(["kubectl", "-n", "a", "get", "secret", n, "-o", "json"])', 'kubectl_json("secret", ca)'):
            self.assertTrue(SECRET.search(line) and (VALUE_FLAG.search(line) or "describe" in line or "kubectl_json" in line), line)
        for line in ("kubectl get secret -o name", "kubectl get secrets", 'kubectl("get", "secret", "ghcr-pull")', "kubectl get cm x -o json"):
            self.assertFalse(SECRET.search(line) and (VALUE_FLAG.search(line) or "describe" in line or "kubectl_json" in line), line)


if __name__ == "__main__":
    unittest.main()
