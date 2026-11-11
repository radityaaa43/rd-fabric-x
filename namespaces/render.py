#!/usr/bin/env python3
"""Print the fabricx S1 namespace manifests of one cluster-1 party (stdout only: no kubectl, no cluster).

usage: render.py bi|bank-a|bank-b | kubectl apply -f -      (apply only inside "WINDOW OPEN fabricx S1")
bank-c is refused: its namespace lives on cluster 2, a separate GO (final-design/fabricx/PLAN.md S1 cluster-2 sub-step, S18).
"""
import os, string, sys

HERE = os.path.dirname(os.path.abspath(__file__))
PARTIES = ("bi", "bank-a", "bank-b")
TEMPLATES = ("namespace.yaml", "networkpolicies.yaml", "rbac.yaml")


def render(party):
    if party == "bank-c":
        sys.exit("render.py: bank-c is refused: its namespace is on cluster 2, a separate GO (fabricx S1 cluster-2 sub-step, S18)")
    if party not in PARTIES:
        sys.exit(f"render.py: unknown party {party!r}; use one of {', '.join(PARTIES)}")
    sub = {"PARTY": party, "NS": f"rd-fabricx-{party}"}
    out = []
    for name in TEMPLATES:
        with open(os.path.join(HERE, "templates", name)) as f:
            out.append(string.Template(f.read()).substitute(sub).strip("\n"))
    return "\n---\n".join(out) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.stdout.write(render(sys.argv[1]))
