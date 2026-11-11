#!/usr/bin/env python3
"""Print the fabricx S1 namespace manifests of one party (stdout only: no kubectl, no cluster).

usage: render.py bi|bank-a|bank-b                 cluster 1 (pipe to kubectl apply -f - only inside a window opened by lead)
       render.py --cluster 2 bank-c               cluster 2: same objects, namespace label cluster="2"
bank-c is refused without --cluster 2, and --cluster 2 accepts only bank-c: its namespace is on cluster 2, a separate GO
(final-design/fabricx/PLAN.md S1 cluster-2 sub-step, S18). Never apply to cluster 2 without that GO and the cluster-2 kubeconfig.
"""
import os, string, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CLUSTER_PARTIES = {1: ("bi", "bank-a", "bank-b"), 2: ("bank-c",)}
TEMPLATES = ("namespace.yaml", "networkpolicies.yaml", "rbac.yaml")


def render(party, cluster=1):
    if cluster not in CLUSTER_PARTIES:
        sys.exit(f"render.py: unknown cluster {cluster!r}; use 1 or 2")
    if party == "bank-c" and cluster == 1:
        sys.exit("render.py: bank-c is refused without --cluster 2: its namespace is on cluster 2, a separate GO (fabricx S1 cluster-2 sub-step, S18)")
    if party not in CLUSTER_PARTIES[cluster]:
        sys.exit(f"render.py: party {party!r} is not on cluster {cluster}; use one of {', '.join(CLUSTER_PARTIES[cluster])}")
    sub = {"PARTY": party, "NS": f"rd-fabricx-{party}"}
    out = []
    for name in TEMPLATES:
        with open(os.path.join(HERE, "templates", name)) as f:
            out.append(string.Template(f.read()).substitute(sub).strip("\n"))
    text = "\n---\n".join(out) + "\n"
    if cluster == 2:  # cluster-1 output stays byte-identical to what S1 applied
        text = text.replace(f"    party: {party}\n", f'    party: {party}\n    cluster: "2"\n', 1)
    return text


if __name__ == "__main__":
    args, cluster = sys.argv[1:], 1
    if args[:1] == ["--cluster"] and len(args) >= 2:
        if not args[1].isdigit():
            sys.exit(f"render.py: --cluster takes 1 or 2, got {args[1]!r}")
        cluster, args = int(args[1]), args[2:]
    if len(args) != 1:
        sys.exit(__doc__)
    sys.stdout.write(render(args[0], cluster))
