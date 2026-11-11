#!/usr/bin/env python3
"""Print the Role + RoleBinding that let BI's OWN party credential run reconcile.py (fabricx S17, analyst Q18). stdout only, nothing is applied.

usage: reconcile_role.py --fsc-pod rdbi-bi-<hash>-<id>
Role `reconcile` in rd-fabricx-bi: verbs EXACTLY `get` on pods and `create` on pods/exec, on exactly two pod names (committer-db-0 and the current FSC pod), no list, no watch,
no wildcard, nothing else. RoleBinding subject: the ServiceAccount party-admin of rd-fabricx-bi (BI's own party credential) only. The FSC pod is a Deployment pod whose name
changes at every rollout, so this is re-rendered and re-applied as a step of every FSC rollout; a reconcile that fails after a rollout is "Role stale", never retried under
cluster-admin."""
import argparse, re, sys
import yaml

NS = "rd-fabricx-bi"
LABELS = {"app.kubernetes.io/part-of": "rd-fabricx"}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fsc-pod", required=True)
    a = ap.parse_args()
    if not re.fullmatch(r"rdbi-bi-[a-z0-9]+-[a-z0-9]+", a.fsc_pod):
        sys.exit(f"reconcile_role.py: --fsc-pod {a.fsc_pod!r} must be the BI FSC pod name rdbi-bi-<hash>-<id>")
    names = ["committer-db-0", a.fsc_pod]
    meta = {"name": "reconcile", "namespace": NS, "labels": LABELS}
    docs = [{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta,
             "rules": [{"apiGroups": [""], "resources": ["pods"], "resourceNames": names, "verbs": ["get"]},
                       {"apiGroups": [""], "resources": ["pods/exec"], "resourceNames": names, "verbs": ["create"]}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": meta,
             "subjects": [{"kind": "ServiceAccount", "name": "party-admin", "namespace": NS}],
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reconcile"}}]
    sys.stdout.write(yaml.safe_dump_all(docs, sort_keys=False))


if __name__ == "__main__":
    main()
