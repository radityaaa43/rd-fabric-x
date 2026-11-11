# namespaces: fabricx S1 (cluster 1)

Manifests for `rd-fabricx-bi`, `rd-fabricx-bank-a`, `rd-fabricx-bank-b` (final-design/fabricx/PLAN.md S1).
Per namespace: labels, 3 NetworkPolicies, ServiceAccount/Role/RoleBinding `party-admin`. No workloads, PVCs or CAs.

    python3 namespaces/render.py bi|bank-a|bank-b          # stdout only
    python3 -m unittest discover -s namespaces             # offline, needs PyYAML

## Cluster 2 (bank C): two separate GOs, nothing here applies to cluster 2 by itself

Sources: final-design/fabricx/PLAN.md S1 (cluster-2 sub-step: "create ns `rd-fabricx-bank-c` ONLY, no workloads", DELTA 2) and S18; GO L0-SG.
`KUBECONFIG_C2` is a shell variable holding the cluster-2 kubeconfig path, supplied by the user; never write the path into a file or PR.

    # GO 1: the first cluster-2 write, the Namespace object only
    python3 namespaces/render.py --cluster 2 --ns-only bank-c | kubectl --kubeconfig "$KUBECONFIG_C2" apply -f -
    # GO 2: the other 6 objects (NetworkPolicies, ServiceAccount, Role, RoleBinding), after GO 1 is verified
    python3 namespaces/render.py --cluster 2 bank-c | kubectl --kubeconfig "$KUBECONFIG_C2" apply -f -
    # rollback (namespace is empty at this point; user-only)
    kubectl --kubeconfig "$KUBECONFIG_C2" delete ns rd-fabricx-bank-c

`bank-c` is refused without `--cluster 2`, and `--cluster 2` accepts only `bank-c`. Cluster-1 output is unchanged. Apply happens only in a window opened by `lead`.
Egress: `allow-dns-egress` selects every pod and allows egress to anything (L0, as PLAN S1); S11/S13 tighten it.
`secrets` has no `get` by design: use `kubectl create` / `replace`; `kubectl apply` of a Secret fails.
