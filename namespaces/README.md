# namespaces: fabricx S1 (cluster 1)

Manifests for `rd-fabricx-bi`, `rd-fabricx-bank-a`, `rd-fabricx-bank-b` (final-design/fabricx/PLAN.md S1).
Per namespace: labels, 3 NetworkPolicies, ServiceAccount/Role/RoleBinding `party-admin`. No workloads, PVCs or CAs.

    python3 namespaces/render.py bi|bank-a|bank-b          # stdout only
    python3 -m unittest discover -s namespaces             # offline, needs PyYAML

    python3 namespaces/render.py --cluster 2 bank-c       # cluster 2: same objects, label cluster="2"

`bank-c` is refused without `--cluster 2`, and `--cluster 2` accepts only `bank-c` (cluster 2 is a separate GO and kubeconfig). Cluster-1 output is unchanged. Apply happens only in a window opened by `lead`.
Egress: `allow-dns-egress` selects every pod and allows egress to anything (L0, as PLAN S1); S11/S13 tighten it.
`secrets` has no `get` by design: use `kubectl create` / `replace`; `kubectl apply` of a Secret fails.
