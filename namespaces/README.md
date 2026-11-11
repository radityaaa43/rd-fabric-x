# namespaces: fabricx S1 (cluster 1)

Manifests for `rd-fabricx-bi`, `rd-fabricx-bank-a`, `rd-fabricx-bank-b` (final-design/fabricx/PLAN.md S1).
Per namespace: labels, 3 NetworkPolicies, ServiceAccount/Role/RoleBinding `party-admin`. No workloads, PVCs or CAs.

    python3 namespaces/render.py bi|bank-a|bank-b          # stdout only
    python3 -m unittest discover -s namespaces             # offline, needs PyYAML

`bank-c` is refused: its namespace is on cluster 2 (separate GO). Apply happens only in a window opened by `lead`.
Egress: `allow-dns-egress` selects every pod, so egress is limited to DNS (kube-system:53) and the same namespace until S11/S13 add rules.
`secrets` has no `get`: `kubectl create`/`replace` work, `kubectl apply` of a Secret does not.
