#!/usr/bin/env python3
"""Print the four per-role LoadBalancer Services of one party (fabricx S16 input; stdout only, nothing is applied, no cluster).

usage: render.py bi|bank-a|bank-b|bank-c --acl-id acl-<id> --source-range <ipv4>/32 [--source-range <ipv4>/32 ...]
One Service `lb-<role>-<N>` per Arma role (assembler, consenter, router, batcher1) in rd-fabricx-<party>, port = PORT_PLAN[role].
ACL-first: the Alibaba Cloud CLB access control list (white) is named in the annotations, so the listener is never open;
--acl-id and at least one /32 source range (the peer cluster's egress address) are required, anything wider is refused.
The ACL object must already exist (see RUNBOOK-LB.md). Annotation names: Alibaba Cloud ACK "use annotations to configure load balancing".
"""
import argparse, ipaddress, os, re, sys
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fca"))
from enroll import PARTY_N, PORT_PLAN   # single source of the ports (ADR 0001), as the S10 runbook says

A = "service.beta.kubernetes.io/alibaba-cloud-loadbalancer-"


def check_range(r):
    try:
        net = ipaddress.IPv4Network(r, strict=True)
    except ValueError:
        sys.exit(f"render.py: source range {r!r} is not an IPv4 CIDR")
    if net.prefixlen != 32 or "/" not in r:
        sys.exit(f"render.py: source range {r!r} must be a single host /32 (the peer cluster's egress address), nothing wider")
    return str(net)


def render(party, acl_id, ranges):
    if party not in PARTY_N:
        sys.exit(f"render.py: party {party!r} unknown; use one of {', '.join(PARTY_N)}")
    if not acl_id or not re.fullmatch(r"acl-[a-z0-9]+", acl_id):
        sys.exit(f"render.py: --acl-id {acl_id!r} must look like acl-abc123 (ACL-first: no LB without an access control list)")
    if not ranges:
        sys.exit("render.py: at least one --source-range <ipv4>/32 is required")
    ranges = list(dict.fromkeys(check_range(r) for r in ranges))   # de-duplicated, order kept
    n, ns = PARTY_N[party], f"rd-fabricx-{party}"
    docs = []
    for role, port in PORT_PLAN.items():
        docs.append({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": f"lb-{role}-{n}", "namespace": ns,
                         "labels": {"app.kubernetes.io/part-of": "rd-fabricx", "party": party},
                         "annotations": {A + "acl-status": "on", A + "acl-id": acl_id, A + "acl-type": "white", A + "address-type": "internet"}},
            "spec": {"type": "LoadBalancer", "loadBalancerSourceRanges": ranges,
                     # [unverified] the S11 role pods do not exist yet; this selector assumes they will carry app.kubernetes.io/name: <role>-<N>
                     "selector": {"app.kubernetes.io/name": f"{role}-{n}"},
                     "ports": [{"name": role, "port": port, "targetPort": port, "protocol": "TCP"}]}})
    return yaml.safe_dump_all(docs, sort_keys=False)


if __name__ == "__main__":
    p = argparse.ArgumentParser(usage=__doc__, allow_abbrev=False)
    p.add_argument("party")
    p.add_argument("--acl-id")
    p.add_argument("--source-range", action="append", default=[])
    a = p.parse_args()
    sys.stdout.write(render(a.party, a.acl_id, a.source_range))
