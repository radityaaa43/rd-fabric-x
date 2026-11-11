#!/usr/bin/env python3
"""Print the LoadBalancer Service of one party (fabricx S16; stdout only, nothing is applied, no cluster).

usage: render.py bi|bank-a|bank-b|bank-c --acl-id acl-<id> --source-range <ipv4>/32 [--source-range <ipv4>/32 ...] [--per-role]
Default (decided): ONE Service `lb-<N>` in rd-fabricx-<party> carrying the four listeners (assembler 8011, consenter 8012, router 8013,
batcher1 8014; PORT_PLAN), externalTrafficPolicy Local + scheduler wrr. --per-role: the documented option, four Services `lb-<role>-<N>`.
ACL-first: the Alibaba Cloud CLB access control list (white) is named in the annotations, so the listener is never open;
--acl-id and at least one /32 source range (the peer cluster's egress address) are required, anything wider is refused.
The ACL object must already exist (see RUNBOOK-LB.md). Annotation names: ACK managed "configure CLB using annotations" page.
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


def render(party, acl_id, ranges, per_role=False):
    if party not in PARTY_N:
        sys.exit(f"render.py: party {party!r} unknown; use one of {', '.join(PARTY_N)}")
    if not acl_id or not re.fullmatch(r"acl-[a-z0-9]+", acl_id):
        sys.exit(f"render.py: --acl-id {acl_id!r} must look like acl-abc123 (ACL-first: no LB without an access control list)")
    if not ranges:
        sys.exit("render.py: at least one --source-range <ipv4>/32 is required")
    ranges = list(dict.fromkeys(check_range(r) for r in ranges))   # de-duplicated, order kept
    n, ns = PARTY_N[party], f"rd-fabricx-{party}"

    def service(name, roles):
        return {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": ns,
                         "labels": {"app.kubernetes.io/part-of": "rd-fabricx", "party": party},
                         "annotations": {A + "acl-status": "on", A + "acl-id": acl_id, A + "acl-type": "white", A + "address-type": "internet",
                                         # Local mounts only the nodes where the pods run and, per the ACK CLB page, needs the wrr scheduler
                                         A + "scheduler": "wrr"}},
            "spec": {"type": "LoadBalancer", "externalTrafficPolicy": "Local", "loadBalancerSourceRanges": ranges,
                     # S11 pod contract: the four Arma role pods of the party carry these labels and declare NAMED container ports
                     # router/batcher1/consenter/assembler. A named targetPort sends a port only to the pods that declare it.
                     # [unverified until S11 pods exist]
                     "selector": {"app.kubernetes.io/part-of": "rd-fabricx", "party": party, "rd-fabricx/arma": "true"},
                     "ports": [{"name": r, "port": PORT_PLAN[r], "targetPort": r, "protocol": "TCP"} for r in roles]}}

    if per_role:   # documented option: four Services, four CLBs
        return yaml.safe_dump_all([service(f"lb-{r}-{n}", [r]) for r in PORT_PLAN], sort_keys=False)
    return yaml.safe_dump_all([service(f"lb-{n}", list(PORT_PLAN))], sort_keys=False)   # decided: one Service, one CLB, four listeners


if __name__ == "__main__":
    p = argparse.ArgumentParser(usage=__doc__, allow_abbrev=False)
    p.add_argument("party")
    p.add_argument("--acl-id")
    p.add_argument("--source-range", action="append", default=[])
    p.add_argument("--per-role", action="store_true")
    a = p.parse_args()
    sys.stdout.write(render(a.party, a.acl_id, a.source_range, a.per_role))
