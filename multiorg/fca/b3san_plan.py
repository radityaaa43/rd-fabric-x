#!/usr/bin/env python3
"""Print (never run) the exact B3-SAN command list for the four orgs, so the GO text quotes it verbatim (fabricx S9 re-issue with LB SANs).

usage: b3san_plan.py --lb-host-template '{role}-{n}.lb.{party}' [--generation san1] [--ca-url http://localhost:7054]
The template is filled per role and party; until S16 gives the real LB hosts it is a placeholder. A template that still contains
`.lb.` is printed with a warning line: do not run it. No cluster access, no secrets: the commands read the CA admin password from W/admin.pass.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import enroll

KCFG = "$HOME/fabricx-party-kubeconfigs/rd-fabricx-{party}.kubeconfig"


def plan(template, generation="san1", ca_url="http://localhost:7054"):
    enroll.check_generation(generation)
    if "{role}" not in template and "{n}" not in template and "{party}" not in template:
        sys.exit("b3san_plan.py: the template must contain {role}, {n} or {party}: one LB host per role and party")
    out = []
    for party, n in enroll.PARTY_N.items():
        ns, w = f"rd-fabricx-{party}", f"/dev/shm/s9-{party}-{generation}"
        sans = []
        for role in enroll.ROLES:
            host = template.format(role=role, n=n, party=party)
            enroll.check_san(host)
            sans.append(f"--extra-san {role}={host}")
        k = KCFG.format(party=party)
        out += [f"# org{n} ({party})",
                f"# 1. operator, cluster-admin kubeconfig: read Secret fca-org{n}-admin into {w}/admin.pass (umask 077, mode 600); GO text must name this Secret read",
                f"kubectl --kubeconfig {k} -n {ns} port-forward svc/fca-org{n} 7054:7054 &",
                f"python3 -I multiorg/fca/enroll.py enroll {party} {ns} --kubeconfig {k} --ca-url {ca_url} --work {w} --out exchange-{generation}/org{n} " + " ".join(sans) + f" --generation {generation}",
                f"python3 -I multiorg/check_exchange.py exchange-{generation}/org{n} {n}",
                f"ls {w}   # must print: No such file or directory", ""]
    if ".lb." in template:
        out.insert(0, "# WARNING: placeholder LB hosts (.lb.): do NOT run this plan until S16 provides the real hosts")
    return "\n".join(out)


if __name__ == "__main__":
    a, opt = sys.argv[1:], {}
    while len(a) >= 2 and a[0].startswith("--"):
        opt[a[0]], a = a[1], a[2:]
    if a or "--lb-host-template" not in opt:
        sys.exit(__doc__)
    print(plan(opt["--lb-host-template"], opt.get("--generation", "san1"), opt.get("--ca-url", "http://localhost:7054")))
