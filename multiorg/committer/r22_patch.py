#!/usr/bin/env python3
"""Print the strategic-merge patch that applies R22 to ONE live committer StatefulSet, EXTRACTED from this directory's renderer (never typed by hand).
usage: r22_patch.py bi|bank-a|bank-b committer-db|committer-sidecar        stdout = compact JSON (sorted keys), stderr = `sha256 <hex> <workload> <party>`
Only the two fields the series changes are taken from the render: spec.template.metadata.labels["rd/role"] and spec.template.spec.affinity.podAntiAffinity.
The live object's other fields (nodeAffinity AVOID_NODES, image, env, volumes, selector) are not part of the patch. Only the state holders (RWO disks) are in the series;
the stateless helpers have a PREFERRED rule that arrives with their next template change, cluster 2 has no peers. Nothing is applied; usage: `kubectl patch statefulset <name> --type=strategic -p "$(r22_patch.py ...)"`."""
import hashlib, importlib.util, json, os, sys
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
_s = importlib.util.spec_from_file_location("committer_render", os.path.join(HERE, "render.py"))
render = importlib.util.module_from_spec(_s)
_s.loader.exec_module(render)

PARTIES = ("bi", "bank-a", "bank-b")
WORKLOADS = tuple(render.R22_STATE)


def patch(party, name):
    if party not in PARTIES:
        sys.exit(f"r22_patch.py: party {party!r} must be one of {', '.join(PARTIES)} (bank-c is on cluster 2: no peers)")
    if name not in WORKLOADS:
        sys.exit(f"r22_patch.py: workload {name!r} must be one of {', '.join(WORKLOADS)} (the state holders; helpers are PREFERRED only)")
    docs = [d for d in yaml.safe_load_all(render.render(party)) if d]
    (obj,) = [d for d in docs if d["kind"] == "StatefulSet" and d["metadata"]["name"] == name]
    tpl = obj["spec"]["template"]
    out = {"spec": {"template": {"metadata": {"labels": {"rd/role": tpl["metadata"]["labels"]["rd/role"]}},
                                 "spec": {"affinity": {"podAntiAffinity": tpl["spec"]["affinity"]["podAntiAffinity"]}}}}}
    return json.dumps(out, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__.split("\n")[1])
    p = patch(sys.argv[1], sys.argv[2])
    sys.stdout.write(p)
    print(f"sha256 {hashlib.sha256(p.encode()).hexdigest()} {sys.argv[2]} {sys.argv[1]}", file=sys.stderr)
