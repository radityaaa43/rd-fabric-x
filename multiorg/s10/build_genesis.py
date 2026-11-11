#!/usr/bin/env python3
"""Build the Arma genesis block from the four orgs' PUBLIC exchange trees (fabricx S10 prep; no cluster, no key read).

usage: build_genesis.py --exchange DIR --armageddon BIN --sample-config DIR --out DIR --heads 1=<sha256>,2=...
DIR holds org1..org4 (output of multiorg/fca/enroll.py). BIN is armageddon built from hyperledger/fabric-x-orderer@dd296e3 and
--sample-config its testutil/fabric/sampleconfig. --heads (required on the command line) are the sha256 of each org's MANIFEST.sha256 as the org announced it.
Steps: check_exchange on every org (refuse otherwise) -> certs-only baseDir -> shared_config.yaml from endpoints.yaml (Consensus,
Batching and MaxPartyID are copied from upstream's own `generate` output, run in a scratch dir with throwaway keys that is shredded)
-> `createBlock` run INSIDE baseDir (its shared-config paths resolve against the CWD) -> prints the block's sha256 as JSON.
"""
import glob, hashlib, json, os, re, shutil, subprocess, sys
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import check_exchange

TEMPLATE_HOSTS = "{role}-{n}.example.invalid"


def die(msg):
    sys.exit(f"build_genesis.py: {msg}")


def sha256_file(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def shred_tree(root):
    for d, _, names in os.walk(root):
        for x in names:
            subprocess.run(["shred", "-u", os.path.join(d, x)], check=False)
    shutil.rmtree(root)


def upstream_defaults(armageddon, sample, gen):
    """Consensus/Batching/MaxPartyID exactly as the pinned generator writes them; the generated keys are throwaway and shredded."""
    net = {"Parties": [{"ID": n, "AssemblerEndpoint": f"a{n}.example.invalid:7050", "ConsenterEndpoint": f"c{n}.example.invalid:7051",
                        "RouterEndpoint": f"r{n}.example.invalid:7052", "BatchersEndpoints": [f"b{n}.example.invalid:7053"]} for n in (1, 2, 3, 4)],
           "UseTLSRouter": "mTLS", "UseTLSAssembler": "mTLS", "MaxPartyID": 4}
    os.makedirs(gen, mode=0o700)
    try:
        with open(f"{gen}/net.yaml", "w") as f:
            yaml.safe_dump(net, f)
        subprocess.run([armageddon, "generate", f"--config={gen}/net.yaml", f"--output={gen}/o", f"--sampleConfigPath={sample}"],
                       check=True, capture_output=True, text=True)
        with open(f"{gen}/o/bootstrap/shared_config.yaml") as f:
            sc = yaml.safe_load(f)
        return {k: sc[k] for k in ("Consensus", "Batching", "MaxPartyID")}
    except subprocess.CalledProcessError as e:
        die(f"armageddon generate failed: {(e.stderr or '')[-300:]}")
    finally:
        shred_tree(gen)


def party_config(exchange, base, n):
    org = f"crypto/ordererOrganizations/org{n}"
    rel = lambda p: os.path.relpath(p, base)
    pick = lambda pattern: rel(sorted(glob.glob(f"{base}/{org}/{pattern}"))[0])
    ep = yaml.safe_load(open(f"{exchange}/org{n}/endpoints.yaml"))
    role = lambda r: f"{org}/orderers/party{n}/{r}"
    batchers = sorted(r for r in ep if r.startswith("batcher"))
    return {"PartyID": n, "CACerts": [pick("msp/cacerts/*.pem")], "TLSCACerts": [pick("msp/tlscacerts/*.pem")],
            "RouterConfig": {"TLSCert": f"{role('router')}/tls/server.crt", "Host": ep["router"]["Host"], "Port": ep["router"]["Port"]},
            "BatchersConfig": [{"ShardID": k, "SignCert": f"{role(r)}/msp/signcerts/{r}-cert.pem", "TLSCert": f"{role(r)}/tls/server.crt",
                                "Host": ep[r]["Host"], "Port": ep[r]["Port"]} for k, r in enumerate(batchers, 1)],
            "ConsenterConfig": {"SignCert": f"{role('consenter')}/msp/signcerts/consenter-cert.pem", "TLSCert": f"{role('consenter')}/tls/server.crt",
                                "Host": ep["consenter"]["Host"], "Port": ep["consenter"]["Port"]},
            "AssemblerConfig": {"TLSCert": f"{role('assembler')}/tls/server.crt", "Host": ep["assembler"]["Host"], "Port": ep["assembler"]["Port"]}}


def build(exchange, armageddon, sample, out, manifest_heads=None):
    parties = sorted(int(d[3:]) for d in os.listdir(exchange) if re.fullmatch(r"org\d+", d))
    if len(parties) < 4 or parties != list(range(1, len(parties) + 1)):
        die(f"need org1..orgN with N >= 4 in {exchange}, found {parties}")
    for n in parties:
        found = check_exchange.problems(f"{exchange}/org{n}", n)
        if found:
            die(f"org{n} exchange tree is not clean: {'; '.join(found[:5])}")
        if manifest_heads is not None and manifest_heads.get(n) != sha256_file(f"{exchange}/org{n}/MANIFEST.sha256"):
            die(f"org{n}: MANIFEST.sha256 hash differs from the one the org announced")
    if os.path.exists(out) and os.listdir(out):
        die(f"{out} exists and is not empty")
    base, block = os.path.realpath(f"{out}/base"), os.path.realpath(f"{out}/block")
    os.makedirs(base, mode=0o700, exist_ok=True)
    os.makedirs(block, mode=0o700, exist_ok=True)
    for n in parties:   # certificates only: the checker already refused keys; MANIFEST and endpoints are not crypto material
        shutil.copytree(f"{exchange}/org{n}", f"{base}/crypto/ordererOrganizations/org{n}", ignore=shutil.ignore_patterns("MANIFEST.sha256", "endpoints.yaml"))
    leak = subprocess.run(["grep", "-rl", "PRIVATE KEY", base], capture_output=True, text=True).stdout
    if leak:
        die(f"private key material below baseDir: {leak.split()[0]}")
    shared = {"Parties": [party_config(exchange, base, n) for n in parties], **upstream_defaults(armageddon, os.path.realpath(sample), f"{out}/gen")}
    os.makedirs(f"{base}/bootstrap", exist_ok=True)
    with open(f"{base}/bootstrap/shared_config.yaml", "w") as f:
        yaml.safe_dump(shared, f, sort_keys=False)
    r = subprocess.run([armageddon, "createBlock", "--sharedConfigYaml=bootstrap/shared_config.yaml", "--baseDir=.",
                        f"--blockOutput={block}", f"--sampleConfigPath={os.path.realpath(sample)}"], cwd=base, capture_output=True, text=True)
    if r.returncode:
        die(f"createBlock failed (rc {r.returncode}): {r.stderr[-400:]}")
    return {"parties": parties, "block": f"{block}/bootstrap.block", "sha256": sha256_file(f"{block}/bootstrap.block")}


if __name__ == "__main__":
    a, opt = sys.argv[1:], {}
    while len(a) >= 2 and a[0].startswith("--"):
        opt[a[0]], a = a[1], a[2:]
    if a or not {"--exchange", "--armageddon", "--sample-config", "--out"} <= set(opt):
        sys.exit(__doc__)
    if "--heads" not in opt:   # the announced hashes are the only link to what each org really sent: no build without them
        die("--heads is required (sha256 of each org's MANIFEST.sha256 as announced by the org): 1=<hex>,2=<hex>,...")
    try:
        heads = {int(k): v for k, v in (kv.split("=") for kv in opt["--heads"].split(","))}
    except ValueError:
        die("--heads must look like 1=<sha256>,2=<sha256>,...")
    print(json.dumps(build(opt["--exchange"], opt["--armageddon"], opt["--sample-config"], opt["--out"], heads), indent=1))
