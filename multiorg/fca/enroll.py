#!/usr/bin/env python3
"""Enroll one party's four Arma roles at its own fca-org<N> and keep the keys only as Secrets (fabricx S9).

usage: enroll.py init   <party> rd-fabricx-<party> --kubeconfig K --work W
       enroll.py admin|endorser <party> rd-fabricx-<party> --kubeconfig K --ca-url http://localhost:7054 --work W --src <public tree> --dst <new tree> [--generation TAG]
       enroll.py enroll <party> rd-fabricx-<party> --kubeconfig K --ca-url http://localhost:7054 --work W --out exchange/org<N> [--extra-san <host|ip> | --extra-san <role>=<host|ip>]... [--generation TAG]
One org at a time (sequential): W under /dev/shm only (tmpfs, umask 077 set by the script); destroy W before the next org starts.
init creates the admin password Secret (apply render.py's CA manifest after it). enroll runs `fabric-ca-client` (msp + tls profile)
per role, writes Secrets `orderer-<role>-<N>-secret` with `kubectl create`, builds the public exchange tree, runs check_exchange,
then shreds W. `--generation TAG` (B3-SAN re-issue): role identities are registered as `<role>-<N>-TAG` (the first-run secrets were never stored and identities cannot be removed) and the SAME Secret names are overwritten with `kubectl replace`; it needs the CA admin password in W/admin.pass (see RUNBOOK-S9 section 9). `init` leaves admin.pass in W until `enroll` runs: if enroll never runs, shred W by hand. Private keys exist in W only between enroll and the Secret create: run it on the org's own host.
NOT run live yet: fabric-ca-client is not installed on the build host; the flow is a CLUSTER-OP step (GO B).
"""
import glob, hashlib, os, re, shutil, subprocess, sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import check_exchange

PARTY_N = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
ROLES = ("router", "batcher1", "consenter", "assembler")
# One port per role, from the upstream sample (orderer@dd296e3 deployment/vms/sample-config/config.yaml:8-13 and deployment/README.md:10):
# assembler 8011, consenter 8012, router 8013, batcher shards 8014+. Distinct per role so a per-party LB can also carry all four. Hosts and
# ports go into the genesis (ADR 0001): this table is the single source, and the S10 runbook points at it.
PORT_PLAN = {"assembler": 8011, "consenter": 8012, "router": 8013, "batcher1": 8014}
SECRET_ROLE = {"router": "router", "batcher1": "batcher", "consenter": "consenter", "assembler": "assembler"}


def check_target(party, ns):
    if party not in PARTY_N or ns != f"rd-fabricx-{party}":
        sys.exit(f"enroll.py: party {party!r} must be one of {', '.join(PARTY_N)} and the namespace rd-fabricx-<party>, got {ns!r}")
    return PARTY_N[party]


def check_work(work):
    """private keys only on tmpfs (/dev/shm), only readable by us: umask 077 is set here for everything that follows"""
    if not os.path.isabs(work) or os.path.normpath(work) != work or not work.startswith("/dev/shm/"):
        sys.exit(f"enroll.py: --work must be a normalized absolute path under /dev/shm/, got {work!r}")
    os.umask(0o077)
    return work


def check_san(x):
    import ipaddress
    if re.fullmatch(r"[0-9.]+", x):                      # dotted digits must be a real IPv4 address
        ipaddress.ip_address(x)
        return x
    try:
        return str(ipaddress.ip_address(x)) if ":" in x else _hostname(x)
    except ValueError:
        sys.exit(f"enroll.py: --extra-san {x!r} is neither a host name nor an IP address")


def _hostname(x):
    if len(x) > 253 or not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*", x):
        raise ValueError(x)
    return x


def parse_extra_sans(items):
    """--extra-san <host|ip> (all four roles of the party) or <role>=<host|ip> (that role only). Returns {role: [san, ...]}."""
    out = {r: [] for r in ROLES}
    for item in items:
        role, _, san = item.rpartition("=") if "=" in item else ("", "", item)
        if role and role not in ROLES:
            sys.exit(f"enroll.py: --extra-san role {role!r} must be one of {', '.join(ROLES)}")
        try:
            san = check_san(san)
        except ValueError:
            sys.exit(f"enroll.py: --extra-san {item!r} is neither a host name nor an IP address")
        for r in ([role] if role else ROLES):
            if san not in out[r]:
                out[r].append(san)
    return out


def check_generation(g):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,11}", g):
        sys.exit(f"enroll.py: --generation {g!r} must match [a-z0-9][a-z0-9-]{{0,11}}")
    return g


def first(pattern):
    found = sorted(glob.glob(pattern))
    if not found:
        sys.exit(f"enroll.py: nothing matches {pattern}")
    return found[0]


def read(p):
    with open(p) as f:
        return f.read()


def write(p, data):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(data)


def build(enrolled, exchange, n, ns, hosts, ports=None):
    ports = PORT_PLAN if ports is None else ports
    """enrolled/<role>/{msp,tls}/{signcerts,cacerts|tlscacerts,keystore} -> exchange tree (certs) + Secret manifests (keys).
    Names follow what the nodes read: msp/keystore/priv_sk (config/config.go:308), tls/server.{crt,key} (config/generate/local_config_gen.go:195-196)."""
    secrets, endpoints = [], {}
    base = f"{exchange}/orderers/party{n}"
    for role in ROLES:
        e = f"{enrolled}/{role}"
        sign, tls = read(first(f"{e}/msp/signcerts/*.pem")), read(first(f"{e}/tls/signcerts/*.pem"))
        ca, tlsca = read(first(f"{e}/msp/cacerts/*.pem")), read(first(f"{e}/tls/tlscacerts/*.pem"))
        write(f"{exchange}/msp/cacerts/ca.pem", ca)
        write(f"{exchange}/msp/tlscacerts/tlsca.pem", tlsca)
        write(f"{base}/{role}/tls/server.crt", tls)
        write(f"{base}/{role}/tls/ca.crt", tlsca)
        if role in ("batcher1", "consenter"):
            write(f"{base}/{role}/msp/signcerts/{role}-cert.pem", sign)
        endpoints[role] = {"Host": hosts[role], "Port": ports[role]}
        secrets.append({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                        "metadata": {"name": f"orderer-{SECRET_ROLE[role]}-{n}-secret", "namespace": ns},
                        "stringData": {"msp-keystore-priv_sk": read(first(f"{e}/msp/keystore/*_sk")),
                                       "msp-signcert.pem": sign, "tls-server.key": read(first(f"{e}/tls/keystore/*_sk")),
                                       "tls-server.crt": tls}})
    write(f"{exchange}/endpoints.yaml", yaml.safe_dump(endpoints))
    lines = sorted(f"{hashlib.sha256(open(p, 'rb').read()).hexdigest()}  {os.path.relpath(p, exchange)}\n"
                   for d, _, names in os.walk(exchange) for x in names if x != "MANIFEST.sha256" for p in [os.path.join(d, x)])
    write(f"{exchange}/MANIFEST.sha256", "".join(lines))
    return secrets


def scrub(text, secrets):
    for x in secrets:
        if x:
            text = text.replace(x, "***")
    return text


def sh(*cmd, stdin=None, env=None, secrets=()):
    """secrets never go on argv (visible in /proc/<pid>/cmdline and in CalledProcessError): callers pass them through env/stdin
    and list them here so a failure message, built from cmd[:3] and stderr only, is scrubbed of every one."""
    try:
        return subprocess.run(list(cmd), input=stdin, text=True, check=True, capture_output=True, env=env, stdin=None if stdin else subprocess.DEVNULL).stdout
    except subprocess.CalledProcessError as e:
        sys.exit(f"enroll.py: {scrub(' '.join(cmd[:3]), secrets)} failed (rc {e.returncode}): {scrub((e.stderr or '').strip()[-400:], secrets)}")
    except OSError as e:
        sys.exit(f"enroll.py: cannot run {cmd[0]}: {e.strerror}")


def init(party, ns, kubeconfig, work):
    """admin password -> work/admin.pass (600) and Secret fca-org<N>-admin; apply the CA manifest only after this."""
    n = check_target(party, ns)
    work = check_work(work)
    os.makedirs(work, mode=0o700, exist_ok=True)
    p = f"{work}/admin.pass"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(os.urandom(18).hex())
    sh("kubectl", "--kubeconfig", kubeconfig, "-n", ns, "create", "secret", "generic", f"fca-org{n}-admin", f"--from-file=password={p}")


def enroll(party, ns, kubeconfig, ca_url, work, out, extra_sans=(), generation="", replace_secrets=None):
    """needs `kubectl --kubeconfig K -n NS port-forward svc/fca-org<N> 7054` running (OPERATOR kubeconfig: the party-admin Role has no pods/portforward since 2026-11-12).
    Credentials travel only in the fabric-ca-client environment (FABRIC_CA_CLIENT_URL), never on a command line.
    [unverified live] that the client reads FABRIC_CA_CLIENT_URL and prints `Password: <x>` on a register without --id.secret
    (Fabric CA users guide): the window-start throwaway enroll settles it."""
    work = check_work(work)   # path guard first: destroy() below only ever touches a /dev/shm path
    secrets = []
    try:
        n = check_target(party, ns)
        sans = parse_extra_sans(extra_sans)
        gen = check_generation(generation) if generation else ""
        replace_secrets = bool(gen) if replace_secrets is None else replace_secrets
        pw = read(f"{work}/admin.pass").strip()
        secrets.append(pw)
        base_env = {**os.environ, "FABRIC_CA_CLIENT_HOME": f"{work}/client"}
        creds = lambda who, secret: {**base_env, "FABRIC_CA_CLIENT_URL": ca_url.replace("://", f"://{who}:{secret}@")}
        adminmsp = f"{work}/admin-msp"
        sh("fabric-ca-client", "enroll", "-M", adminmsp, env=creds("admin", pw), secrets=secrets)
        hosts = {r: f"{r}-{n}.{ns}.svc.cluster.local" for r in ROLES}
        for role in ROLES:
            who = f"{role}-{n}" + (f"-{gen}" if gen else "")   # B3-SAN: old secrets are gone and identities cannot be removed
            reg = sh("fabric-ca-client", "register", "-u", ca_url, "-M", adminmsp, "--id.name", who, "--id.type", "orderer",
                     env=base_env, secrets=secrets)
            m = re.search(r"Password:\s*(\S+)", reg)
            if not m:
                sys.exit(f"enroll.py: register of {who} printed no generated password")
            secrets.append(m.group(1))
            sh("fabric-ca-client", "enroll", "-M", f"{work}/enrolled/{role}/msp", "--csr.hosts", ",".join([hosts[role], *sans[role]]), env=creds(who, m.group(1)), secrets=secrets)
            sh("fabric-ca-client", "enroll", "-M", f"{work}/enrolled/{role}/tls", "--enrollment.profile", "tls", "--csr.hosts", ",".join([hosts[role], *sans[role]]),
               env=creds(who, m.group(1)), secrets=secrets)
        for s in build(f"{work}/enrolled", out, n, ns, hosts):   # create, never apply: party-admin may create/update/patch secrets but not get
            sh("kubectl", "--kubeconfig", kubeconfig, "replace" if replace_secrets else "create", "-f", "-", stdin=yaml.safe_dump(s), secrets=secrets)
        found = check_exchange.problems(out, n)
        if found:
            sys.exit("enroll.py: exchange tree is not clean:\n" + "\n".join(found))
    finally:  # keys never stay in /dev/shm, also on error
        destroy(work)


# One more CA identity per org, besides the four Arma roles. The cert goes into a COPY of the public tree, the key only into a Secret.
#   admin    (PLAN S8)  type admin,  msp/admincerts/admin-<N>-cert.pem,    Secret orderer-admin-<N>-secret: the org MSP's admin, or no config tx can be authorized
#   endorser (lead Q1)  type client, msp/knowncerts/endorser-<N>-cert.pem, Secret fsc-endorser-<N>-secret: FSC endorser cert for FabricMSPConfig.known_certs (S13 uses the key)
KINDS = {"admin": {"type": "admin", "dir": "admincerts", "secret": "orderer-admin-{n}-secret"},
         "endorser": {"type": "client", "dir": "knowncerts", "secret": "fsc-endorser-{n}-secret"}}


def identity(kind, party, ns, kubeconfig, ca_url, work, src, dst, generation=""):
    """Register and enroll <kind>-<N>[-gen] at the org's own CA; cert -> dst/msp/<dir>/<kind>-<N>-cert.pem (dst = a COPY of src with a new MANIFEST, must
    not exist); key + cert -> Secret (create; keys msp-keystore-priv_sk, msp-signcert.pem). Same custody rules as enroll(): credentials in the environment
    only, work dir under /dev/shm and destroyed in a finally (also on a refusal). Needs the CA admin password in W/admin.pass and a port-forward."""
    work = check_work(work)   # path guard first: destroy() below only ever touches a /dev/shm path
    secrets = []
    try:
        if kind not in KINDS:
            sys.exit(f"enroll.py: identity kind {kind!r} must be one of {', '.join(KINDS)}")
        k = KINDS[kind]
        n = check_target(party, ns)
        gen = check_generation(generation) if generation else ""
        if os.path.exists(dst):
            sys.exit(f"enroll.py: {dst} must be a new directory (the source tree is never modified)")
        found = check_exchange.problems(src, n)
        if found:
            sys.exit("enroll.py: source tree is not clean: " + "; ".join(found[:3]))
        if glob.glob(f"{src}/msp/{k['dir']}/*.pem"):
            sys.exit(f"enroll.py: the source tree already has msp/{k['dir']}: use a source tree without it")
        pw = read(f"{work}/admin.pass").strip()
        secrets.append(pw)
        base_env = {**os.environ, "FABRIC_CA_CLIENT_HOME": f"{work}/client"}
        creds = lambda who, secret: {**base_env, "FABRIC_CA_CLIENT_URL": ca_url.replace("://", f"://{who}:{secret}@")}
        adminmsp = f"{work}/admin-msp"
        sh("fabric-ca-client", "enroll", "-M", adminmsp, env=creds("admin", pw), secrets=secrets)
        who = f"{kind}-{n}" + (f"-{gen}" if gen else "")
        reg = sh("fabric-ca-client", "register", "-u", ca_url, "-M", adminmsp, "--id.name", who, "--id.type", k["type"], env=base_env, secrets=secrets)
        m = re.search(r"Password:\s*(\S+)", reg)
        if not m:
            sys.exit(f"enroll.py: register of {who} printed no generated password")
        secrets.append(m.group(1))
        sh("fabric-ca-client", "enroll", "-M", f"{work}/ident/msp", env=creds(who, m.group(1)), secrets=secrets)
        cert = read(first(f"{work}/ident/msp/signcerts/*.pem"))
        key = read(first(f"{work}/ident/msp/keystore/*_sk"))
        shutil.copytree(src, dst)
        write(f"{dst}/msp/{k['dir']}/{kind}-{n}-cert.pem", cert)
        lines = sorted(f"{hashlib.sha256(open(p, 'rb').read()).hexdigest()}  {os.path.relpath(p, dst)}\n"
                       for d, _, names in os.walk(dst) for x in names if x != "MANIFEST.sha256" for p in [os.path.join(d, x)])
        write(f"{dst}/MANIFEST.sha256", "".join(lines))
        found = check_exchange.problems(dst, n)
        if found:
            shutil.rmtree(dst)
            sys.exit("enroll.py: new tree is not clean: " + "; ".join(found[:3]))
        secret = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": {"name": k["secret"].format(n=n), "namespace": ns},
                  "stringData": {"msp-keystore-priv_sk": key, "msp-signcert.pem": cert}}
        sh("kubectl", "--kubeconfig", kubeconfig, "create", "-f", "-", stdin=yaml.safe_dump(secret), secrets=secrets)
    finally:
        destroy(work)


def admin(party, ns, kubeconfig, ca_url, work, src, dst, generation=""):
    """PLAN S8 admin identity (see identity())."""
    return identity("admin", party, ns, kubeconfig, ca_url, work, src, dst, generation)


def destroy(work):
    """shred every file, remove the tree; the caller then proves it with `find <work>` (must print nothing / not exist)."""
    if not os.path.exists(work):
        return
    for d, _, names in os.walk(work):
        for x in names:
            subprocess.run(["shred", "-u", os.path.join(d, x)], check=True)
    shutil.rmtree(work)


if __name__ == "__main__":
    a = sys.argv[1:]
    try:
        cmd, party, ns = a[0], a[1], a[2]
        opt, sans = {}, []
        for k, v in zip(a[3::2], a[4::2]):
            sans.append(v) if k == "--extra-san" else opt.__setitem__(k, v)
        if cmd == "init":
            init(party, ns, opt["--kubeconfig"], opt["--work"])
        elif cmd in KINDS:
            identity(cmd, party, ns, opt["--kubeconfig"], opt["--ca-url"], opt["--work"], opt["--src"], opt["--dst"], opt.get("--generation", ""))
        elif cmd == "enroll":
            enroll(party, ns, opt["--kubeconfig"], opt["--ca-url"], opt["--work"], opt["--out"], sans, opt.get("--generation", ""))
        else:
            raise IndexError
    except (IndexError, KeyError):
        sys.exit(__doc__)
