#!/usr/bin/env python3
"""Enroll one party's four Arma roles at its own fca-org<N> and keep the keys only as Secrets (fabricx S9).

usage: enroll.py init   <party> rd-fabricx-<party> --kubeconfig K --work W
       enroll.py enroll <party> rd-fabricx-<party> --kubeconfig K --ca-url http://localhost:7054 --work W --out exchange/org<N>
One org at a time (sequential): W under /dev/shm only (tmpfs, umask 077 set by the script); destroy W before the next org starts.
init creates the admin password Secret (apply render.py's CA manifest after it). enroll runs `fabric-ca-client` (msp + tls profile)
per role, writes Secrets `orderer-<role>-<N>-secret` with `kubectl create`, builds the public exchange tree, runs check_exchange,
then shreds W. `init` leaves admin.pass in W until `enroll` runs: if enroll never runs, shred W by hand. Private keys exist in W only between enroll and the Secret create: run it on the org's own host.
NOT run live yet: fabric-ca-client is not installed on the build host; the flow is a CLUSTER-OP step (GO B).
"""
import glob, hashlib, os, re, shutil, subprocess, sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import check_exchange

PARTY_N = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
ROLES = ("router", "batcher1", "consenter", "assembler")
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
        endpoints[role] = {"Host": hosts[role], "Port": (ports or {}).get(role, 7050)}
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


def enroll(party, ns, kubeconfig, ca_url, work, out):
    """needs `kubectl --kubeconfig K -n NS port-forward svc/fca-org<N> 7054` running (party-admin Role: pods/portforward).
    Credentials travel only in the fabric-ca-client environment (FABRIC_CA_CLIENT_URL), never on a command line.
    [unverified live] that the client reads FABRIC_CA_CLIENT_URL and prints `Password: <x>` on a register without --id.secret
    (Fabric CA users guide): the window-start throwaway enroll settles it."""
    n = check_target(party, ns)
    work = check_work(work)
    secrets = []
    try:
        pw = read(f"{work}/admin.pass").strip()
        secrets.append(pw)
        base_env = {**os.environ, "FABRIC_CA_CLIENT_HOME": f"{work}/client"}
        creds = lambda who, secret: {**base_env, "FABRIC_CA_CLIENT_URL": ca_url.replace("://", f"://{who}:{secret}@")}
        adminmsp = f"{work}/admin-msp"
        sh("fabric-ca-client", "enroll", "-M", adminmsp, env=creds("admin", pw), secrets=secrets)
        hosts = {r: f"{r}-{n}.{ns}.svc.cluster.local" for r in ROLES}
        for role in ROLES:
            who = f"{role}-{n}"
            reg = sh("fabric-ca-client", "register", "-u", ca_url, "-M", adminmsp, "--id.name", who, "--id.type", "orderer",
                     env=base_env, secrets=secrets)
            m = re.search(r"Password:\s*(\S+)", reg)
            if not m:
                sys.exit(f"enroll.py: register of {who} printed no generated password")
            secrets.append(m.group(1))
            sh("fabric-ca-client", "enroll", "-M", f"{work}/enrolled/{role}/msp", "--csr.hosts", hosts[role], env=creds(who, m.group(1)), secrets=secrets)
            sh("fabric-ca-client", "enroll", "-M", f"{work}/enrolled/{role}/tls", "--enrollment.profile", "tls", "--csr.hosts", hosts[role],
               env=creds(who, m.group(1)), secrets=secrets)
        for s in build(f"{work}/enrolled", out, n, ns, hosts):   # create, never apply: party-admin may create/update/patch secrets but not get
            sh("kubectl", "--kubeconfig", kubeconfig, "create", "-f", "-", stdin=yaml.safe_dump(s), secrets=secrets)
        found = check_exchange.problems(out, n)
        if found:
            sys.exit("enroll.py: exchange tree is not clean:\n" + "\n".join(found))
    finally:  # keys never stay in /dev/shm, also on error
        destroy(work)


def destroy(work):
    """shred every file, remove the tree; the caller then proves it with `find <work>` (must print nothing / not exist)."""
    for d, _, names in os.walk(work):
        for x in names:
            subprocess.run(["shred", "-u", os.path.join(d, x)], check=True)
    shutil.rmtree(work)


if __name__ == "__main__":
    a = sys.argv[1:]
    try:
        cmd, party, ns = a[0], a[1], a[2]
        opt = dict(zip(a[3::2], a[4::2]))
        if cmd == "init":
            init(party, ns, opt["--kubeconfig"], opt["--work"])
        elif cmd == "enroll":
            enroll(party, ns, opt["--kubeconfig"], opt["--ca-url"], opt["--work"], opt["--out"])
        else:
            raise IndexError
    except (IndexError, KeyError):
        sys.exit(__doc__)
