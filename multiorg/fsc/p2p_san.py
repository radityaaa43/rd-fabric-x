#!/usr/bin/env python3
"""S13 precondition (issuance and the setup-pp rerun): the certificate a p2p listener PRESENTS must carry every name peers dial (node, node.<ns>.svc.cluster.local).
Live 2026-11-11 21:29Z: all 8 listeners presented SAN `bi-server` only, so issuer -> endorser-3 failed `x509: certificate is valid for bi-server, not endorser-3`.

usage: p2p_san.py file <cert.pem> <party> <node>       offline: the SAN of a PEM file (public cert)
       p2p_san.py live <party>... [--kube-dir DIR]     read-only: port-forward (timeout 60) to svc/rdbi-p2p-<pod> with the party's OWN party-admin kubeconfig DIR/<party>.kubeconfig,
                                                        `openssl s_client -servername <node>`, check the presented cert; nothing written to disk; ends with "port-forwards: none left"
Exit code 0 only if every checked listener carries all names.
"""
import os, socket, subprocess, sys, time

NS = "rd-fabricx-{}"
LISTEN = {"bi": [("issuer", "rdbi-p2p-bi", 5101), ("endorser-1", "rdbi-p2p-bi", 5113)],
          "bank-a": [("bank2", "rdbi-p2p-bank2", 5104), ("endorser-2", "rdbi-p2p-bank2", 5116)],
          "bank-b": [("bank3", "rdbi-p2p-bank3", 5107), ("endorser-3", "rdbi-p2p-bank3", 5119)],
          "bank-c": [("bank4", "rdbi-p2p-bank4", 5110), ("endorser-4", "rdbi-p2p-bank4", 5122)]}


def names(party, node):
    return [node, f"{node}.{NS.format(party)}.svc.cluster.local"]


def san(pem):
    r = subprocess.run(["openssl", "x509", "-noout", "-ext", "subjectAltName"], input=pem, capture_output=True, text=True)
    return [x.strip()[4:] for line in r.stdout.splitlines() if "DNS:" in line for x in line.split(",")]


def check(pem, party, node):
    """names peers dial that the cert does not carry ([] = ok)"""
    have = san(pem)
    return [n for n in names(party, node) if n not in have]


def presented(party, node, svc, port, lport, kube):
    pf = subprocess.Popen(["timeout", "60", "kubectl", "--kubeconfig", kube, "-n", NS.format(party), "port-forward", f"svc/{svc}", f"{lport}:{port}"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        t0 = time.time()
        while time.time() - t0 < 20:
            if pf.poll() is not None:
                return None, "port-forward exited: " + (pf.stderr.read() or "")[:200]
            try:
                socket.create_connection(("127.0.0.1", lport), 1).close()
                break
            except OSError:
                time.sleep(0.5)
        else:
            return None, "port-forward not ready in 20 s"
        s = subprocess.run(["timeout", "15", "openssl", "s_client", "-connect", f"127.0.0.1:{lport}", "-servername", node], input="", capture_output=True, text=True)
        a, b = s.stdout.find("-----BEGIN CERTIFICATE-----"), s.stdout.find("-----END CERTIFICATE-----")
        if a < 0 or b < 0:
            return None, "no certificate presented"
        return s.stdout[a:b + len("-----END CERTIFICATE-----")] + "\n", None
    finally:
        pf.terminate()
        try:
            pf.wait(5)
        except subprocess.TimeoutExpired:
            pf.kill()


def report(party, node, miss, have):
    print(f"{party} {node}: SAN {have} {'OK' if not miss else 'MISSING ' + str(miss)}")
    return not miss


def main(a):
    if len(a) == 4 and a[0] == "file":
        pem = open(a[1]).read()
        return 0 if report(a[2], a[3], check(pem, a[2], a[3]), san(pem)) else 1
    if a and a[0] == "live":
        kdir = "/dev/shm/swap-fabric"
        if "--kube-dir" in a:
            kdir = a[a.index("--kube-dir") + 1]
        ok, lport = True, 47200
        for party in [x for x in a[1:] if x in LISTEN]:
            for node, svc, port in LISTEN[party]:
                lport += 1
                pem, err = presented(party, node, svc, port, lport, f"{kdir}/{party}.kubeconfig")
                if err:
                    print(f"{party} {node}: {err}")
                    ok = False
                else:
                    ok &= report(party, node, check(pem, party, node), san(pem))
        left = subprocess.run(["pgrep", "-fc", "kubectl.*port-forward.*rdbi-p2p"], capture_output=True, text=True).stdout.strip() or "0"
        print("port-forwards:", "none left" if left == "0" else left)
        return 0 if ok else 1
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
