"""Throwaway rehearsal trees: 4 org CAs (openssl), admin + endorser + node certs, laid out like the public exchange tree. Keys stay in ./keys (scratch)."""
import os, subprocess, sys, hashlib, yaml
root = sys.argv[1]
PORTS = {"assembler": 8011, "consenter": 8012, "router": 8013, "batcher1": 8014}
def sh(*a, **k): subprocess.run(a, check=True, capture_output=True, **k)
def ca(name):
    sh("openssl","req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256","-nodes","-keyout",f"{root}/keys/{name}.key","-subj",f"/CN={name}","-days","30",
       "-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign","-out",f"{root}/keys/{name}.pem")
def leaf(cafile, cn, ou, out, keyout=None, san=None):
    k = keyout or f"{root}/keys/tmp.key"
    sh("openssl","genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-256","-out",k)
    sh("openssl","req","-new","-key",k,"-subj",f"/OU={ou}/CN={cn}","-out",f"{root}/keys/tmp.csr")
    ext = f"{root}/keys/ext.cnf"
    open(ext,"w").write("keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth,serverAuth\n" + (f"subjectAltName=DNS:{san}\n" if san else ""))
    sh("openssl","x509","-req","-in",f"{root}/keys/tmp.csr","-CA",f"{root}/keys/{cafile}.pem","-CAkey",f"{root}/keys/{cafile}.key","-CAcreateserial","-days","30","-extfile",ext,"-out",out)
os.makedirs(f"{root}/keys")
def w(p, data, mode="w"):
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p, mode).write(data)
def rd(p): return open(p).read()
for n in (1,2,3,4):
    t = f"{root}/exchange/org{n}"
    ca(f"ca{n}"); ca(f"tlsca{n}")
    w(f"{t}/msp/cacerts/ca.pem", rd(f"{root}/keys/ca{n}.pem")); w(f"{t}/msp/tlscacerts/tlsca.pem", rd(f"{root}/keys/tlsca{n}.pem"))
    os.makedirs(f"{t}/msp/admincerts"); leaf(f"ca{n}", f"admin-{n}", "admin", f"{t}/msp/admincerts/admin-{n}-cert.pem", f"{root}/keys/admin{n}.key")
    os.makedirs(f"{t}/msp/knowncerts"); leaf(f"ca{n}", f"endorser-{n}", "client", f"{t}/msp/knowncerts/endorser-{n}-cert.pem")
    # admin MSP dir as loadSigner reads it: signcerts/cert.pem + keystore/*_sk (PKCS8)
    w(f"{root}/admins/org{n}/signcerts/cert.pem", rd(f"{t}/msp/admincerts/admin-{n}-cert.pem"))
    w(f"{root}/admins/org{n}/keystore/admin{n}_sk", rd(f"{root}/keys/admin{n}.key"))
    ep = {}
    for role, port in PORTS.items():
        host = f"{role}-{n}.arma.rd"
        d = f"{t}/orderers/party{n}/{role}"
        os.makedirs(f"{d}/tls"); leaf(f"tlsca{n}", host, "orderer", f"{d}/tls/server.crt", san=host)
        w(f"{d}/tls/ca.crt", rd(f"{root}/keys/tlsca{n}.pem"))
        if role in ("batcher1", "consenter"):
            os.makedirs(f"{d}/msp/signcerts"); leaf(f"ca{n}", f"{role}-{n}", "orderer", f"{d}/msp/signcerts/{role}-cert.pem")
        ep[role] = {"Host": host, "Port": port}
    w(f"{t}/endpoints.yaml", yaml.safe_dump(ep))
    L = sorted(f"{hashlib.sha256(open(os.path.join(dd,x),'rb').read()).hexdigest()}  {os.path.relpath(os.path.join(dd,x),t)}\n" for dd,_,names in os.walk(t) for x in names if x != "MANIFEST.sha256")
    w(f"{t}/MANIFEST.sha256", "".join(L))
print(",".join(f"{n}={hashlib.sha256(open(f'{root}/exchange/org{n}/MANIFEST.sha256','rb').read()).hexdigest()}" for n in (1,2,3,4)))
