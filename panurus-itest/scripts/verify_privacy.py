#!/usr/bin/env python3
"""Check the visibility rule against the stored data of a running deployment (read-only).

Rule: only the sender, the recipient and BI (auditor) see a transaction; nobody else, and the ledger shows no
cleartext. Instead of asking the nodes, it opens their SQLite files and the committer database:

  P1  BI's audit trail is the reference: for every confirmed tx it lists the parties.
  P2  confirmed tx: a bank holds a record <=> it is a party; unconfirmed tx: only a party may hold one.
  P3  no bank record shows more than BI's record (type, amount, parties), so nobody sees more than BI.
  P4  a bank that took part in nothing holds no transaction, token or request.
  P5  ledger namespace: no cleartext names, token types or amounts in any key or value; outputs are distinct.
  P6  the endorser stores no names, types or amounts (it only validates the zero-knowledge proofs).

Exit status 1 on any FAIL. Env: RDBI_HOME (default ~/.fabricx-token), KUBECONFIG (for P5; skipped without).
"""
import collections, os, re, sqlite3, subprocess, sys

H = os.path.join(os.environ.get("RDBI_HOME", os.path.expanduser("~/.fabricx-token")), "live")
BANKS = ["bank2", "bank3", "bank4"]
ACT = {0: "issue", 1: "transfer", 2: "redeem"}
NS = os.environ.get("NAMESPACE", "rd_dfabi")
fails = 0


def conn(n):
    c = sqlite3.connect(f"file:{H}/{n}/data/default.sqlite?mode=ro", uri=True)
    c.text_factory = bytes
    return c


def tbl(c, suffix):
    return [r[0].decode() for r in c.execute("select name from sqlite_master where type='table'") if r[0].decode().endswith(suffix)][0]


def s(x):
    return x.decode() if isinstance(x, bytes) else x


def check(name, ok, detail=""):
    global fails
    print(f"{'PASS' if ok else 'FAIL'}  {name:62} {detail}")
    fails += 0 if ok else 1


# ---- P1 reference: BI's audit trail. Confirmed txs are the reference for P2; unconfirmed ones (pending or
# aborted, e.g. the recipient refused) are in BI's trail too and only constrain who may hold a record.
bi = conn("issuer")
status = {s(r[0]): r[1] for r in bi.execute(f'select tx_id,status from "{tbl(bi, "aud_requests")}"')}
confirmed = {tx for tx, st in status.items() if st == 2}
audit = collections.defaultdict(set)
for tx, a, snd, rcp, ty, amt in bi.execute(f'select tx_id,action_type,sender_eid,recipient_eid,token_type,amount from "{tbl(bi, "aud_txs")}"'):
    audit[s(tx)].add((ACT[a], s(snd) or "-", s(rcp) or "-", s(ty), int(amt)))
parties = {tx: {p for (_, snd, rcp, _, _) in rows for p in (snd, rcp) if p.startswith("bank")} for tx, rows in audit.items()}
check("P1 BI audited every request with type, amount and parties", set(audit) == set(status) and len(confirmed) > 0,
      f"{len(confirmed)} confirmed, {len(status) - len(confirmed)} unconfirmed")

# ---- per-bank records
rec = {}
for b in BANKS:
    c = conn(b)
    d = collections.defaultdict(set)
    for tx, a, snd, rcp, ty, amt in c.execute(f'select tx_id,action_type,sender_eid,recipient_eid,token_type,amount from "{tbl(c, "_txs")}"'):
        d[s(tx)].add((ACT[a], s(snd) or "-", s(rcp) or "-", s(ty), int(amt)))
    rec[b] = d

# P2: confirmed txs are held by exactly their parties
bad = [(tx[:10], b) for tx in confirmed for b in BANKS if (tx in rec[b]) != (b in parties[tx])]
check("P2 confirmed tx: a bank has a record exactly when it is a party", not bad, f"violations: {bad}" if bad else f"{len(confirmed)} tx x {len(BANKS)} banks")
# P2b: unconfirmed txs may be missing at the recipient (never delivered) but never present at a non-party
bad = [(tx[:10], b) for tx in audit if tx not in confirmed for b in BANKS if tx in rec[b] and b not in parties[tx]]
check("P2b unconfirmed tx: only a party may hold a record", not bad, str(bad) if bad else f"{len(audit) - len(confirmed)} unconfirmed tx")
# P2c: no bank holds a record BI does not know about
unknown = {b: [tx[:10] for tx in rec[b] if tx not in audit] for b in BANKS}
check("P2c banks hold no record that BI's trail lacks", not any(unknown.values()), str({b: v for b, v in unknown.items() if v}))
# P3
over = []
for b in BANKS:
    for tx, rows in rec[b].items():
        if tx in audit and not rows <= audit[tx]:
            over.append((b, tx[:10]))
check("P3 no bank record shows more than BI's record", not over, str(over) if over else "")
# P3b: parties of a DvP / transfer see their own legs only; report how much of the tx each side sees
share = collections.Counter()
for tx, rows in audit.items():
    for b in BANKS:
        if tx in rec[b]:
            share["full" if rec[b][tx] == rows else "own legs only"] += 1
print(f"INFO  bank-side view of transactions the bank took part in: {dict(share)}")
# P4
for b in BANKS:
    if not any(b in p for p in parties.values()):
        c = conn(b)
        n = {suf: c.execute(f'select count(*) from "{tbl(c, suf)}"').fetchone()[0] for suf in ("_txs", "_tokens", "_requests")}
        check(f"P4 {b} took part in nothing and holds nothing", not any(n.values()), str(n))

# ---- P5 ledger (needs the cluster)
if os.environ.get("KUBECONFIG"):
    sql = (f"export PGPASSWORD=$POSTGRES_PASSWORD; psql -h 127.0.0.1 -p 5150 -U $POSTGRES_USER -d $POSTGRES_DB -At -F ' ' "
           f"-c \"select encode(key,'hex'), encode(value,'hex') from ns_{NS}\"")
    out = subprocess.run(["kubectl", "-n", "fabricx", "exec", "-i", "committer-db-0", "--", "sh"], input=sql.encode(), capture_output=True)
    rows = [(l.split(" ")[0], l.split(" ")[1] if " " in l else "") for l in out.stdout.decode().splitlines() if re.fullmatch(r"[0-9a-f]+ ?[0-9a-f]*", l)]
    outs, setup = [], []
    for k, v in rows:
        key = bytes.fromhex(k).replace(b"\x00", b"|").decode("latin1")
        (setup if key.startswith("|se") else outs).append((key, bytes.fromhex(v)))
    token_rows = [v for k, v in outs if len(v) > 100]  # 274-byte token outputs; the rest are 1- or 32-byte markers
    blob = b"".join(k.encode("latin1") + v for k, v in outs).lower()
    words = [b"bank", b"issuer", b"auditor", b"dfabi", b"rd-", b"quantity", b"1000", b"2027"]
    hit = [w.decode() for w in words if w in blob]
    check("P5a ledger keys/values contain no names, types or amounts", not hit, f"{len(outs)} rows scanned" + (f", found {hit}" if hit else ""))
    check("P5b token outputs are distinct, fixed-size ciphertext-like blobs", len(set(token_rows)) == len(token_rows) and len({len(v) for v in token_rows}) == 1,
          f"{len(token_rows)} outputs of {sorted({len(v) for v in token_rows})} bytes")
else:
    print("SKIP  P5 ledger checks (KUBECONFIG not set)")

# ---- P6 endorser
e = conn("endorser-1")
t = tbl(e, "req_vals")
blob = b"".join(bytes(x) for r in e.execute(f'select request, metadata from "{t}"') for x in r if x).lower()
log = open(f"{H}/endorser-1/node.log", errors="replace").read().lower()
# the namespace is called rd_dfabi, so match the token type (dfabi-2027a) and bank names, not the bare word
names = [w for w in ("bank2", "bank3", "bank4", "dfabi-2027a", "dfabi-", "quantity=", "amount=") if w.encode() in blob or w in log]
check("P6 endorser data and log contain no bank names, token types or amounts", not names, str(names) if names else f"{len(blob)} bytes + log scanned")

print("PRIVACY OK" if not fails else f"PRIVACY FAILED: {fails} check(s)")
sys.exit(1 if fails else 0)
