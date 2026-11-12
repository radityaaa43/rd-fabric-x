package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Gateway read ops `ledger {txid}` and `ledgertxs {limit, before?}`: what the party's OWN committer database holds, for Lensa's ledger view (role lensa only: the OPA row decides who may call).
// The store is a read-only Postgres role (gw_ro: SELECT on tx_status and the token namespace table, nothing else) behind the ledgerStore interface; fixed statements only, no caller SQL.
// The token namespace is the node's own core.yaml (token.tms.<id>.namespace), never a literal: a changed namespace is returned in every answer and an unknown table is an explicit 404, never an empty list.
// Until the store is wired (it needs the committer schema read first) both ops answer 501.

const (
	ledgerValueHexMax = 128 // bytes of a value returned as hex; longer values are cut and flagged
	ledgerMaxLimit    = 200
)

var (
	txidRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nsRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)
)

type ledgerRowRaw struct {
	Key     []byte
	Version int64
	Value   []byte
}

type ledgerTxRecord struct {
	Block, TxNum int64
	Status       string
}

type ledgerTxInfo struct {
	TxID   string `json:"txId"`
	Block  int64  `json:"block"`
	Status string `json:"status"`
}

// ledgerStore is the party's committer DB as the ops see it. Txs returns at most `limit` entries, newest block first, strictly below `before` when set.
type ledgerStore interface {
	HasTable(ns string) (bool, error)
	Tx(ns, txid string) (*ledgerTxRecord, []ledgerRowRaw, error) // nil record = unknown tx
	Txs(ns string, limit int, before *int64) ([]ledgerTxInfo, error)
}

var (
	ledger   ledgerStore // nil until the store is wired
	ledgerNS string      // token namespace id from core.yaml
)

// tokenNamespace reads token.tms.<id>.namespace from a core.yaml: exactly one TMS, a plain identifier.
func tokenNamespace(core []byte) (string, error) {
	var c struct {
		Token struct {
			TMS map[string]struct {
				Namespace string `yaml:"namespace"`
			} `yaml:"tms"`
		} `yaml:"token"`
	}
	if err := yaml.Unmarshal(core, &c); err != nil {
		return "", err
	}
	if len(c.Token.TMS) != 1 {
		return "", fmt.Errorf("want exactly one token.tms entry, found %d", len(c.Token.TMS))
	}
	for _, t := range c.Token.TMS {
		if !nsRE.MatchString(t.Namespace) {
			return "", fmt.Errorf("token namespace %q is not [a-z][a-z0-9_]{0,40}", t.Namespace)
		}
		return t.Namespace, nil
	}
	return "", fmt.Errorf("no token namespace")
}

// initLedger reads the namespace of this gateway's node. The store stays nil here: the read-only DB role and its Secret are a separate, approved step.
func initLedger() {
	raw, err := os.ReadFile(filepath.Join(live, party, "core.yaml"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ledger ops: core.yaml not read:", err)
		return
	}
	ns, err := tokenNamespace(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ledger ops:", err)
		return
	}
	ledgerNS = ns
}

func ledgerReady() error {
	if ledger == nil || ledgerNS == "" {
		return httpError{http.StatusNotImplemented, "ledger op not configured"}
	}
	ok, err := ledger.HasTable(ledgerNS)
	if err != nil {
		return err
	}
	if !ok {
		return httpError{http.StatusNotFound, "unknown namespace table"}
	}
	return nil
}

// escapeKey prints a ledger key: printable ASCII as is, a backslash doubled, everything else as \xNN.
func escapeKey(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\\':
			sb.WriteString(`\\`)
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, `\x%02x`, c)
		}
	}
	return sb.String()
}

func ledgerOp(txid string) (any, error) {
	if !txidRE.MatchString(txid) {
		return nil, bad("ledger needs txid: 64 lowercase hex characters")
	}
	if err := ledgerReady(); err != nil {
		return nil, err
	}
	rec, raw, err := ledger.Tx(ledgerNS, txid)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"namespace": ledgerNS, "txId": txid, "found": rec != nil, "block": nil, "txNum": nil, "status": nil, "rows": []map[string]any{}}
	if rec == nil {
		return out, nil
	}
	out["block"], out["txNum"], out["status"] = rec.Block, rec.TxNum, rec.Status
	rows := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		v, cut := r.Value, false
		if len(v) > ledgerValueHexMax {
			v, cut = v[:ledgerValueHexMax], true
		}
		rows = append(rows, map[string]any{"key": escapeKey(r.Key), "version": r.Version, "valueLen": len(r.Value), "valueHex": hex.EncodeToString(v), "truncated": cut})
	}
	out["rows"] = rows
	return out, nil
}

func ledgerTxsOp(limit int, before *int64) (any, error) {
	if limit < 1 || limit > ledgerMaxLimit {
		return nil, bad("ledgertxs needs limit 1..%d", ledgerMaxLimit)
	}
	if before != nil && *before < 0 {
		return nil, bad("before is a block number >= 0")
	}
	if err := ledgerReady(); err != nil {
		return nil, err
	}
	got, err := ledger.Txs(ledgerNS, limit+1, before)
	if err != nil {
		return nil, err
	}
	txs, next := pageTxs(got, limit)
	return map[string]any{"namespace": ledgerNS, "txs": txs, "nextBefore": next}, nil
}

// pageTxs cuts `got` (newest first, at most limit+1 entries) to a page that ends on a BLOCK boundary, so the exclusive block cursor never skips a transaction:
// when the next entry belongs to the same block as the last kept one, that block's entries are dropped from this page (unless one block fills it) and returned by the next page.
// nextBefore = the lowest block on the page when more entries exist, else nil.
func pageTxs(got []ledgerTxInfo, limit int) ([]ledgerTxInfo, *int64) {
	if len(got) <= limit {
		if got == nil {
			got = []ledgerTxInfo{}
		}
		return got, nil
	}
	kept := got[:limit]
	if got[limit].Block == kept[limit-1].Block {
		b, n := kept[limit-1].Block, len(kept)
		for n > 0 && kept[n-1].Block == b {
			n--
		}
		if n > 0 {
			kept = kept[:n]
		}
	}
	next := kept[len(kept)-1].Block
	return kept, &next
}
