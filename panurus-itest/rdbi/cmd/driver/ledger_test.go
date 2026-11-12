package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeLedger is the party's committer DB as the gateway op sees it: no SQL, no network.
type fakeLedger struct {
	tables map[string]bool
	txs    []ledgerTxInfo // newest block first
	recs   map[string]ledgerTxRecord
	rows   map[string][]ledgerRowRaw
	asked  *[]string
}

func (f fakeLedger) HasTable(ns string) (bool, error) {
	*f.asked = append(*f.asked, "table "+ns)
	return f.tables[ns], nil
}

func (f fakeLedger) Tx(ns, txid string) (*ledgerTxRecord, []ledgerRowRaw, error) {
	*f.asked = append(*f.asked, "tx "+ns+" "+txid)
	r, ok := f.recs[txid]
	if !ok {
		return nil, nil, nil
	}
	return &r, f.rows[txid], nil
}

func (f fakeLedger) Txs(ns string, limit int, before *int64) ([]ledgerTxInfo, error) {
	b := "-"
	if before != nil {
		b = string(rune('0' + *before))
	}
	*f.asked = append(*f.asked, "txs "+ns+" limit "+string(rune('0'+limit%10))+" before "+b)
	var out []ledgerTxInfo
	for _, t := range f.txs {
		if before != nil && t.Block >= *before {
			continue
		}
		out = append(out, t)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

const tx1 = "aa00000000000000000000000000000000000000000000000000000000000001"

func withLedger(t *testing.T, f *fakeLedger) *[]string {
	t.Helper()
	asked := &[]string{}
	if f != nil {
		f.asked = asked
	}
	oldL, oldN := ledger, ledgerNS
	ledgerNS = "rd_dfabi_v2"
	if f == nil {
		ledger = nil
	} else {
		ledger = f
	}
	t.Cleanup(func() { ledger, ledgerNS = oldL, oldN })
	return asked
}

func call(t *testing.T, body string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	handle(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	return w.Code, w.Body.String()
}

func TestLedgerNotConfiguredIs501(t *testing.T) {
	withLedger(t, nil)
	for _, b := range []string{`{"op":"ledger","txid":"` + tx1 + `"}`, `{"op":"ledgertxs","limit":5}`} {
		if code, body := call(t, b); code != 501 || !strings.Contains(body, "ledger op not configured") {
			t.Fatalf("%s: %d %q", b, code, body)
		}
	}
}

func TestLedgerUnknownNamespaceTableIs404NeverEmpty(t *testing.T) {
	withLedger(t, &fakeLedger{tables: map[string]bool{}})
	for _, b := range []string{`{"op":"ledger","txid":"` + tx1 + `"}`, `{"op":"ledgertxs","limit":5}`} {
		if code, body := call(t, b); code != 404 || !strings.Contains(body, "unknown namespace table") {
			t.Fatalf("%s: %d %q", b, code, body)
		}
	}
}

func TestLedgerInputValidation(t *testing.T) {
	withLedger(t, &fakeLedger{tables: map[string]bool{"rd_dfabi_v2": true}})
	bad := []string{
		`{"op":"ledger"}`, `{"op":"ledger","txid":"AA00000000000000000000000000000000000000000000000000000000000001"}`, `{"op":"ledger","txid":"abc"}`,
		`{"op":"ledger","txid":"` + tx1 + `' or 1=1 --"}`, `{"op":"ledger","txid":"zz00000000000000000000000000000000000000000000000000000000000001"}`,
		`{"op":"ledgertxs"}`, `{"op":"ledgertxs","limit":0}`, `{"op":"ledgertxs","limit":201}`, `{"op":"ledgertxs","limit":-1}`, `{"op":"ledgertxs","limit":5,"before":-3}`,
	}
	for _, b := range bad {
		if code, _ := call(t, b); code != 400 {
			t.Fatalf("%s: want 400, got %d", b, code)
		}
	}
}

func TestLedgerTxUnknownAndKnown(t *testing.T) {
	long := make([]byte, 300)
	for i := range long {
		long[i] = byte(i)
	}
	f := &fakeLedger{tables: map[string]bool{"rd_dfabi_v2": true},
		recs: map[string]ledgerTxRecord{tx1: {Block: 12, TxNum: 3, Status: "COMMITTED"}},
		rows: map[string][]ledgerRowRaw{tx1: {{Key: []byte("\x00tokenreq\\" + tx1[:4] + "\xff"), Version: 7, Value: long}, {Key: []byte("k"), Version: 1, Value: []byte{0xde, 0xad}}}}}
	withLedger(t, f)
	code, body := call(t, `{"op":"ledger","txid":"`+tx1+`"}`)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var got struct {
		Namespace string  `json:"namespace"`
		TxID      string  `json:"txId"`
		Found     bool    `json:"found"`
		Block     int64   `json:"block"`
		TxNum     int64   `json:"txNum"`
		Status    string  `json:"status"`
		Rows      []struct {
			Key       string `json:"key"`
			Version   int64  `json:"version"`
			ValueLen  int    `json:"valueLen"`
			ValueHex  string `json:"valueHex"`
			Truncated bool   `json:"truncated"`
		} `json:"rows"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Namespace != "rd_dfabi_v2" || got.TxID != tx1 || !got.Found || got.Block != 12 || got.TxNum != 3 || got.Status != "COMMITTED" || len(got.Rows) != 2 {
		t.Fatalf("%+v", got)
	}
	if got.Rows[0].Key != `\x00tokenreq\\aa00\xff` || got.Rows[0].ValueLen != 300 || len(got.Rows[0].ValueHex) != 256 || !got.Rows[0].Truncated || got.Rows[0].Version != 7 {
		t.Fatalf("row0 %+v", got.Rows[0])
	}
	if got.Rows[1].Key != "k" || got.Rows[1].ValueHex != "dead" || got.Rows[1].Truncated {
		t.Fatalf("row1 %+v", got.Rows[1])
	}
	_, body = call(t, `{"op":"ledger","txid":"`+strings.Repeat("0", 64)+`"}`)
	if !strings.Contains(body, `"found":false`) || !strings.Contains(body, `"status":null`) || !strings.Contains(body, `"rows":[]`) {
		t.Fatalf("unknown tx: %s", body)
	}
}

func TestLedgerTxsPagingEndsOnBlockBoundariesAndCursorIsExclusive(t *testing.T) {
	// blocks 9,9,8,8,8,7,6 (newest first)
	mk := func(b int64, id string) ledgerTxInfo { return ledgerTxInfo{TxID: strings.Repeat(id, 64), Block: b, Status: "COMMITTED"} }
	f := &fakeLedger{tables: map[string]bool{"rd_dfabi_v2": true}, txs: []ledgerTxInfo{mk(9, "a"), mk(9, "b"), mk(8, "c"), mk(8, "d"), mk(8, "e"), mk(7, "f"), mk(6, "1")}}
	withLedger(t, f)
	type page struct {
		Namespace  string          `json:"namespace"`
		Txs        []ledgerTxInfo  `json:"txs"`
		NextBefore *int64          `json:"nextBefore"`
	}
	get := func(body string) page {
		code, out := call(t, body)
		if code != 200 {
			t.Fatalf("%s: %d %s", body, code, out)
		}
		var p page
		if err := json.Unmarshal([]byte(out), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := get(`{"op":"ledgertxs","limit":3}`) // 9,9,8 would cut block 8: the page keeps the two block-9 txs only
	if p.Namespace != "rd_dfabi_v2" || len(p.Txs) != 2 || p.Txs[0].Block != 9 || p.NextBefore == nil || *p.NextBefore != 9 {
		t.Fatalf("%+v", p)
	}
	p = get(`{"op":"ledgertxs","limit":3,"before":9}`) // 8,8,8 is a whole block: clean boundary, more follows
	if len(p.Txs) != 3 || p.NextBefore == nil || *p.NextBefore != 8 {
		t.Fatalf("%+v", p)
	}
	p = get(`{"op":"ledgertxs","limit":3,"before":8}`) // 7,6: not full, nextBefore null
	if len(p.Txs) != 2 || p.NextBefore != nil {
		t.Fatalf("%+v", p)
	}
	p = get(`{"op":"ledgertxs","limit":200}`)
	if len(p.Txs) != 7 || p.NextBefore != nil {
		t.Fatalf("%+v", p)
	}
}

func TestTokenNamespaceFromCoreYAML(t *testing.T) {
	ok := "token:\n  tms:\n    rd_dfabi_v2_tms:\n      channel: arma\n      namespace: rd_dfabi_v2\n      network: default\n"
	if ns, err := tokenNamespace([]byte(ok)); err != nil || ns != "rd_dfabi_v2" {
		t.Fatalf("%q %v", ns, err)
	}
	for _, bad := range []string{"", "token: {}", "token:\n  tms: {}\n", "token:\n  tms:\n    a:\n      namespace: A b\n", "token:\n  tms:\n    a:\n      namespace: x\n    b:\n      namespace: y\n",
		"token:\n  tms:\n    a:\n      namespace: \"x; drop table y\"\n"} {
		if ns, err := tokenNamespace([]byte(bad)); err == nil {
			t.Fatalf("%q accepted as %q", bad, ns)
		}
	}
}

func TestEscapeKey(t *testing.T) {
	if got := escapeKey([]byte("ab c\\\x00\x7f\xff")); got != `ab c\\\x00\x7f\xff` {
		t.Fatalf("%q", got)
	}
}
