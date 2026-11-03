package main

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"time"

	views1 "github.com/LFDT-Panurus/panurus/integration/token/common/views"
	rep "github.com/LFDT-Panurus/panurus/integration/token/fungible/rdbi/report"
	"github.com/LFDT-Panurus/panurus/integration/token/fungible/views"
	"github.com/LFDT-Panurus/panurus/token/token"
)

// api runs one operation for the Lensa Privasi adapter (frontend/server/src/adapters/fabricx.ts) and prints one
// JSON object on stdout; logs go to stderr, a failure exits 1 with "FAIL ..." on stderr. Amounts are decimal
// strings (the public parameters allow 64-bit values, more than a JavaScript number holds).
//
//	api issue <to> <type> <amount>                                  BI issues to a bank
//	api transfer <from> <to> <type> <amount>
//	api swap <from> <to> <type from gives> <amount> <type to gives> <amount>    DvP
//	api award <to> <dfabi amount> <rd amount>                       BI issues DFABI to a bank, the bank pays RD, one transaction
//	api balance <node> <type>
//	api records <node> <txid>    what the node itself holds about the transaction (BI: its audit records)
//	api history <node> <limit>   the movements of the node's <limit> newest transactions from its own store, newest first
func api(args []string) {
	var out any
	switch args[0] {
	case "issue":
		out = run(bi, []string{args[1]}, func() any {
			return call(bi, "issue", &views.IssueCash{Auditor: auditor, TokenType: token.Type(args[2]), Quantity: amount(args[3]), Recipient: []byte(args[1]), RecipientEID: args[1]})
		})
	case "transfer":
		out = run(args[1], []string{args[2]}, func() any {
			return call(args[1], "transfer", &views.Transfer{Auditor: auditor, Type: token.Type(args[3]), Amount: amount(args[4]), Recipient: []byte(args[2]), RecipientEID: args[2]})
		})
	case "swap":
		out = run(args[1], []string{args[2]}, func() any {
			return call(args[1], "swap", &views.Swap{Auditor: auditor, FromAliceType: token.Type(args[3]), FromAliceAmount: amount(args[4]),
				FromBobType: token.Type(args[5]), FromBobAmount: amount(args[6]), Bob: []byte(args[2])})
		})
	case "award":
		out = run(bi, []string{args[1]}, func() any {
			return call(bi, "award", awardInput(args[1], amount(args[2]), amount(args[3])))
		})
	case "balance":
		out = map[string]string{"amount": strconv.FormatUint(balance(args[1], args[2]), 10)}
	case "records":
		out = map[string]any{"records": records(args[1], args[2])}
	case "history":
		n, err := strconv.Atoi(args[2])
		if err != nil || n < 1 {
			must(os.ErrInvalid, "history limit "+args[2])
		}
		out = map[string]any{"records": history(args[1], n)}
	default:
		must(os.ErrInvalid, "api "+args[0])
	}
	must(json.NewEncoder(os.Stdout).Encode(out), "encode")
}

func amount(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	must(err, "amount "+s)
	return v
}

type step struct {
	Name string `json:"name"`
	Ms   int64  `json:"ms"`
}

// run submits a transaction from initiator (the view returns once the ledger has it), waits until the initiator
// and the counterparties have it final, then reports it to BI. A report BI cannot take (BI offline) does not fail
// the call: the transaction is final, the report is sent later (driver report).
func run(initiator string, others []string, submit func() any) map[string]any {
	var steps []step
	t := time.Now()
	lap := func(name string) {
		steps = append(steps, step{name, time.Since(t).Milliseconds()})
		t = time.Now()
	}
	tx := txID(submit())
	lap("submit")
	for _, n := range append([]string{initiator}, others...) {
		call(n, "TxFinality", &views1.TxFinality{TxID: tx, Timeout: 90 * time.Second})
	}
	lap("final")
	report := "not delivered"
	if o, err := tryCall(initiator, "report", &rep.Report{TxID: tx}); err == nil {
		res := map[string]string{}
		jsonUnmarshal(o.([]byte), &res)
		report = res[tx]
	} else {
		report += ": " + short(err)
	}
	lap("report")
	return map[string]any{"txId": tx, "steps": steps, "report": report}
}

type record struct {
	Action    string `json:"action"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Type      string `json:"type"`
	Amount    string `json:"amount"`
	Status    string `json:"status"`
}

// records returns the movements of txid as the node's own store has them: a bank's transaction store (only
// transactions it took part in), BI's audit store (every transaction reported to it).
func records(n, txid string) []record {
	var raw []struct {
		TxID         string
		ActionType   int
		SenderEID    string
		RecipientEID string
		TokenType    string
		Amount       json.Number
		Status       int
	}
	var out any
	if n == bi {
		out = call(bi, "audited", struct{}{})
	} else {
		out = call(n, "acceptedTransactionHistory", &views.ListAcceptedTransactions{IDs: []string{txid}})
	}
	dec := json.NewDecoder(bytes.NewReader(out.([]byte)))
	dec.UseNumber()
	must(dec.Decode(&raw), "decode records")
	recs := []record{}
	for _, r := range raw {
		if r.TxID != txid {
			continue
		}
		recs = append(recs, record{
			Action: []string{"issue", "transfer", "redeem"}[r.ActionType], Sender: r.SenderEID, Recipient: r.RecipientEID,
			Type: r.TokenType, Amount: r.Amount.String(),
			Status: []string{"unknown", "pending", "confirmed", "deleted", "orphan"}[r.Status],
		})
	}
	return recs
}

type historyRecord struct {
	TxID      string `json:"txId"`
	Type      string `json:"type"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Token     string `json:"token"`
	Amount    string `json:"amount"`
	Timestamp string `json:"timestamp"` // RFC 3339: when the node stored the record, not the commit time
	Status    string `json:"status"`
}

// history returns the movements of the node's newest `limit` transactions, newest first, from the node's own store
// (a bank: the transactions it took part in; BI: its audit store, every transaction reported to it). Read-only: the
// same views as records, without the txid filter.
func history(n string, limit int) []historyRecord {
	var raw []struct {
		TxID         string
		ActionType   int
		SenderEID    string
		RecipientEID string
		TokenType    string
		Amount       json.Number
		Status       int
		Timestamp    time.Time
	}
	var out any
	if n == bi {
		out = call(bi, "audited", struct{}{})
	} else {
		out = call(n, "acceptedTransactionHistory", &views.ListAcceptedTransactions{})
	}
	dec := json.NewDecoder(bytes.NewReader(out.([]byte)))
	dec.UseNumber()
	must(dec.Decode(&raw), "decode history")
	sort.SliceStable(raw, func(i, j int) bool { return raw[i].Timestamp.After(raw[j].Timestamp) })
	// Index = enum value: ActionType Issue, Transfer, Redeem (panurus v0.24.0 token/services/storage/db/driver/common.go:22-31);
	// TxStatus Unknown, Pending, Confirmed, Deleted, Orphan (token/driver/vault.go:32-45).
	actions := []string{"issue", "transfer", "redeem"}
	statuses := []string{"unknown", "pending", "confirmed", "deleted", "orphan"}
	recs := []historyRecord{}
	seen := map[string]bool{}
	for _, r := range raw {
		if !seen[r.TxID] {
			if len(seen) == limit {
				continue // the newest `limit` txs are chosen: skip the rows of older ones, but keep every row of a chosen one
			}
			seen[r.TxID] = true
		}
		if r.ActionType < 0 || r.ActionType >= len(actions) || r.Status < 0 || r.Status >= len(statuses) {
			must(os.ErrInvalid, "history record "+r.TxID+": unknown action or status")
		}
		recs = append(recs, historyRecord{
			TxID: r.TxID, Type: actions[r.ActionType], Sender: r.SenderEID, Recipient: r.RecipientEID, Token: r.TokenType,
			Amount: r.Amount.String(), Timestamp: r.Timestamp.UTC().Format(time.RFC3339Nano), Status: statuses[r.Status],
		})
	}
	return recs
}
