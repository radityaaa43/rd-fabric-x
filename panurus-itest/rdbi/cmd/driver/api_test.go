package main

import (
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sort"
	"testing"
)

// fakeNode records the views called on it; no network. It answers a transaction id for every view except the
// few whose result the api parses.
type fakeNode struct {
	name  string
	calls *[]string
}

func (f fakeNode) CallView(fid string, in []byte) (any, error) {
	*f.calls = append(*f.calls, f.name+" "+fid+" "+string(in))
	switch fid {
	case "report":
		return []byte(`{"tx1":"recorded"}`), nil
	case "balance":
		return []byte(`{"Quantity":"0x5"}`), nil
	case "audited", "acceptedTransactionHistory":
		return []byte(`[]`), nil
	}
	return []byte(`"tx1"`), nil
}

// TestAPIRequests pins what each api command sends to which node and the keys of the JSON it prints, so a
// new command cannot change the existing ones that the Lensa Privasi adapter relies on.
func TestAPIRequests(t *testing.T) {
	const fin = `{"TxID":"tx1","TMSID":null,"Timeout":90000000000}`
	const rpt = `issuer report {"TxID":"tx1"}`
	tests := []struct {
		name  string
		args  []string
		calls []string
		keys  []string
	}{
		{"issue", []string{"issue", "bank2", "RD", "1000"}, []string{
			`issuer issue {"TMSID":null,"Anonymous":false,"Auditor":"","IssuerWallet":"","TokenType":"RD","Quantity":1000,"Recipient":"YmFuazI=","RecipientWalletID":"","RecipientEID":"bank2","SkipAuditorSignatureVerification":false}`,
			"issuer TxFinality " + fin, "bank2 TxFinality " + fin, rpt,
		}, []string{"report", "steps", "txId"}},
		{"transfer", []string{"transfer", "bank2", "bank3", "RD", "7"}, []string{
			`bank2 transfer {"Auditor":"","Wallet":"","TokenIDs":null,"Type":"RD","Amount":7,"Recipient":"YmFuazM=","RecipientEID":"bank3","RecipientWalletID":"","Retry":false,"FailToRelease":false,"TransferAction":null,"SenderChangeRecipientData":null,"RecipientData":null,"TMSID":null,"NotAnonymous":false,"ApplicationMetadata":null}`,
			"bank2 TxFinality " + fin, "bank3 TxFinality " + fin, "bank2 report " + `{"TxID":"tx1"}`,
		}, []string{"report", "steps", "txId"}},
		{"swap", []string{"swap", "bank2", "bank3", "RD", "200", "DFABI-2027A", "20"}, []string{
			`bank2 swap {"Auditor":"","AliceWallet":"","FromAliceType":"RD","FromAliceAmount":200,"FromBobType":"DFABI-2027A","FromBobAmount":20,"Bob":"YmFuazM="}`,
			"bank2 TxFinality " + fin, "bank3 TxFinality " + fin, "bank2 report " + `{"TxID":"tx1"}`,
		}, []string{"report", "steps", "txId"}},
		{"award", []string{"award", "bank2", "3", "3000000"}, []string{
			`issuer award {"Auditor":"","Bank":"YmFuazI=","IssueType":"DFABI-2027A","IssueAmount":3,"PayType":"RD","PayAmount":3000000}`,
			"issuer TxFinality " + fin, "bank2 TxFinality " + fin, rpt,
		}, []string{"report", "steps", "txId"}},
		{"balance", []string{"balance", "bank2", "RD"}, []string{`bank2 balance {"TMSID":null,"SkipCheck":false,"Wallet":"","Type":"RD"}`}, []string{"amount"}},
		{"records bank", []string{"records", "bank2", "tx1"}, []string{`bank2 acceptedTransactionHistory {"SenderWallet":"","RecipientWallet":"","From":null,"To":null,"ActionTypes":null,"Statuses":null,"TMSID":null,"IDs":["tx1"],"SearchDirection":0}`}, []string{"records"}},
		{"records bi", []string{"records", "issuer", "tx1"}, []string{`issuer audited {}`}, []string{"records"}},
		{"history bank", []string{"history", "bank2", "5"}, []string{`bank2 acceptedTransactionHistory {"SenderWallet":"","RecipientWallet":"","From":null,"To":null,"ActionTypes":null,"Statuses":null,"TMSID":null,"IDs":null,"SearchDirection":0}`}, []string{"records"}},
		{"history bi", []string{"history", "issuer", "5"}, []string{`issuer audited {}`}, []string{"records"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			clients = map[string]viewClient{}
			for _, n := range []string{bi, "bank2", "bank3", "bank4"} {
				clients[n] = fakeNode{n, &calls}
			}
			out := captureStdout(t, func() { api(tc.args) })
			var got map[string]json.RawMessage
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("stdout is not one JSON object: %q", out)
			}
			var keys []string
			for k := range got {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if !reflect.DeepEqual(keys, tc.keys) {
				t.Errorf("output keys %v, want %v", keys, tc.keys)
			}
			if !reflect.DeepEqual(calls, tc.calls) {
				t.Errorf("calls\n%q\nwant\n%q", calls, tc.calls)
			}
		})
	}
}

func captureStdout(t *testing.T, f func()) []byte {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	f()
	w.Close()
	out, _ := io.ReadAll(r)
	return out
}
