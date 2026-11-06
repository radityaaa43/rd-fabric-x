package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// rowsNode answers acceptedTransactionHistory/audited with fixed rows, everything else like fakeNode.
type rowsNode struct {
	fakeNode
	rows string
	fail string // view that returns an error
}

func (f rowsNode) CallView(fid string, in []byte) (any, error) {
	if fid == f.fail {
		*f.calls = append(*f.calls, f.name+" "+fid+" FAIL")
		return nil, errors.New("view failed")
	}
	if fid == "acceptedTransactionHistory" || fid == "audited" {
		*f.calls = append(*f.calls, f.name+" "+fid)
		return []byte(f.rows), nil
	}
	return f.fakeNode.CallView(fid, in)
}

// setup makes this process the gateway of `as`, with fake nodes and a fake counterparty gateway answering
// precheck with peerCode (0: unreachable).
func setup(t *testing.T, as string, peerCode int, rows, fail string) (*[]string, *[]string) {
	t.Helper()
	var calls, prechecks []string
	clients = map[string]viewClient{}
	for _, n := range []string{bi, "bank2", "bank3", "bank4"} {
		clients[n] = rowsNode{fakeNode{n, &calls}, rows, fail}
	}
	party, serving = as, true
	t.Cleanup(func() { serving = false })
	gw := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		prechecks = append(prechecks, r.URL.Query().Get("gw")+" "+strings.TrimSpace(string(b)))
		w.WriteHeader(peerCode)
	}))
	peer, peerURL = gw.Client(), gw.URL+"/?gw=%d"
	if peerCode == 0 {
		gw.Close()
	} else {
		t.Cleanup(gw.Close)
	}
	return &calls, &prechecks
}

func post(body string) (int, string) {
	rec := httptest.NewRecorder()
	handle(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

func TestServeTransferOwnNodeOnly(t *testing.T) {
	const fin = `{"TxID":"tx1","TMSID":null,"Timeout":90000000000}`
	calls, _ := setup(t, "bank2", 200, "[]", "")
	code, out := post(`{"op":"transfer","from":"bank2","to":"bank3","type":"RD","amount":"7"}`)
	if code != 200 || !strings.Contains(out, `"txId":"tx1"`) {
		t.Fatalf("got %d %s", code, out)
	}
	want := []string{
		`bank2 transfer {"Auditor":"","Wallet":"","TokenIDs":null,"Type":"RD","Amount":7,"Recipient":"YmFuazM=","RecipientEID":"bank3","RecipientWalletID":"","Retry":false,"FailToRelease":false,"TransferAction":null,"SenderChangeRecipientData":null,"RecipientData":null,"TMSID":null,"NotAnonymous":false,"ApplicationMetadata":null}`,
		"bank2 TxFinality " + fin, `bank2 report {"TxID":"tx1"}`,
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Errorf("calls\n%q\nwant\n%q", *calls, want)
	}
}

func TestServeRefusesOtherParty(t *testing.T) {
	for _, body := range []string{
		`{"op":"transfer","from":"bank3","to":"bank2","type":"RD","amount":"7"}`,
		`{"op":"issue","to":"bank2","type":"RD","amount":"7"}`,
		`{"op":"redeem","from":"bank4","type":"RD","amount":"7"}`,
		`{"op":"precheck","id":"s1","kind":"swap","from":"bank3","to":"bank4","give":{"type":"RD","amount":"1"},"get":{"type":"DFABI-2027A","amount":"1"}}`,
	} {
		calls, _ := setup(t, "bank2", 200, "[]", "")
		if code, out := post(body); code != http.StatusForbidden || len(*calls) != 0 {
			t.Errorf("%s: got %d %s, calls %q", body, code, out, *calls)
		}
	}
}

func TestServeBadRequests(t *testing.T) {
	for _, body := range []string{
		`{"op":"mint","from":"bank2"}`,
		`{"op":"transfer","from":"bank2","to":"bank3","type":"RD","amount":"0"}`,
		`{"op":"transfer","from":"bank2","to":"bank3","type":"RD","amount":"-1"}`,
		`{"op":"transfer","from":"bank2","to":"bank2","type":"RD","amount":"1"}`,
		`{"op":"transfer","from":"bank2","to":"bank3","type":"RD","amount":"1","extra":1}`,
		`{"op":"swap","from":"bank2","to":"bank3","give":{"type":"RD","amount":"1"},"get":{"type":"DFABI-2027A","amount":"1"}}`,
		`{"op":"usage","type":"RD","since":"yesterday"}`,
	} {
		calls, _ := setup(t, "bank2", 200, "[]", "")
		if code, out := post(body); code != http.StatusBadRequest || len(*calls) != 0 {
			t.Errorf("%s: got %d %s, calls %q", body, code, out, *calls)
		}
	}
}

func TestServeSwapPrecheck(t *testing.T) {
	const body = `{"op":"swap","id":"s1","from":"bank2","to":"bank3","give":{"type":"DFABI-2027A","amount":"2"},"get":{"type":"RD","amount":"2000"}}`
	for _, tc := range []struct {
		name     string
		peerCode int
		code     int
	}{
		{"allowed", 200, 200},
		{"denied", 403, 403},
		{"unreachable", 0, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, prechecks := setup(t, "bank2", tc.peerCode, "[]", "")
			code, out := post(body)
			if code != tc.code {
				t.Fatalf("got %d %s", code, out)
			}
			if tc.peerCode != 0 {
				want := []string{`3 {"op":"precheck","id":"s1","kind":"swap","from":"bank2","to":"bank3","give":{"type":"DFABI-2027A","amount":"2"},"get":{"type":"RD","amount":"2000"}}`}
				if !reflect.DeepEqual(*prechecks, want) {
					t.Errorf("prechecks %q", *prechecks)
				}
			}
			swapped := len(*calls) > 0 && strings.HasPrefix((*calls)[0], "bank2 swap ")
			if swapped != (tc.code == 200) || (!swapped && len(*calls) != 0) {
				t.Errorf("calls %q", *calls)
			}
		})
	}
}

func TestServeAwardPrecheckAtBank(t *testing.T) {
	calls, prechecks := setup(t, bi, 200, "[]", "")
	if code, out := post(`{"op":"award","id":"a1","to":"bank4","dfabi":"3","rd":"3000000"}`); code != 200 {
		t.Fatalf("got %d %s", code, out)
	}
	want := `4 {"op":"precheck","id":"a1","kind":"award","from":"issuer","to":"bank4","give":{"type":"DFABI-2027A","amount":"3"},"get":{"type":"RD","amount":"3000000"}}`
	if len(*prechecks) != 1 || (*prechecks)[0] != want || !strings.HasPrefix((*calls)[0], "issuer award ") {
		t.Errorf("prechecks %q calls %q", *prechecks, *calls)
	}
}

func TestServePrecheckAnswersWithoutChain(t *testing.T) {
	calls, _ := setup(t, "bank3", 200, "[]", "")
	code, out := post(`{"op":"precheck","id":"s1","kind":"swap","from":"bank2","to":"bank3","give":{"type":"DFABI-2027A","amount":"2"},"get":{"type":"RD","amount":"2000"}}`)
	if code != 200 || len(*calls) != 0 || out != `{"id":"s1","ok":true}` {
		t.Errorf("got %d %s, calls %q", code, out, *calls)
	}
}

func TestServeUsage(t *testing.T) {
	// counted: 100 (transfer out) + 20 (redeem); not: change, deleted, inbound, other token, before since, issue
	rows := `[
	 {"ActionType":1,"SenderEID":"bank2","RecipientEID":"bank3","TokenType":"RD","Amount":100,"Status":2,"Timestamp":"2026-11-06T01:00:00Z"},
	 {"ActionType":1,"SenderEID":"bank2","RecipientEID":"bank2","TokenType":"RD","Amount":900,"Status":2,"Timestamp":"2026-11-06T01:00:00Z"},
	 {"ActionType":2,"SenderEID":"bank2","RecipientEID":"","TokenType":"RD","Amount":20,"Status":1,"Timestamp":"2026-11-06T02:00:00Z"},
	 {"ActionType":1,"SenderEID":"bank2","RecipientEID":"bank3","TokenType":"RD","Amount":5,"Status":3,"Timestamp":"2026-11-06T02:00:00Z"},
	 {"ActionType":1,"SenderEID":"bank3","RecipientEID":"bank2","TokenType":"RD","Amount":7,"Status":2,"Timestamp":"2026-11-06T02:00:00Z"},
	 {"ActionType":1,"SenderEID":"bank2","RecipientEID":"bank4","TokenType":"DFABI-2027A","Amount":3,"Status":2,"Timestamp":"2026-11-06T02:00:00Z"},
	 {"ActionType":1,"SenderEID":"bank2","RecipientEID":"bank4","TokenType":"RD","Amount":50,"Status":2,"Timestamp":"2026-11-05T16:59:59Z"},
	 {"ActionType":0,"SenderEID":"","RecipientEID":"bank2","TokenType":"RD","Amount":1000,"Status":2,"Timestamp":"2026-11-06T02:00:00Z"}
	]`
	calls, _ := setup(t, "bank2", 200, rows, "")
	code, out := post(`{"op":"usage","type":"RD","since":"2026-11-05T17:00:00Z"}`)
	if code != 200 || out != `{"amount":"120"}` {
		t.Errorf("got %d %s", code, out)
	}
	if want := []string{"bank2 acceptedTransactionHistory"}; !reflect.DeepEqual(*calls, want) {
		t.Errorf("calls %q", *calls)
	}
}

func TestServeViewFailureIsNotExit(t *testing.T) {
	setup(t, "bank2", 200, "[]", "transfer")
	code, out := post(`{"op":"transfer","from":"bank2","to":"bank3","type":"RD","amount":"7"}`)
	if code != http.StatusBadGateway || !strings.Contains(out, "FAIL bank2.transfer") {
		t.Errorf("got %d %s", code, out)
	}
	var m map[string]any
	if json.Unmarshal([]byte(out), &m) == nil {
		t.Errorf("error body should be text, got JSON %s", out)
	}
}
