package award

import (
	"reflect"
	"strings"
	"testing"

	ptoken "github.com/LFDT-Panurus/panurus/token"
	"github.com/LFDT-Panurus/panurus/token/driver/protos-go/v1/request"
	"github.com/LFDT-Panurus/panurus/token/token"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/view"
)

const (
	issueK = request.ActionType_ACTION_TYPE_ISSUE
	transK = request.ActionType_ACTION_TYPE_TRANSFER
)

var (
	bank   = view.Identity("bank-recipient")
	bi     = view.Identity("bi-recipient")
	other  = view.Identity("somebody")
	change = view.Identity("bank-change") // a fresh pseudonym of the bank: told apart by enrolment id
)

func q(v uint64) token.Quantity {
	r, err := token.UInt64ToQuantity(v, 64)
	if err != nil {
		panic(err)
	}

	return r
}

func out(kind request.ActionType, owner view.Identity, eid string, typ token.Type, v uint64) *ptoken.Output {
	return &ptoken.Output{ActionType: kind, Owner: owner, EnrollmentID: eid, Type: typ, Quantity: q(v)}
}

func in(eid string) *ptoken.Input { return &ptoken.Input{ActionType: transK, EnrollmentID: eid} }

var agreed = terms{Bank: bank, BI: bi, BankEID: "bank2", IssueType: "DFABI", IssueAmount: 50, PayType: "RD", PayAmount: 50 * PricePerUnit}

// good is the request the award produces: DFABI to the bank, RD to BI, RD change back to the bank.
func good() parsed {
	return parsed{
		Issues: 1, Transfers: 1,
		Outputs: []*ptoken.Output{
			out(issueK, bank, "bank2", "DFABI", 50),
			out(transK, bi, "issuer", "RD", 50*PricePerUnit),
			out(transK, change, "bank2", "RD", 300),
		},
		Inputs: []*ptoken.Input{in("bank2"), in("bank2")},
	}
}

func TestCheck(t *testing.T) {
	mutate := func(f func(*parsed)) parsed { r := good(); f(&r); return r }
	tests := []struct {
		name string
		req  parsed
		want string // "" accepts; else a part of the error
	}{
		{"happy path", good(), ""},
		{"happy path without change", mutate(func(r *parsed) { r.Outputs = r.Outputs[:2] }), ""},
		{"superset: extra issue action", mutate(func(r *parsed) {
			r.Issues = 2
			r.Outputs = append(r.Outputs, out(issueK, other, "x", "DFABI", 1))
		}), "2 issues"},
		{"superset: extra transfer action", mutate(func(r *parsed) { r.Transfers = 2 }), "2 transfers"},
		{"superset: second DFABI output", mutate(func(r *parsed) { r.Outputs = append(r.Outputs, out(issueK, other, "x", "DFABI", 1)) }), "DFABI for the bank"},
		{"superset: output to a third party", mutate(func(r *parsed) { r.Outputs = append(r.Outputs, out(transK, other, "x", "RD", 1)) }), "neither"},
		{"superset: second change output", mutate(func(r *parsed) { r.Outputs = append(r.Outputs, out(transK, change, "bank2", "RD", 1)) }), "neither"},
		{"change in another type", mutate(func(r *parsed) { r.Outputs[2].Type = "DFABI" }), "neither"},
		{"change owned by someone else", mutate(func(r *parsed) { r.Outputs[2].EnrollmentID = "bank3" }), "neither"},
		{"wrong DFABI amount", mutate(func(r *parsed) { r.Outputs[0] = out(issueK, bank, "bank2", "DFABI", 51) }), "DFABI for the bank"},
		{"wrong DFABI type", mutate(func(r *parsed) { r.Outputs[0].Type = "DFABI-2028" }), "DFABI for the bank"},
		{"DFABI to the wrong recipient", mutate(func(r *parsed) { r.Outputs[0].Owner = other }), "DFABI for the bank"},
		{"wrong RD amount", mutate(func(r *parsed) { r.Outputs[1] = out(transK, bi, "issuer", "RD", 50*PricePerUnit+1) }), "agreed RD"},
		{"RD to BI in another type", mutate(func(r *parsed) { r.Outputs[1].Type = "DFABI" }), "agreed RD"},
		{"RD paid twice to BI", mutate(func(r *parsed) { r.Outputs = append(r.Outputs, out(transK, bi, "issuer", "RD", 50*PricePerUnit)) }), "agreed RD"},
		{"RD to the wrong recipient", mutate(func(r *parsed) { r.Outputs[1].Owner = other; r.Outputs[1].EnrollmentID = "x" }), "neither"},
		{"RD output missing", mutate(func(r *parsed) { r.Outputs = []*ptoken.Output{r.Outputs[0], r.Outputs[2]} }), "lacks"},
		{"DFABI output missing", mutate(func(r *parsed) { r.Outputs = r.Outputs[1:] }), "lacks"},
		{"input not owned by the bank", mutate(func(r *parsed) { r.Inputs = append(r.Inputs, in("bank3")) }), "not the bank's"},
		{"unknown output kind", mutate(func(r *parsed) { r.Outputs[2].ActionType = request.ActionType_ACTION_TYPE_UNSPECIFIED }), "unknown kind"},
		{"no actions", parsed{}, "0 issues"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := agreed.check(tc.req)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want accepted, got %v", err)
				}

				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestCheckCaller(t *testing.T) {
	if err := checkCaller(bi, bi); err != nil {
		t.Fatal(err)
	}
	if checkCaller(other, bi) == nil {
		t.Fatal("a caller that is not BI was accepted")
	}
	if checkCaller(nil, nil) == nil {
		t.Fatal("an unresolved BI identity accepted an unnamed caller")
	}
}

func TestCheckAsk(t *testing.T) {
	if err := checkAsk("RD", 200, bi, bi); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"wrong recipient":   checkAsk("RD", 200, other, bi),
		"no type":           checkAsk("", 200, bi, bi),
		"zero amount":       checkAsk("RD", 0, bi, bi),
		"above upper bound": checkAsk("RD", MaxAmount+1, bi, bi),
	} {
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The bank derives the DFABI leg from the request; a request that does not issue exactly once to it is refused.
func TestAgreedFromIssue(t *testing.T) {
	r := good()
	w, err := agreedFromIssue(r.Outputs, bank, bi, "bank2", "RD", 50*PricePerUnit)
	if err != nil || !reflect.DeepEqual(w, agreed) {
		t.Fatalf("got %+v, %v", w, err)
	}
	if err := w.check(r); err != nil {
		t.Fatal(err)
	}
	for name, outs := range map[string][]*ptoken.Output{
		"no issue":         r.Outputs[1:],
		"issue to other":   {out(issueK, other, "x", "DFABI", 50)},
		"two issues":       {r.Outputs[0], r.Outputs[0]},
		"issue of RD":      {out(issueK, bank, "bank2", "RD", 50)},
		"issue of nothing": {out(issueK, bank, "bank2", "DFABI", 0)},
		"issue too large":  {out(issueK, bank, "bank2", "DFABI", MaxAmount+1)},
	} {
		if _, err := agreedFromIssue(outs, bank, bi, "bank2", "RD", 50*PricePerUnit); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The bank refuses an RD ask that is not exactly the issued DFABI at the protocol price, either way.
func TestAgreedFromIssuePrice(t *testing.T) {
	r := good()
	for _, ask := range []uint64{50*PricePerUnit - 1, 50*PricePerUnit + 1, 1, 0} {
		if _, err := agreedFromIssue(r.Outputs, bank, bi, "bank2", "RD", ask); err == nil {
			t.Errorf("RD ask %d for 50 DFABI accepted", ask)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := Award{Bank: view.Identity("bank2"), IssueType: "DFABI", IssueAmount: 1, PayType: "RD", PayAmount: PricePerUnit}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Award){
		"empty bank":      func(a *Award) { a.Bank = nil },
		"same types":      func(a *Award) { a.PayType = a.IssueType },
		"empty type":      func(a *Award) { a.IssueType = "" },
		"zero DFABI":      func(a *Award) { a.IssueAmount = 0 },
		"zero RD":         func(a *Award) { a.PayAmount = 0 },
		"RD over bound":   func(a *Award) { a.PayAmount = MaxAmount + 1 },
		"RD not at price": func(a *Award) { a.PayAmount = PricePerUnit - 1 },
	} {
		a := ok
		mod(&a)
		if a.validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
