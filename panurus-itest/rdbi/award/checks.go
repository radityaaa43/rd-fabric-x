package award

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	ptoken "github.com/LFDT-Panurus/panurus/token"
	"github.com/LFDT-Panurus/panurus/token/driver/protos-go/v1/request"
	"github.com/LFDT-Panurus/panurus/token/services/ttx"
	"github.com/LFDT-Panurus/panurus/token/token"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/view"
)

// MaxAmount is the largest amount either leg of an award may carry. The bank cannot learn the agreed price any
// other way than from BI's request, so this ceiling is its protection against an absurd one.
// ponytail: one fixed ceiling, make it a per-bank setting if banks need different limits.
const MaxAmount uint64 = 1_000_000_000_000

// terms are the legs of one award: BI issues IssueAmount of IssueType to Bank, and Bank pays PayAmount of
// PayType to BI.
type terms struct {
	Bank, BI    view.Identity // identities that own the DFABI (Bank) and the RD (BI)
	BankEID     string        // enrolment id of the bank: owner of the inputs and of the RD change
	IssueType   token.Type
	IssueAmount uint64
	PayType     token.Type
	PayAmount   uint64
}

// parsed is a token request reduced to what the check looks at.
type parsed struct {
	Issues, Transfers int // number of issue and transfer actions
	Outputs           []*ptoken.Output
	Inputs            []*ptoken.Input
}

func checkAmount(what string, a uint64) error {
	if a == 0 || a > MaxAmount {
		return fmt.Errorf("%s amount %d is not between 1 and %d", what, a, MaxAmount)
	}

	return nil
}

// checkCaller accepts only BI's node as the one asking.
func checkCaller(caller, bi view.Identity) error {
	if len(bi) == 0 || !bytes.Equal(caller, bi) {
		return errors.New("the request does not come from BI")
	}

	return nil
}

// checkAsk checks the RD transfer BI asks for, before the bank spends anything on it.
func checkAsk(payType token.Type, payAmount uint64, recipient, bi view.Identity) error {
	if payType == "" {
		return errors.New("no token type to pay")
	}
	if !bytes.Equal(recipient, bi) || len(bi) == 0 {
		return errors.New("the payment is not addressed to the identity BI gave in the exchange")
	}

	return checkAmount("RD", payAmount)
}

// check accepts a request that is EXACTLY the award: one issue and one transfer; outputs are the DFABI to the
// bank, the RD to BI and at most one RD change back to the bank; every input belongs to the bank.
func (w terms) check(r parsed) error {
	if r.Issues != 1 || r.Transfers != 1 {
		return fmt.Errorf("the request holds %d issues and %d transfers, expected 1 and 1", r.Issues, r.Transfers)
	}
	var issued, paid, change int
	for _, o := range r.Outputs {
		switch o.ActionType {
		case request.ActionType_ACTION_TYPE_ISSUE:
			issued++
			if issued > 1 || !bytes.Equal(o.Owner, w.Bank) || o.Type != w.IssueType || !hasAmount(o.Quantity, w.IssueAmount) {
				return errors.New("the issue output is not the DFABI for the bank")
			}
		case request.ActionType_ACTION_TYPE_TRANSFER:
			if bytes.Equal(o.Owner, w.BI) {
				paid++
				if paid > 1 || o.Type != w.PayType || !hasAmount(o.Quantity, w.PayAmount) {
					return errors.New("the transfer output for BI is not the agreed RD amount")
				}
				continue
			}
			change++
			if change > 1 || o.Type != w.PayType || o.EnrollmentID != w.BankEID {
				return errors.New("the transfer has an output that is neither BI's RD nor the bank's change")
			}
		default:
			return errors.New("the request has an output of an unknown kind")
		}
	}
	if issued != 1 || paid != 1 {
		return errors.New("the request lacks the DFABI output or the RD output")
	}
	for _, in := range r.Inputs {
		if in.ActionType != request.ActionType_ACTION_TYPE_TRANSFER || in.EnrollmentID != w.BankEID {
			return errors.New("the request spends a token that is not the bank's")
		}
	}

	return nil
}

func hasAmount(q token.Quantity, want uint64) bool {
	return q != nil && q.ToBigInt().Cmp(new(big.Int).SetUint64(want)) == 0
}

// agreedFromIssue is the bank's view: it only knows the RD it was asked for, so it takes the DFABI leg from the
// one issue output in the request (which must be for this bank, of another type, in range) and returns the
// terms the whole request must then match.
func agreedFromIssue(outs []*ptoken.Output, mine, bi view.Identity, eid string, payType token.Type, payAmount uint64) (terms, error) {
	var issue *ptoken.Output
	for _, o := range outs {
		if o.ActionType != request.ActionType_ACTION_TYPE_ISSUE {
			continue
		}
		if issue != nil {
			return terms{}, errors.New("the request issues more than once")
		}
		issue = o
	}
	if issue == nil || !bytes.Equal(issue.Owner, mine) {
		return terms{}, errors.New("the request does not issue to this bank")
	}
	if issue.Type == "" || issue.Type == payType {
		return terms{}, errors.New("the issued token type is missing or is the one to pay")
	}
	q := issue.Quantity.ToBigInt()
	if !q.IsUint64() {
		return terms{}, errors.New("the issued amount is too large")
	}
	if err := checkAmount("DFABI", q.Uint64()); err != nil {
		return terms{}, err
	}

	return terms{Bank: mine, BI: bi, BankEID: eid, IssueType: issue.Type, IssueAmount: q.Uint64(), PayType: payType, PayAmount: payAmount}, nil
}

// readTx lists the actions, outputs and inputs of a token transaction.
func readTx(ctx view.Context, tx *ttx.Transaction) (parsed, error) {
	outs, err := tx.Outputs(ctx.Context())
	if err != nil {
		return parsed{}, errors.New("cannot read the outputs of the request")
	}
	ins, err := tx.Inputs(ctx.Context())
	if err != nil {
		return parsed{}, errors.New("cannot read the inputs of the request")
	}
	req := tx.Request()

	return parsed{
		Issues:    len(req.Issues()),
		Transfers: len(req.Transfers()),
		Outputs:   outs.Outputs(),
		Inputs:    ins.Inputs(),
	}, nil
}

// checkTx is the initiator's check of the request it is about to have endorsed.
func checkTx(ctx view.Context, tx *ttx.Transaction, w terms) error {
	r, err := readTx(ctx, tx)
	if err != nil {
		return err
	}

	return w.check(r)
}
