// Package award lets BI sell DFABI to a bank and receive RD in return, in ONE token request: BI issues the
// DFABI to the bank and the bank transfers RD to BI. Both actions sit in the same transaction, so the ledger
// commits both or none. Panurus has no such view (issue is issuer-only, swap is bank-only), so it lives here
// as a wrapper SDK: "award" on the issuer node, the bank's responder on the bank node.
package award

import (
	"encoding/json"
	"strings"

	ptoken "github.com/LFDT-Panurus/panurus/token"
	"github.com/LFDT-Panurus/panurus/token/services/ttx"
	"github.com/LFDT-Panurus/panurus/token/token"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
	dig2 "github.com/hyperledger-labs/fabric-smart-client/platform/common/sdk/dig"
	"github.com/hyperledger-labs/fabric-smart-client/platform/common/utils/assert"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/services/id"
	viewregistry "github.com/hyperledger-labs/fabric-smart-client/platform/view/services/view"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/view"
)

// biNode is the FSC node of BI (the topology requires the name "issuer").
const biNode = "issuer"

// Award is the input of the "award" view, run on BI.
type Award struct {
	// Auditor is the name of the auditor identity (empty: BI's default identity, as the issue view does)
	Auditor string
	// Bank is the identity of the buying bank's FSC node (the node name; the bank's enrolment id must start with it)
	Bank view.Identity
	// IssueType and IssueAmount: what BI issues to the bank
	IssueType   token.Type
	IssueAmount uint64
	// PayType and PayAmount: what the bank transfers to BI in the same transaction
	PayType   token.Type
	PayAmount uint64
}

// validate rejects an award that cannot be a sale of one type for another.
func (a *Award) validate() error {
	if len(a.Bank) == 0 {
		return errors.New("bank is empty")
	}
	if a.IssueType == "" || a.PayType == "" || a.IssueType == a.PayType {
		return errors.New("issue type and pay type must be two different types")
	}
	if err := checkAmount("DFABI", a.IssueAmount); err != nil {
		return err
	}

	if err := checkAmount("RD", a.PayAmount); err != nil {
		return err
	}

	return checkPrice(a.IssueAmount, a.PayAmount)
}

type InitiatorView struct {
	*Award
}

func (t *InitiatorView) Call(context view.Context) (any, error) {
	assert.NoError(t.Award.validate(), "invalid award")

	// BI and the bank exchange the recipient identities that will own the DFABI (bank) and the RD (BI).
	me, bank, err := ttx.ExchangeRecipientIdentities(context, "", t.Bank)
	assert.NoError(err, "failed exchanging identities")

	// The bank identity must belong to the bank asked for, as the issue view checks.
	tms, err := ptoken.GetManagementService(context)
	assert.NoError(err, "failed getting token service")
	bankEID, err := tms.WalletManager().GetEnrollmentID(context.Context(), bank)
	assert.NoError(err, "failed getting the bank's enrollment id")
	assert.True(strings.HasPrefix(bankEID, string(t.Bank)), "bank enrollment id [%s] does not match the expected one [%s]", bankEID, t.Bank)

	// Same auditor choice as the issue view.
	idProvider, err := id.GetProvider(context)
	assert.NoError(err, "failed getting id provider")
	auditorID := idProvider.DefaultIdentity()
	if len(t.Auditor) != 0 {
		auditorID = idProvider.Identity(t.Auditor)
	}
	tx, err := ttx.NewAnonymousTransaction(context, ttx.WithAuditor(auditorID))
	assert.NoError(err, "failed creating transaction")
	tx.SetApplicationMetadata("github.com/LFDT-Panurus/panurus/integration/token/fungible/award", []byte("award"))

	// BI's leg: issue the DFABI to the bank.
	wallet := ttx.GetIssuerWallet(context, "")
	assert.NotNil(wallet, "issuer wallet not found")
	assert.NoError(tx.Issue(context.Context(), wallet, bank, t.IssueType, t.IssueAmount), "failed adding issue")

	// The bank's leg: ask it to add the RD transfer to BI.
	_, err = context.RunView(ttx.NewCollectActionsView(tx,
		&ttx.ActionTransfer{From: bank, Type: t.PayType, Amount: t.PayAmount, Recipient: me},
	))
	assert.NoError(err, "failed collecting actions")

	// BI checks the request holds exactly the two legs it agreed on, and nothing else.
	assert.NoError(tx.IsValid(context.Context()), "failed verifying transaction")
	assert.NoError(checkTx(context, tx, terms{
		Bank: bank, BI: me, BankEID: bankEID,
		IssueType: t.IssueType, IssueAmount: t.IssueAmount, PayType: t.PayType, PayAmount: t.PayAmount,
	}), "the bank's answer is not the agreed award")

	_, err = context.RunView(ttx.NewCollectEndorsementsView(tx))
	assert.NoError(err, "failed to sign transaction")

	_, err = context.RunView(ttx.NewOrderingAndFinalityView(tx))
	assert.NoError(err, "failed asking ordering")

	return tx.ID(), nil
}

type InitiatorViewFactory struct{}

func (p *InitiatorViewFactory) NewView(in []byte) (view.View, error) {
	f := &InitiatorView{Award: &Award{}}
	err := json.Unmarshal(in, f.Award)
	assert.NoError(err, "failed unmarshalling input")

	return f, nil
}

// ResponderView runs on the bank: it takes part in the exchange and adds the RD transfer BI asks for.
// It mirrors Panurus's SwapResponderView, but checks what it signs: the caller is BI, the transaction holds one
// issue of DFABI to this bank and one RD transfer to BI of the amount asked, and nothing else.
type ResponderView struct{}

func (t *ResponderView) Call(context view.Context) (any, error) {
	idp, err := id.GetProvider(context)
	assert.NoError(err, "failed getting id provider")
	assert.NoError(checkCaller(context.Session().Info().Caller, idp.Identity(biNode)), "award refused")

	mine, bi, err := ttx.RespondExchangeRecipientIdentities(context)
	assert.NoError(err, "failed getting identity")

	tx, action, err := ttx.ReceiveAction(context)
	assert.NoError(err, "failed receiving action")
	assert.NoError(checkAsk(action.Type, action.Amount, action.Recipient, bi), "award refused")

	wallet := ttx.MyWalletFromTx(context, tx)
	assert.NotNil(wallet, "default wallet not found")
	err = tx.Transfer(context.Context(), wallet, action.Type, []uint64{action.Amount}, []view.Identity{action.Recipient})
	assert.NoError(err, "failed appending transfer")

	// Check the whole request before it goes back to BI: the bank signs exactly this request.
	if err := t.checkOwnTx(context, tx, mine, bi, action); err != nil {
		tx.Release()
		assert.NoError(err, "award refused")
	}

	_, err = context.RunView(ttx.NewCollectActionsResponderView(tx, action))
	assert.NoError(err, "failed responding to action collect")

	_, err = context.RunView(ttx.NewEndorseView(tx))
	assert.NoError(err, "failed endorsing transaction")

	_, err = context.RunView(ttx.NewFinalityView(tx))
	assert.NoError(err, "new tokens were not committed")

	return tx.ID(), nil
}

func (t *ResponderView) checkOwnTx(context view.Context, tx *ttx.Transaction, mine, bi view.Identity, action *ttx.ActionTransfer) error {
	tms, err := ptoken.GetManagementService(context)
	if err != nil {
		return errors.WithMessage(err, "token service unavailable")
	}
	eid, err := tms.WalletManager().GetEnrollmentID(context.Context(), mine)
	if err != nil {
		return errors.WithMessage(err, "own enrollment id unavailable")
	}
	r, err := readTx(context, tx)
	if err != nil {
		return err
	}
	w, err := agreedFromIssue(r.Outputs, mine, bi, eid, action.Type, action.Amount)
	if err != nil {
		return err
	}

	return w.check(r)
}

// SDK adds the "award" view to BI's node (issuer=true) or the responder to a bank's node.
type SDK struct {
	dig2.SDK
	issuer bool
}

func NewFrom(sdk dig2.SDK, issuer bool) *SDK { return &SDK{SDK: sdk, issuer: issuer} }

func (p *SDK) Install() error {
	if err := p.SDK.Install(); err != nil {
		return err
	}

	return p.SDK.Container().Invoke(func(registry *viewregistry.Registry) error {
		if p.issuer {
			return errors.WithMessage(registry.RegisterFactory("award", &InitiatorViewFactory{}), "failed to install award")
		}

		return errors.WithMessage(registry.RegisterResponder(&ResponderView{}, &InitiatorView{}), "failed to install award responder")
	})
}
