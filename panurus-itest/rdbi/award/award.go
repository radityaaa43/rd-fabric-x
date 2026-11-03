// Package award lets BI sell DFABI to a bank and receive RD in return, in ONE token request: BI issues the
// DFABI to the bank and the bank transfers RD to BI. Both actions sit in the same transaction, so the ledger
// commits both or none. Panurus has no such view (issue is issuer-only, swap is bank-only), so it lives here
// as a wrapper SDK: "award" on the issuer node, the bank's responder on the bank node.
package award

import (
	"encoding/json"
	"math/big"

	"github.com/LFDT-Panurus/panurus/token/services/ttx"
	"github.com/LFDT-Panurus/panurus/token/token"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
	dig2 "github.com/hyperledger-labs/fabric-smart-client/platform/common/sdk/dig"
	"github.com/hyperledger-labs/fabric-smart-client/platform/common/utils/assert"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/services/id"
	viewregistry "github.com/hyperledger-labs/fabric-smart-client/platform/view/services/view"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/view"
)

// Award is the input of the "award" view, run on BI.
type Award struct {
	// Auditor is the name of the auditor identity (empty: BI's default identity, as the issue view does)
	Auditor string
	// Bank is the identity of the buying bank's FSC node
	Bank view.Identity
	// IssueType and IssueAmount: what BI issues to the bank
	IssueType   token.Type
	IssueAmount uint64
	// PayType and PayAmount: what the bank transfers to BI in the same transaction
	PayType   token.Type
	PayAmount uint64
}

type InitiatorView struct {
	*Award
}

func (t *InitiatorView) Call(context view.Context) (any, error) {
	// BI and the bank exchange the recipient identities that will own the DFABI (bank) and the RD (BI).
	me, bank, err := ttx.ExchangeRecipientIdentities(context, "", t.Bank)
	assert.NoError(err, "failed exchanging identities")

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

	// BI checks the request holds exactly the two legs it agreed on.
	assert.NoError(tx.IsValid(context.Context()), "failed verifying transaction")
	outputs, err := tx.Outputs(context.Context())
	assert.NoError(err, "failed getting outputs")
	got := outputs.ByRecipient(bank).ByType(t.IssueType)
	assert.Equal(0, got.Sum().Cmp(new(big.Int).SetUint64(t.IssueAmount)), "DFABI output for the bank is not the amount awarded")
	got = outputs.ByRecipient(me).ByType(t.PayType)
	assert.Equal(0, got.Sum().Cmp(new(big.Int).SetUint64(t.PayAmount)), "RD output for BI is not the price")

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
// It mirrors Panurus's SwapResponderView.
type ResponderView struct{}

func (t *ResponderView) Call(context view.Context) (any, error) {
	_, _, err := ttx.RespondExchangeRecipientIdentities(context)
	assert.NoError(err, "failed getting identity")

	tx, action, err := ttx.ReceiveAction(context)
	assert.NoError(err, "failed receiving action")

	wallet := ttx.MyWalletFromTx(context, tx)
	assert.NotNil(wallet, "default wallet not found")
	err = tx.Transfer(context.Context(), wallet, action.Type, []uint64{action.Amount}, []view.Identity{action.Recipient})
	assert.NoError(err, "failed appending transfer")

	_, err = context.RunView(ttx.NewCollectActionsResponderView(tx, action))
	assert.NoError(err, "failed responding to action collect")

	_, err = context.RunView(ttx.NewEndorseView(tx))
	assert.NoError(err, "failed endorsing transaction")

	_, err = context.RunView(ttx.NewFinalityView(tx))
	assert.NoError(err, "new tokens were not committed")

	return tx.ID(), nil
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
