// Package report lets banks report their token transactions to BI after finality.
//
// The public parameters list no auditor, so BI neither co-signs nor sees bank-to-bank transactions while they
// happen (that is what lets banks transact while BI is offline). Instead the bank that initiated a transaction
// sends BI the full token request: the actions plus the metadata holding the openings (amounts, token types,
// blinding factors) and the owners' audit information. BI runs the check a Panurus auditor runs (AuditCheck: the
// openings must match the commitments in the request) and stores the request in its audit store, whose finality
// listener then compares it with the token request hash on the ledger. A forged or altered report is refused; a
// missing one is found by `driver report`, which lists every transaction no node got recorded.
//
// The initiator's copy is complete. A receiver's copy only holds the receiver's own openings and is refused, so
// nodes may report everything they hold. Reports must arrive in causal order (BI needs the openings of a
// transaction's inputs from an earlier report); a refused report is simply sent again later.
package report

import (
	"encoding/json"
	"time"

	"github.com/LFDT-Panurus/panurus/token"
	"github.com/LFDT-Panurus/panurus/token/services/auditor"
	"github.com/LFDT-Panurus/panurus/token/services/storage/db/sql/query/pagination"
	"github.com/LFDT-Panurus/panurus/token/services/storage/ttxdb"
	"github.com/LFDT-Panurus/panurus/token/services/ttx"
	"github.com/LFDT-Panurus/panurus/token/services/utils/json/session"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
	"github.com/hyperledger-labs/fabric-smart-client/platform/common/driver"
	dig2 "github.com/hyperledger-labs/fabric-smart-client/platform/common/sdk/dig"
	"github.com/hyperledger-labs/fabric-smart-client/platform/common/utils/collections/iterators"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/services/id"
	viewregistry "github.com/hyperledger-labs/fabric-smart-client/platform/view/services/view"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/view"
)

// BI is the FSC node that receives the reports (BI's issuer node).
const BI = "issuer"

// Outcomes BI answers per transaction id; anything else is the reason the report was refused.
const (
	Recorded        = "recorded"
	AlreadyRecorded = "already recorded"
)

const timeout = 3 * time.Minute

// Report is the input of the "report" view: one transaction id, or empty for every confirmed transaction in the
// node's transaction store. The view returns BI's outcome per transaction id.
type Report struct {
	TxID string
}

type item struct {
	TxID    string
	Request []byte
}

// View sends the token requests to BI and returns BI's outcomes.
type View struct {
	*Report
	bi bool // this node is BI: record directly, FSC cannot open a session to itself
}

func (v *View) Call(ctx view.Context) (any, error) {
	tms, err := token.GetManagementService(ctx)
	if err != nil {
		return nil, err
	}
	db, err := ttxdb.GetByTMSId(ctx, tms.ID())
	if err != nil {
		return nil, err
	}
	var items []item
	if v.TxID != "" {
		raw, err := db.GetTokenRequest(ctx.Context(), v.TxID)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, errors.Errorf("no token request stored for [%s]", v.TxID)
		}
		items = append(items, item{TxID: v.TxID, Request: raw})
	} else {
		it, err := db.TokenRequests(ctx.Context(), ttxdb.QueryTokenRequestsParams{Statuses: []ttxdb.TxStatus{ttxdb.Confirmed}})
		if err != nil {
			return nil, err
		}
		defer it.Close()
		for {
			r, err := it.Next()
			if err != nil {
				return nil, err
			}
			if r == nil {
				break
			}
			items = append(items, item{TxID: r.TxID, Request: r.TokenRequest})
		}
	}

	if v.bi {
		return recordAll(ctx, items), nil
	}
	idp, err := id.GetProvider(ctx)
	if err != nil {
		return nil, err
	}
	s, err := session.NewJSON(ctx, v, idp.Identity(BI))
	if err != nil {
		return nil, errors.WithMessagef(err, "BI unreachable")
	}
	if err := s.Send(items); err != nil {
		return nil, errors.WithMessagef(err, "BI unreachable")
	}
	out := map[string]string{}
	if err := s.ReceiveWithTimeout(&out, timeout); err != nil {
		return nil, errors.WithMessagef(err, "no answer from BI")
	}

	return out, nil
}

// Responder runs on BI.
type Responder struct{}

func (r *Responder) Call(ctx view.Context) (any, error) {
	s := session.JSON(ctx)
	var items []item
	if err := s.ReceiveWithTimeout(&items, timeout); err != nil {
		return nil, err
	}

	return nil, s.Send(recordAll(ctx, items))
}

func recordAll(ctx view.Context, items []item) map[string]string {
	out := map[string]string{}
	for _, it := range items {
		out[it.TxID] = record(ctx, it)
	}

	return out
}

// record checks one reported token request and stores it in BI's audit store.
func record(ctx view.Context, it item) string {
	tms, err := token.GetManagementService(ctx)
	if err != nil {
		return err.Error()
	}
	a := auditor.GetByTMSID(ctx, tms.ID())
	if a == nil {
		return "no audit store on this node"
	}
	if raw, err := a.GetTokenRequest(ctx.Context(), it.TxID); err == nil && raw != nil {
		return AlreadyRecorded
	}
	req, err := tms.NewFullRequestFromBytes(it.Request)
	if err != nil {
		return err.Error()
	}
	if string(req.Anchor) != it.TxID {
		return "token request belongs to another transaction"
	}
	if err := a.Validate(ctx.Context(), req); err != nil {
		return err.Error()
	}
	if err := a.Append(ctx.Context(), &tx{req: req, id: tms.ID()}); err != nil {
		return err.Error()
	}

	return Recorded
}

// tx is the auditor.Transaction view of a reported request.
type tx struct {
	req *token.Request
	id  token.TMSID
}

func (t *tx) ID() string              { return string(t.req.Anchor) }
func (t *tx) Network() string         { return t.id.Network }
func (t *tx) Channel() string         { return t.id.Channel }
func (t *tx) Namespace() string       { return t.id.Namespace }
func (t *tx) Request() *token.Request { return t.req }

// AuditedView lists BI's audit records (one per movement: sender, recipient, type, amount, ledger status).
type AuditedView struct{}

func (v *AuditedView) Call(ctx view.Context) (any, error) {
	tms, err := token.GetManagementService(ctx)
	if err != nil {
		return nil, err
	}
	a, err := ttx.NewAuditorFromTMSID(ctx, tms.ID())
	if err != nil {
		return nil, err
	}
	const size = 1000 // the store's maximum page size
	var page driver.Pagination
	page, err = pagination.Offset(0, size)
	if err != nil {
		return nil, err
	}
	var all []*ttxdb.TransactionRecord
	for {
		it, err := a.Transactions(ctx.Context(), ttxdb.QueryTransactionsParams{}, page)
		if err != nil {
			return nil, err
		}
		recs, err := iterators.ReadAllPointers(it.Items)
		if err != nil {
			return nil, err
		}
		all = append(all, recs...)
		if len(recs) < size {
			return all, nil
		}
		if page, err = page.Next(); err != nil {
			return nil, err
		}
	}
}

type factory struct{ bi bool }

func (f *factory) NewView(in []byte) (view.View, error) {
	v := &View{Report: &Report{}, bi: f.bi}
	if err := json.Unmarshal(in, v.Report); err != nil {
		return nil, err
	}

	return v, nil
}

type auditedFactory struct{}

func (f *auditedFactory) NewView([]byte) (view.View, error) { return &AuditedView{}, nil }

// SDK adds the "report" view to a node; on BI also the responder and the "audited" view.
type SDK struct {
	dig2.SDK
	bi bool
}

func NewFrom(sdk dig2.SDK, bi bool) *SDK { return &SDK{SDK: sdk, bi: bi} }

func (p *SDK) Install() error {
	if err := p.SDK.Install(); err != nil {
		return err
	}

	return p.SDK.Container().Invoke(func(registry *viewregistry.Registry) error {
		errs := []error{registry.RegisterFactory("report", &factory{bi: p.bi})}
		if p.bi {
			errs = append(errs,
				registry.RegisterResponder(&Responder{}, &View{}),
				registry.RegisterFactory("audited", &auditedFactory{}))
		}

		return errors.Join(errs...)
	})
}
