package rdbi

import (
	"github.com/LFDT-Panurus/panurus/integration/token/fungible"
	token4 "github.com/LFDT-Panurus/panurus/token"
	. "github.com/onsi/ginkgo/v2"
)

const (
	rd    = "RD"
	dfabi = "DFABI-2027A"
)

var _ = Describe("RD and DFABI on Fabric-X", func() {
	ts, sel := newTestSuite()
	BeforeEach(ts.Setup)
	AfterEach(ts.TearDown)

	It("issue, transfer, burn and DvP; only BI and the counterparties see them", func() {
		bi := sel.Get(biNode)
		bank2, bank3, bank4 := sel.Get("bank2"), sel.Get("bank3"), sel.Get("bank4")
		endorsers := fungible.GetEndorsers(ts.II, sel)
		fungible.RegisterAuditor(ts.II, bi)

		// Issuance: BI issues RD and DFABI (BI is also the DFABI custodian).
		fungible.IssueSuccessfulCash(ts.II, "", rd, 1000, bank2, bi, true, bi, endorsers...)
		fungible.IssueSuccessfulCash(ts.II, "", rd, 1000, bank3, bi, true, bi, endorsers...)
		fungible.IssueSuccessfulCash(ts.II, "", dfabi, 100, bank3, bi, true, bi, endorsers...)
		fungible.CheckBalanceAndHolding(ts.II, bank2, "", rd, 1000, bi)
		fungible.CheckBalanceAndHolding(ts.II, bank3, "", rd, 1000, bi)
		fungible.CheckBalanceAndHolding(ts.II, bank3, "", dfabi, 100, bi)

		// Transfer RD and DFABI between banks.
		fungible.TransferCash(ts.II, bank2, "", rd, 100, bank3, bi)
		fungible.TransferCash(ts.II, bank3, "", dfabi, 10, bank2, bi)
		fungible.CheckBalanceAndHolding(ts.II, bank2, "", rd, 900, bi)
		fungible.CheckBalanceAndHolding(ts.II, bank3, "", rd, 1100, bi)
		fungible.CheckBalanceAndHolding(ts.II, bank2, "", dfabi, 10, bi)
		fungible.CheckBalanceAndHolding(ts.II, bank3, "", dfabi, 90, bi)

		// DvP: one atomic token request, bank2 pays RD for DFABI from bank3.
		fungible.SwapCash(ts.II, bank2, "", rd, 200, dfabi, 20, bank3, bi)
		fungible.CheckBalanceAndHolding(ts.II, bank2, "", rd, 700, bi)
		fungible.CheckBalanceAndHolding(ts.II, bank3, "", rd, 1300, bi)
		fungible.CheckBalanceAndHolding(ts.II, bank2, "", dfabi, 30, bi)
		fungible.CheckBalanceAndHolding(ts.II, bank3, "", dfabi, 70, bi)

		// Burn RD: redeem is authorised by the auditor for BI's issuer identity.
		tms := fungible.GetTMSByNetworkName(ts.II, "default")
		tmsID := &token4.TMSID{Network: tms.Network, Channel: tms.Channel, Namespace: tms.Namespace}
		fungible.AuthorizeRedeemIssuer(ts.II, bi, fungible.GetIssuerIdentity(tms, bi.Id()))
		fungible.RedeemCashForTMSID(ts.II, bank2, "", rd, 50, bi, bi, tmsID)
		fungible.CheckBalanceAndHolding(ts.II, bank2, "", rd, 650, bi)

		// Privacy: bank4 took part in nothing, so it holds nothing and has no transaction record.
		fungible.CheckBalance(ts.II, bank4, "", rd, 0)
		fungible.CheckBalance(ts.II, bank4, "", dfabi, 0)
		fungible.CheckAcceptedTransactions(ts.II, bank4, "", nil, nil, nil, nil)
	})
})
