// Package rdbi holds the Panurus integration test for the RD/DFABI privacy track on Fabric-X:
// BI is issuer of both tokens and DFABI custodian; bank2..bank4 are token owners. Every institution
// is its own organisation with its own FSC endorser, and the token namespace needs 3 of the 4
// endorsements, so transfers keep working while BI or any one bank is down. There is no auditor:
// with auditors in the public parameters Panurus requires an auditor signature on every token
// request, which would stop all transfers whenever BI is offline.
// It is copied into a pinned Panurus checkout (see ../Makefile) and mirrors
// integration/token/fungible/topology ("one endorser per org").
package rdbi

import (
	"github.com/LFDT-Panurus/panurus/integration/nwo/token"
	fabric2 "github.com/LFDT-Panurus/panurus/integration/nwo/token/fabric"
	"github.com/LFDT-Panurus/panurus/integration/nwo/token/generators/crypto/zkatdlognoghv1"
	token2 "github.com/LFDT-Panurus/panurus/integration/token"
	"github.com/LFDT-Panurus/panurus/integration/token/common"
	"github.com/LFDT-Panurus/panurus/integration/token/common/sdk/fxdlog"
	"github.com/LFDT-Panurus/panurus/integration/token/fungible/sdk/endorser"
	issuer2 "github.com/LFDT-Panurus/panurus/integration/token/fungible/sdk/issuer"
	"github.com/LFDT-Panurus/panurus/integration/token/fungible/sdk/party"
	endorsementfsc "github.com/LFDT-Panurus/panurus/token/services/network/fabric/endorsement/fsc"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/api"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/fabric"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/fabricx"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/fsc"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/fsc/support/libp2p"
)

const (
	// biNode must be "issuer": Panurus's fabricx backend installs the public parameters through the
	// FSC node of that name (nwo/token/fabricx issuerClientID).
	biNode = "issuer"
)

// orgs: BI is Org1, bank2..bank4 are Org2..Org4 (on the live network Org1MSP and OrdererOrg2..4MSP,
// the organisations of orderer parties 1..4).
var (
	orgs          = []string{"Org1", "Org2", "Org3", "Org4"}
	bankNodes     = []string{"bank2", "bank3", "bank4"}
	endorserNodes = []string{"endorser-1", "endorser-2", "endorser-3", "endorser-4"}
)

// topology: one organisation per institution, each with its own FSC endorser; namespace policy 3 of 4.
func topologies() []api.Topology {
	backend := fabricx.NewDefaultTopology()
	backend.EnableIdemix()
	backend.AddOrganizationsByName(orgs...)
	backend.SetNamespaceApproverOrgs("Org1")

	fscTopology := fsc.NewTopology()
	fscTopology.P2PCommunicationType = fsc.WebSocket
	fscTopology.SetLogging(token2.RunnerDebug("info"), "")

	bi := fscTopology.AddNodeByName(biNode).AddOptions(
		fabric.WithOrganization(orgs[0]),
		fabric.WithAnonymousIdentity(),
		token.WithDefaultIssuerIdentity(false),
		token.WithDefaultOwnerIdentity(),
		fabric.WithDefaultSqlitePersistence(),
	)
	for i, name := range bankNodes {
		fscTopology.AddNodeByName(name).AddOptions(
			fabric.WithOrganization(orgs[i+1]),
			fabric.WithAnonymousIdentity(),
			token.WithDefaultOwnerIdentity(),
			fabric.WithDefaultSqlitePersistence(),
		).AddSDKWithBase(&fxdlog.SDK{}, &party.SDK{})
	}

	for i, name := range endorserNodes {
		fscTopology.AddNodeByName(name).AddOptions(
			fabric.WithOrganization(orgs[i]),
			fabric2.WithEndorserRole(),
			fabric.WithDefaultSqlitePersistence(),
		).AddSDKWithBase(&fxdlog.SDK{}, &endorser.SDK{})
	}

	tokenTopology := token.NewTopology()
	tms := tokenTopology.AddTMS(fscTopology.ListNodes(), backend, backend.Channels[0].Name, zkatdlognoghv1.DriverIdentifier)
	tms.SetNamespace("token_chaincode")
	common.SetDefaultParams(tms, common.TMSOpts{TokenSDKDriver: zkatdlognoghv1.DriverIdentifier, Aries: true})
	fabric2.WithFSCEndorsers(tms, endorserNodes...)
	fabric2.WithFSCEndorsementPolicyType(tms, endorsementfsc.NamespacePolicy)
	fabric2.WithNamespacePolicy(tms, "OutOf(3, 'Org1MSP.member', 'Org2MSP.member', 'Org3MSP.member', 'Org4MSP.member')")
	fabric2.SetOrgs(tms, orgs...)
	tms.AddIssuer(bi)

	bi.AddSDKWithBase(&fxdlog.SDK{}, &issuer2.SDK{})
	fscTopology.SetBootstrapNode(fscTopology.AddNodeByName("lib-p2p-bootstrap-node"))
	fscTopology.ListNodes("lib-p2p-bootstrap-node")[0].AddSDK(&libp2p.SDK{})

	return []api.Topology{backend, tokenTopology, fscTopology}
}
