// Package rdbi holds the Panurus integration test for the RD/DFABI privacy track on Fabric-X:
// BI is issuer of both tokens, DFABI custodian and auditor; bank2..bank4 are token owners.
// It is copied into a pinned Panurus checkout (see ../Makefile) and mirrors
// integration/token/fungible/topology with the dlogx "Auditor = Issuer" shape.
package rdbi

import (
	"github.com/LFDT-Panurus/panurus/integration/nwo/token"
	fabric2 "github.com/LFDT-Panurus/panurus/integration/nwo/token/fabric"
	"github.com/LFDT-Panurus/panurus/integration/nwo/token/generators/crypto/zkatdlognoghv1"
	token2 "github.com/LFDT-Panurus/panurus/integration/token"
	"github.com/LFDT-Panurus/panurus/integration/token/common"
	"github.com/LFDT-Panurus/panurus/integration/token/common/sdk/fxdlog"
	auditor2 "github.com/LFDT-Panurus/panurus/integration/token/fungible/sdk/auditor"
	"github.com/LFDT-Panurus/panurus/integration/token/fungible/sdk/endorser"
	issuer2 "github.com/LFDT-Panurus/panurus/integration/token/fungible/sdk/issuer"
	"github.com/LFDT-Panurus/panurus/integration/token/fungible/sdk/party"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/api"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/fabric"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/fabricx"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/fsc"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/fsc/support/libp2p"
)

const (
	// biNode must be "issuer": Panurus's fabricx backend installs the public parameters through the
	// FSC node of that name (nwo/token/fabricx issuerClientID). BI is that node, plus the "auditor" alias.
	biNode       = "issuer"
	endorserNode = "endorser-1"
)

var bankNodes = []string{"bank2", "bank3", "bank4"}

// topology: BI in Org1 (as the committer operator), banks in Org2, one FSC endorser.
func topologies() []api.Topology {
	backend := fabricx.NewDefaultTopology()
	backend.EnableIdemix()
	backend.AddOrganizationsByName("Org1", "Org2")
	backend.SetNamespaceApproverOrgs("Org1")

	fscTopology := fsc.NewTopology()
	fscTopology.P2PCommunicationType = fsc.WebSocket
	fscTopology.SetLogging(token2.RunnerDebug("info"), "")

	bi := fscTopology.AddNodeByName(biNode).AddOptions(
		fabric.WithOrganization("Org1"),
		fabric.WithAnonymousIdentity(),
		token.WithDefaultIssuerIdentity(false),
		token.WithAuditorIdentity(false),
		fsc.WithAlias("auditor"),
		token.WithDefaultOwnerIdentity(),
		fabric.WithDefaultSqlitePersistence(),
	)
	for _, name := range bankNodes {
		fscTopology.AddNodeByName(name).AddOptions(
			fabric.WithOrganization("Org2"),
			fabric.WithAnonymousIdentity(),
			token.WithDefaultOwnerIdentity(),
			fabric.WithDefaultSqlitePersistence(),
		).AddSDKWithBase(&fxdlog.SDK{}, &party.SDK{})
	}

	endorserTemplate := fscTopology.NewTemplate("endorser")
	endorserTemplate.AddOptions(fabric.WithOrganization("Org1"), fabric2.WithEndorserRole())
	endorser1 := fscTopology.AddNodeFromTemplate(endorserNode, endorserTemplate)
	endorser1.AddOptions(fabric.WithDefaultSqlitePersistence())

	tokenTopology := token.NewTopology()
	tms := tokenTopology.AddTMS(fscTopology.ListNodes(), backend, backend.Channels[0].Name, zkatdlognoghv1.DriverIdentifier)
	tms.SetNamespace("token_chaincode")
	common.SetDefaultParams(tms, common.TMSOpts{TokenSDKDriver: zkatdlognoghv1.DriverIdentifier, Aries: true})
	fabric2.WithFSCEndorsers(tms, endorserNode)
	fabric2.SetOrgs(tms, "Org1")
	tms.AddAuditor(bi)
	tms.AddIssuer(bi)

	bi.AddSDKWithBase(&fxdlog.SDK{}, &issuer2.SDK{}, &auditor2.SDK{})
	endorser1.AddSDKWithBase(&fxdlog.SDK{}, &endorser.SDK{})
	fscTopology.SetBootstrapNode(fscTopology.AddNodeByName("lib-p2p-bootstrap-node"))
	fscTopology.ListNodes("lib-p2p-bootstrap-node")[0].AddSDK(&libp2p.SDK{})

	return []api.Topology{backend, tokenTopology, fscTopology}
}
