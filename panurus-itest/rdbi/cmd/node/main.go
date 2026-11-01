// Command node runs one FSC node of the RD/DFABI token network against an existing Fabric-X network.
//
// It is the same composition NWO generates for the integration test (fxdlog base SDK plus one role
// SDK set), so a node behaves exactly like the ones in the passing local test. Start it like NWO
// does:   FSCNODE_CFG_PATH=<dir with core.yaml> RDBI_ROLE=issuer|bank|endorser node start
// (RDBI_ROLE=forward only runs the shim's TCP forwards, see netshim.go).
package main

import (
	"log"
	"os"

	"github.com/LFDT-Panurus/panurus/integration/token/common/sdk/fxdlog"
	endorser "github.com/LFDT-Panurus/panurus/integration/token/fungible/sdk/endorser"
	issuer "github.com/LFDT-Panurus/panurus/integration/token/fungible/sdk/issuer"
	party "github.com/LFDT-Panurus/panurus/integration/token/fungible/sdk/party"
	"github.com/LFDT-Panurus/panurus/integration/token/fungible/rdbi/report"
	fscnode "github.com/hyperledger-labs/fabric-smart-client/node"
)

func main() {
	if err := startNetShim(os.Getenv("RDBI_NETSHIM")); err != nil {
		log.Fatalf("netshim: %v", err)
	}

	if os.Getenv("RDBI_ROLE") == "forward" { // only the TCP forwards of the shim (one process per host)
		select {}
	}

	n := fscnode.New()
	base := fxdlog.NewSDK(n)
	switch role := os.Getenv("RDBI_ROLE"); role {
	case "issuer": // BI: issuer of RD and DFABI, DFABI custodian, receives the banks' reports
		n.InstallSDK(report.NewFrom(issuer.NewFrom(base), true))
	case "bank":
		n.InstallSDK(report.NewFrom(party.NewFrom(base), false))
	case "endorser":
		n.InstallSDK(endorser.NewFrom(base))
	default:
		log.Fatalf("RDBI_ROLE must be issuer, bank or endorser (got %q)", role)
	}
	n.Execute(func() error { return nil })
}
