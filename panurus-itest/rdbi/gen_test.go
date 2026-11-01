package rdbi

import (
	"os"
	"testing"

	integration2 "github.com/LFDT-Panurus/panurus/integration"
	"github.com/LFDT-Panurus/panurus/integration/nwo/token"
	fsc "github.com/hyperledger-labs/fabric-smart-client/integration"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/fabricx"
	"github.com/onsi/gomega"
)

// TestGenerate only generates the crypto material, public parameters and node configs
// (no processes, no containers). It is the first step of the live deployment: scripts/assemble.py
// turns its output into configs that point at an existing Fabric-X network.
// Run it with RDBI_GENERATE=<output dir>; it is skipped otherwise.
func TestGenerate(t *testing.T) {
	gomega.RegisterTestingT(t)
	out := os.Getenv("RDBI_GENERATE")
	if out == "" {
		t.Skip("RDBI_GENERATE not set")
	}
	i, err := fsc.New(integration2.ZKATDLogFungible.StartPortForNode(), out, topologies()...)
	if err != nil {
		t.Fatal(err)
	}
	i.DeleteOnStart = true
	i.DeleteOnStop = false
	i.RegisterPlatformFactory(fabricx.NewPlatformFactory())
	i.RegisterPlatformFactory(token.NewPlatformFactory(i))
	i.Generate()
}
