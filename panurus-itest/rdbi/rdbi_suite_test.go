package rdbi

import (
	"testing"

	integration2 "github.com/LFDT-Panurus/panurus/integration"
	"github.com/LFDT-Panurus/panurus/integration/nwo/token"
	token2 "github.com/LFDT-Panurus/panurus/integration/token"
	fsc "github.com/hyperledger-labs/fabric-smart-client/integration"
	"github.com/hyperledger-labs/fabric-smart-client/integration/nwo/fabricx"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRDBI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "RD/DFABI on Fabric-X (Panurus ZKAT-DLOG) Suite")
}

// publicParamsInstaller installs the public parameters recorded while the network started.
type publicParamsInstaller interface {
	InstallPendingPublicParams()
}

type testSuite struct {
	*fsc.TestSuite
	installer publicParamsInstaller
}

// Setup starts the network, then installs the fabricx public parameters (needs the FSC nodes up).
func (s *testSuite) Setup() {
	s.TestSuite.Setup()
	s.installer.InstallPendingPublicParams()
}

func newTestSuite() (*testSuite, *token2.ReplicaSelector) {
	_, selector := token2.NewReplicationOptions(token2.None, append([]string{biNode}, bankNodes...)...)
	ts := &testSuite{}
	ts.TestSuite = fsc.NewTestSuite(func() (*fsc.Infrastructure, error) {
		i, err := fsc.New(integration2.ZKATDLogFungible.StartPortForNode(), "./testdata", topologies()...)
		i.DeleteOnStart = true
		i.DeleteOnStop = false
		i.RegisterPlatformFactory(fabricx.NewPlatformFactory())
		tokenPlatformFactory := token.NewPlatformFactory(i)
		i.RegisterPlatformFactory(tokenPlatformFactory)
		i.Generate()
		ts.installer = tokenPlatformFactory

		return i, err
	})

	return ts, selector
}
