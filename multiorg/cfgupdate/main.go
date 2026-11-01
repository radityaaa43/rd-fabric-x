// Command cfgupdate turns the live Fabric-X network into a multi-bank network: the orderer orgs
// OrdererOrg2..4 (parties 2..4, the banks) join the Application group next to Org1 (BI, party 1),
// and LifecycleEndorsement requires all four orgs.
//
//	cfgupdate genesis       -block <current config block> -out <new genesis block>
//	cfgupdate check-genesis -block <new genesis block> -msp <Org1 admin msp dir> [cert.pem ...]
//	cfgupdate build         -block <current config block> -msp <Org1 admin msp dir> -out <envelope>
//	cfgupdate verify        -block <current config block> -msp <Org1 admin msp dir> -env <envelope>
//
// The channel deployed by the hyperledger.fabricx Ansible collection 0.8.26 has no capabilities, so
// its MSPs run as MSPv1_0, which does not recognise the admin NodeOU: no identity satisfies any
// Admins policy and no config update can pass. genesis therefore writes a new genesis block (same
// orgs, crypto and Arma config, plus capabilities as in the fabric-x-orderer v1.0.4 sample
// configtx.yaml and the changes above); it needs a channel reset. build/verify are the config-update
// path for channels that have capabilities.
//
// verify and check-genesis run, without contacting the network, the checks a router runs before it
// forwards a config request to consensus (fabric-x-orderer v1.0.4 node/router/config_submitter.go)
// or before it starts from a block, plus the committer's parse of LifecycleEndorsement
// (fabric-x-committer v1.0.4).
package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mb "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/common/policydsl"
	"github.com/hyperledger/fabric-x-common/common/util"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/tools/configtxlator/update"
	"github.com/hyperledger/fabric-x-committer/service/verifier/policy"
	orderpolicy "github.com/hyperledger/fabric-x-orderer/common/policy"
	"github.com/hyperledger/fabric-x-orderer/common/types"
	"github.com/hyperledger/fabric-x-orderer/config/verify"
	"github.com/hyperledger/fabric-x-orderer/node/crypto"
	"google.golang.org/protobuf/proto"
)

const channelID = "arma"

var (
	bankOrgs  = []string{"OrdererOrg2", "OrdererOrg3", "OrdererOrg4"}
	allMSPIDs = []string{"Org1MSP", "OrdererOrg2MSP", "OrdererOrg3MSP", "OrdererOrg4MSP"}
)

func must(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", what, err)
		os.Exit(1)
	}
}

// signer signs as an MSP identity in the Fabric-X identity format (msppb.Identity).
type signer struct {
	key     crypto.ECDSASigner
	creator []byte
}

func (s signer) Sign(msg []byte) ([]byte, error) { return s.key.Sign(msg) }
func (s signer) Serialize() ([]byte, error)      { return s.creator, nil }

func loadSigner(mspDir, mspID string) signer {
	cert, err := os.ReadFile(filepath.Join(mspDir, "signcerts", "cert.pem"))
	must(err, "read signcert")
	keys, err := filepath.Glob(filepath.Join(mspDir, "keystore", "*_sk"))
	must(err, "glob keystore")
	if len(keys) != 1 {
		must(fmt.Errorf("want 1 key in %s/keystore, got %d", mspDir, len(keys)), "keystore")
	}
	raw, err := os.ReadFile(keys[0])
	must(err, "read key")
	block, _ := pem.Decode(raw)
	if block == nil {
		must(fmt.Errorf("no PEM block in %s", keys[0]), "decode key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	must(err, "parse key")
	creator, err := proto.Marshal(msppb.NewIdentity(mspID, cert))
	must(err, "marshal creator")
	return signer{key: crypto.ECDSASigner(*k.(*ecdsa.PrivateKey)), creator: creator}
}

// configEnvelope reads the CONFIG envelope (tx 0) of a config block and its config.
func configEnvelope(path string) (*cb.Envelope, *cb.Config) {
	raw, err := os.ReadFile(path)
	must(err, "read block")
	block := &cb.Block{}
	must(proto.Unmarshal(raw, block), "unmarshal block")
	env, err := protoutil.ExtractEnvelope(block, 0)
	must(err, "extract envelope")
	payload, err := protoutil.UnmarshalPayload(env.Payload)
	must(err, "unmarshal payload")
	ce := &cb.ConfigEnvelope{}
	must(proto.Unmarshal(payload.Data, ce), "unmarshal config envelope")
	return env, ce.Config
}

// target returns the current config with the banks added to the Application group (same MSP and
// org policies as in the Orderer group) and LifecycleEndorsement set to all four orgs.
func target(current *cb.Config) *cb.Config {
	next := proto.Clone(current).(*cb.Config)
	app := next.ChannelGroup.Groups["Application"]
	ord := next.ChannelGroup.Groups["Orderer"]
	for _, org := range bankOrgs {
		if _, ok := app.Groups[org]; ok {
			must(fmt.Errorf("%s already in Application", org), "target")
		}
		g := proto.Clone(ord.Groups[org]).(*cb.ConfigGroup)
		delete(g.Values, "Endpoints") // orderer-only value
		app.Groups[org] = g
	}
	lifecycle := policydsl.SignedByNOutOfGivenRole(int32(len(allMSPIDs)), mb.MSPRole_MEMBER, allMSPIDs)
	app.Policies["LifecycleEndorsement"].Policy = &cb.Policy{
		Type:  int32(cb.Policy_SIGNATURE),
		Value: protoutil.MarshalOrPanic(lifecycle),
	}
	return next
}

// capabilities as in fabric-x-orderer v1.0.4 testutil/fabric/sampleconfig/configtx.yaml
var capabilities = map[string]string{"": "V3_0", "Orderer": "V2_0", "Application": "V2_5"}

func setCapabilities(cfg *cb.Config) {
	for group, capability := range capabilities {
		g := cfg.ChannelGroup
		if group != "" {
			g = g.Groups[group]
		}
		if g.Values == nil {
			g.Values = map[string]*cb.ConfigValue{}
		}
		g.Values[channelconfig.CapabilitiesKey] = &cb.ConfigValue{
			ModPolicy: channelconfig.AdminsPolicyKey,
			Value:     protoutil.MarshalOrPanic(&cb.Capabilities{Capabilities: map[string]*cb.Capability{capability: {}}}),
		}
	}
}

// genesis writes a copy of the current config block (block 0) with the target config and capabilities.
func genesis(blockPath, out string) {
	raw, err := os.ReadFile(blockPath)
	must(err, "read block")
	block := &cb.Block{}
	must(proto.Unmarshal(raw, block), "unmarshal block")
	if block.Header.Number != 0 {
		must(fmt.Errorf("block %d is not a genesis block", block.Header.Number), "genesis")
	}
	env, err := protoutil.ExtractEnvelope(block, 0)
	must(err, "extract envelope")
	payload, err := protoutil.UnmarshalPayload(env.Payload)
	must(err, "unmarshal payload")
	ce := &cb.ConfigEnvelope{}
	must(proto.Unmarshal(payload.Data, ce), "unmarshal config envelope")

	ce.Config = target(ce.Config)
	setCapabilities(ce.Config)
	payload.Data = protoutil.MarshalOrPanic(ce)
	env.Payload = protoutil.MarshalOrPanic(payload)
	block.Data.Data[0] = protoutil.MarshalOrPanic(env)
	block.Header.DataHash = protoutil.ComputeBlockDataHash(block.Data)
	must(os.WriteFile(out, protoutil.MarshalOrPanic(block), 0o600), "write genesis")
	fmt.Printf("genesis block written to %s\n", out)
}

// checkGenesis runs the start-up checks of orderer and committer on the new genesis block, checks
// that the Org1 admin now satisfies Org1's Admins policy, and validates every node identity listed
// in the config plus the given client certificates against the new MSPs.
func checkGenesis(blockPath, mspDir string, certs []string) {
	bccsp := factory.GetDefault()
	env, cfg := configEnvelope(blockPath)
	bundle, err := orderpolicy.BuildBundleFromBlock(env, bccsp)
	must(err, "bundle (orderer start-up checks)")
	rules := &verify.DefaultOrdererRules{}
	for p := types.PartyID(1); p <= 4; p++ {
		must(rules.ValidateNewConfig(env, bccsp, p), fmt.Sprintf("ValidateNewConfig party %d", p))
	}
	_, err = policy.ParseLifecycleEndorsementPolicy(bundle)
	must(err, "committer ParseLifecycleEndorsementPolicy")
	fmt.Println("PASS bundle, capabilities, Arma ValidateNewConfig (parties 1..4), committer LifecycleEndorsement")
	fmt.Println("MSP version for this channel:", bundle.ChannelConfig().Capabilities().MSPVersion())

	// the reason for the reset: the admin must satisfy Admins policies now
	admin := loadSigner(mspDir, "Org1MSP")
	adminID := &msppb.Identity{}
	must(proto.Unmarshal(admin.creator, adminID), "admin identity")
	msg := []byte("admin policy check")
	sig, err := admin.Sign(msg)
	must(err, "sign")
	signed := []*protoutil.SignedData{{Data: msg, Identity: adminID, Signature: sig}}
	pol, _ := bundle.PolicyManager().GetPolicy("/Channel/Application/Org1/Admins")
	must(pol.EvaluateSignedData(signed), "/Channel/Application/Org1/Admins by Org1 admin")
	fmt.Println("PASS Org1 admin satisfies /Channel/Application/Org1/Admins")
	// with four application orgs, MAJORITY means BI alone can no longer change the Application group
	pol, _ = bundle.PolicyManager().GetPolicy("/Channel/Application/Admins")
	if pol.EvaluateSignedData(signed) == nil {
		must(fmt.Errorf("Org1 admin alone satisfies it"), "/Channel/Application/Admins must need 3 of 4 orgs")
	}
	fmt.Println("PASS /Channel/Application/Admins is not satisfied by Org1 admin alone (MAJORITY of 4)")

	// every node certificate the config knows (known_certs) must still validate under the new MSP version
	n := 0
	for _, groupName := range []string{"Orderer", "Application"} {
		for orgName, org := range cfg.ChannelGroup.Groups[groupName].Groups {
			mc := &mb.MSPConfig{}
			must(proto.Unmarshal(org.Values[channelconfig.MSPKey].Value, mc), "msp config "+orgName)
			fc := &msppb.FabricMSPConfig{} // Fabric-X variant, carries known_certs
			must(proto.Unmarshal(mc.Config, fc), "fabric msp config "+orgName)
			for _, cert := range fc.KnownCerts {
				validate(bundle, fc.Name, cert)
				n++
			}
		}
	}
	for _, path := range certs {
		cert, err := os.ReadFile(path)
		must(err, "read "+path)
		validate(bundle, "", cert)
		n++
	}
	fmt.Printf("PASS %d identities (known_certs of all orgs + %d given) validate under the new MSPs\n", n, len(certs))
	app, _ := bundle.ApplicationConfig()
	var orgs []string
	for name, org := range app.Organizations() {
		orgs = append(orgs, name+"("+org.MSPID()+")")
	}
	sort.Strings(orgs)
	fmt.Println("Application orgs:", orgs)
}

// validate checks a certificate against the MSP that issued it (mspID "" = try every MSP).
func validate(bundle *channelconfig.Bundle, mspID string, cert []byte) {
	ids := []string{mspID}
	if mspID == "" {
		ids = nil
		msps, err := bundle.MSPManager().GetMSPs()
		must(err, "msps")
		for id := range msps {
			ids = append(ids, id)
		}
	}
	var last error
	for _, id := range ids {
		ident, err := bundle.MSPManager().DeserializeIdentity(msppb.NewIdentity(id, cert))
		if err == nil {
			if err = ident.Validate(); err == nil {
				return
			}
		}
		last = err
	}
	block, _ := pem.Decode(cert)
	subject := "?"
	if block != nil {
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			subject = c.Subject.String()
		}
	}
	must(last, "validate "+subject)
}

func build(blockPath, mspDir, out string) {
	_, current := configEnvelope(blockPath)
	cu, err := update.Compute(current, target(current))
	must(err, "compute update")
	cu.ChannelId = channelID
	cuBytes := protoutil.MarshalOrPanic(cu)

	admin := loadSigner(mspDir, "Org1MSP")
	sh := protoutil.MakeSignatureHeader(admin.creator, protoutil.CreateNonceOrPanic())
	cs := &cb.ConfigSignature{SignatureHeader: protoutil.MarshalOrPanic(sh)}
	cs.Signature, err = admin.Sign(util.ConcatenateBytes(cs.SignatureHeader, cuBytes))
	must(err, "sign config update")
	cue := &cb.ConfigUpdateEnvelope{ConfigUpdate: cuBytes, Signatures: []*cb.ConfigSignature{cs}}

	env, err := protoutil.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelID, admin, cue, 0, 0)
	must(err, "envelope")
	raw := protoutil.MarshalOrPanic(env)
	must(os.WriteFile(out, raw, 0o600), "write envelope")
	fmt.Printf("config update envelope written to %s (%d bytes)\n", out, len(raw))
}

func verifyUpdate(blockPath, mspDir, envPath string) {
	bccsp := factory.GetDefault()
	currentEnv, current := configEnvelope(blockPath)
	bundle, err := orderpolicy.BuildBundleFromBlock(currentEnv, bccsp)
	must(err, "current bundle")

	raw, err := os.ReadFile(envPath)
	must(err, "read envelope")
	upd := &cb.Envelope{}
	must(proto.Unmarshal(raw, upd), "unmarshal envelope")

	// 1. mod_policy against the current config, new bundle against the old one (router and consenter)
	newCE, err := (&orderpolicy.DefaultConfigUpdateProposer{}).AuthorizeAndVerifyConfigUpdate(upd, bundle, bccsp)
	must(err, "authorize config update")
	fmt.Println("PASS mod_policy satisfied, new bundle valid against the current one")

	// 2. Arma rules on the CONFIG envelope the router builds from it
	cfgEnv, err := protoutil.CreateSignedEnvelope(cb.HeaderType_CONFIG, channelID, loadSigner(mspDir, "Org1MSP"), newCE, 0, 0)
	must(err, "config envelope")
	rules := &verify.DefaultOrdererRules{}
	for p := types.PartyID(1); p <= 4; p++ {
		must(rules.ValidateNewConfig(cfgEnv, bccsp, p), fmt.Sprintf("ValidateNewConfig party %d", p))
	}
	must(rules.ValidateTransition(bundle, cfgEnv, bccsp), "ValidateTransition")
	fmt.Println("PASS Arma ValidateNewConfig (parties 1..4) and ValidateTransition")

	// 3. committer: new bundle and the namespace verifier built from LifecycleEndorsement
	newBundle, err := channelconfig.NewBundle(channelID, newCE.Config, bccsp)
	must(err, "new bundle")
	_, err = policy.ParseLifecycleEndorsementPolicy(newBundle)
	must(err, "committer ParseLifecycleEndorsementPolicy")
	fmt.Println("PASS committer parses the new LifecycleEndorsement policy")

	// 4. what changed
	app, _ := newBundle.ApplicationConfig()
	var orgs []string
	for name, org := range app.Organizations() {
		orgs = append(orgs, name+"("+org.MSPID()+")")
	}
	sort.Strings(orgs)
	fmt.Println("Application orgs:", orgs)
	lp := &cb.SignaturePolicyEnvelope{}
	must(proto.Unmarshal(newCE.Config.ChannelGroup.Groups["Application"].Policies["LifecycleEndorsement"].Policy.Value, lp), "lifecycle policy")
	fmt.Printf("LifecycleEndorsement: %d-of-%d MEMBER of", lp.Rule.GetNOutOf().GetN(), len(lp.Identities))
	for _, id := range lp.Identities {
		r := &mb.MSPRole{}
		must(proto.Unmarshal(id.Principal, r), "principal")
		fmt.Printf(" %s", r.MspIdentifier)
	}
	fmt.Println()
	fmt.Println("Orderer group unchanged:", proto.Equal(newCE.Config.ChannelGroup.Groups["Orderer"], current.ChannelGroup.Groups["Orderer"]))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: cfgupdate build|verify [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	blockPath := fs.String("block", "", "current config block")
	mspDir := fs.String("msp", "", "Org1 admin MSP dir")
	out := fs.String("out", "update.env", "output envelope (build)")
	envPath := fs.String("env", "update.env", "envelope to check (verify)")
	must(fs.Parse(os.Args[2:]), "flags")
	switch os.Args[1] {
	case "genesis":
		genesis(*blockPath, *out)
	case "check-genesis":
		checkGenesis(*blockPath, *mspDir, fs.Args())
	case "build":
		build(*blockPath, *mspDir, *out)
	case "verify":
		verifyUpdate(*blockPath, *mspDir, *envPath)
	default:
		must(fmt.Errorf("unknown command %q", os.Args[1]), "usage")
	}
}
