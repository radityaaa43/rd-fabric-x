package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mb "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"google.golang.org/protobuf/proto"
)

var banks = []string{"org1", "org2", "org3", "org4"}

// orgGroup is a bank org as the pinned createBlock writes it: a Fabric MSP value plus Readers/Writers/Admins/Endorsement policies.
func orgGroup(id string, admins, known int) *cb.ConfigGroup {
	fc := &msppb.FabricMSPConfig{Name: id}
	for i := 0; i < admins; i++ {
		fc.Admins = append(fc.Admins, []byte("admin-cert-"+id))
	}
	for i := 0; i < known; i++ {
		fc.KnownCerts = append(fc.KnownCerts, []byte("endorser-cert-"+id))
	}
	mc := &mb.MSPConfig{Type: 0, Config: protoutil.MarshalOrPanic(fc)}
	g := &cb.ConfigGroup{
		Values:   map[string]*cb.ConfigValue{channelconfig.MSPKey: {Value: protoutil.MarshalOrPanic(mc)}},
		Policies: map[string]*cb.ConfigPolicy{},
	}
	for _, n := range []string{"Readers", "Writers", "Admins", "Endorsement"} {
		g.Policies[n] = &cb.ConfigPolicy{Policy: signaturePolicy(1, mb.MSPRole_MEMBER, []string{id})}
	}
	return g
}

func implicit(rule string) *cb.ConfigPolicy {
	return &cb.ConfigPolicy{Policy: &cb.Policy{Type: int32(cb.Policy_IMPLICIT_META), Value: []byte(rule)}, ModPolicy: "Admins"}
}

// sampleConfig is what createBlock produces for four parties: implicit MAJORITY policies at Application level.
func sampleConfig() *cb.Config {
	app := &cb.ConfigGroup{Groups: map[string]*cb.ConfigGroup{}, Policies: map[string]*cb.ConfigPolicy{
		"LifecycleEndorsement": implicit("MAJORITY Endorsement"), "Endorsement": implicit("MAJORITY Endorsement"),
		"Readers": implicit("ANY Readers"), "Writers": implicit("ANY Writers"), "Admins": implicit("MAJORITY Admins")}}
	ord := &cb.ConfigGroup{Groups: map[string]*cb.ConfigGroup{}, Policies: map[string]*cb.ConfigPolicy{"Admins": implicit("MAJORITY Admins")}}
	for _, id := range banks {
		app.Groups[id] = orgGroup(id, 1, 1)
		ord.Groups[id] = orgGroup(id, 1, 1)
	}
	root := &cb.ConfigGroup{Groups: map[string]*cb.ConfigGroup{"Application": app, "Orderer": ord},
		Policies: map[string]*cb.ConfigPolicy{"Admins": implicit("MAJORITY Admins")}}
	for group, cap := range capabilities {
		g := root
		if group != "" {
			g = root.Groups[group]
		}
		g.Values = map[string]*cb.ConfigValue{channelconfig.CapabilitiesKey: {Value: protoutil.MarshalOrPanic(&cb.Capabilities{Capabilities: map[string]*cb.Capability{cap: {}}})}}
	}
	return &cb.Config{ChannelGroup: root}
}

func writeBlock(t *testing.T, cfg *cb.Config) string {
	t.Helper()
	payload := &cb.Payload{Data: protoutil.MarshalOrPanic(&cb.ConfigEnvelope{Config: cfg})}
	env := &cb.Envelope{Payload: protoutil.MarshalOrPanic(payload)}
	block := &cb.Block{Header: &cb.BlockHeader{Number: 0}, Data: &cb.BlockData{Data: [][]byte{protoutil.MarshalOrPanic(env)}}}
	block.Header.DataHash = protoutil.ComputeBlockDataHash(block.Data)
	p := filepath.Join(t.TempDir(), "genesis.block")
	if err := os.WriteFile(p, protoutil.MarshalOrPanic(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func finalized(t *testing.T) *cb.Config {
	t.Helper()
	cfg := sampleConfig()
	addIdemixOrg(cfg, "testdata/idemix")
	explicitPolicies(cfg, banks, 3)
	return cfg
}

func joined(v []string) string { return strings.Join(v, " | ") }

func TestExplicitPoliciesAreOutOf3OfTheFourBanks(t *testing.T) {
	cfg := finalized(t)
	app := cfg.ChannelGroup.Groups["Application"]
	for name, role := range map[string]mb.MSPRole_MSPRoleType{"LifecycleEndorsement": mb.MSPRole_MEMBER, "Endorsement": mb.MSPRole_MEMBER, "Admins": mb.MSPRole_ADMIN} {
		n, ids, roles, err := decodeOutOf(app.Policies[name].Policy)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n != 3 || len(ids) != 4 {
			t.Fatalf("%s: OutOf(%d) over %d principals, want OutOf(3) over 4", name, n, len(ids))
		}
		for i, id := range ids {
			if id != banks[i] || roles[i] != role {
				t.Fatalf("%s: principal %d is %s/%s, want %s/%s", name, i, id, roles[i], banks[i], role)
			}
		}
	}
	// Readers and Writers stay implicit ANY (Idemix included)
	if string(app.Policies["Readers"].Policy.Value) != "ANY Readers" || string(app.Policies["Writers"].Policy.Value) != "ANY Writers" {
		t.Fatal("Readers/Writers must stay ANY")
	}
}

func TestIdemixOrgIsAnApplicationOrgOfTypeIdemixWithReadersWritersOnly(t *testing.T) {
	cfg := finalized(t)
	g := cfg.ChannelGroup.Groups["Application"].Groups[idemixOrgName]
	if g == nil {
		t.Fatal("IdemixOrg missing from the Application group")
	}
	mc := &mb.MSPConfig{}
	if err := proto.Unmarshal(g.Values[channelconfig.MSPKey].Value, mc); err != nil {
		t.Fatal(err)
	}
	if mc.Type != 1 { // idemix
		t.Fatalf("MSP type %d, want 1 (idemix)", mc.Type)
	}
	ic := &mb.IdemixMSPConfig{}
	if err := proto.Unmarshal(mc.Config, ic); err != nil || ic.Name != idemixMSPID {
		t.Fatalf("idemix MSP name %q (%v), want %s", ic.Name, err, idemixMSPID)
	}
	if len(ic.Ipk) == 0 || len(ic.RevocationPk) == 0 {
		t.Fatal("issuer public key or revocation public key missing")
	}
	for name := range g.Policies {
		if name != "Readers" && name != "Writers" {
			t.Fatalf("IdemixOrg has a %q policy: it may only read/write", name)
		}
	}
	if g.ModPolicy != "/Channel/Application/Admins" {
		t.Fatalf("mod_policy %q: changes to the Idemix org must need the bank majority", g.ModPolicy)
	}
	if _, ok := cfg.ChannelGroup.Groups["Orderer"].Groups[idemixOrgName]; ok {
		t.Fatal("IdemixOrg must not be an orderer org")
	}
}

func TestInspectPassesTheFinalizedConfig(t *testing.T) {
	lines, bad := inspectConfig(finalized(t), banks, 3, true)
	if len(bad) != 0 {
		t.Fatalf("violations: %s", joined(bad))
	}
	if !strings.Contains(joined(lines), idemixMSPID) || !strings.Contains(joined(lines), "known_certs=1") {
		t.Fatalf("report lacks the Idemix org or the known_certs count: %s", joined(lines))
	}
}

func TestInspectCatchesEveryDeviation(t *testing.T) {
	cases := map[string]func(*cb.Config){
		"implicit MAJORITY left in Application/Admins": func(c *cb.Config) {
			c.ChannelGroup.Groups["Application"].Policies["Admins"] = implicit("MAJORITY Admins")
		},
		"IdemixOrgMSP principal in LifecycleEndorsement": func(c *cb.Config) {
			c.ChannelGroup.Groups["Application"].Policies["LifecycleEndorsement"].Policy = signaturePolicy(3, mb.MSPRole_MEMBER, []string{"org1", "org2", "org3", idemixMSPID})
		},
		"threshold 2 instead of 3 in Endorsement": func(c *cb.Config) {
			c.ChannelGroup.Groups["Application"].Policies["Endorsement"].Policy = signaturePolicy(2, mb.MSPRole_MEMBER, banks)
		},
		"member role in Admins": func(c *cb.Config) {
			c.ChannelGroup.Groups["Application"].Policies["Admins"].Policy = signaturePolicy(3, mb.MSPRole_MEMBER, banks)
		},
		"IdemixOrg has an Admins policy": func(c *cb.Config) {
			c.ChannelGroup.Groups["Application"].Groups[idemixOrgName].Policies["Admins"] = &cb.ConfigPolicy{Policy: signaturePolicy(1, mb.MSPRole_ADMIN, []string{idemixMSPID})}
		},
		"a bank without admin certs": func(c *cb.Config) {
			c.ChannelGroup.Groups["Application"].Groups["org3"] = orgGroup("org3", 0, 1)
		},
		"a bank without known_certs": func(c *cb.Config) {
			c.ChannelGroup.Groups["Application"].Groups["org2"] = orgGroup("org2", 1, 0)
		},
		"IdemixOrg missing": func(c *cb.Config) {
			delete(c.ChannelGroup.Groups["Application"].Groups, idemixOrgName)
		},
		"wrong capability": func(c *cb.Config) {
			c.ChannelGroup.Values[channelconfig.CapabilitiesKey] = &cb.ConfigValue{Value: protoutil.MarshalOrPanic(&cb.Capabilities{Capabilities: map[string]*cb.Capability{"V2_0": {}}})}
		},
	}
	for name, mutate := range cases {
		cfg := finalized(t)
		mutate(cfg)
		if _, bad := inspectConfig(cfg, banks, 3, true); len(bad) == 0 {
			t.Errorf("%s: inspect did not complain", name)
		}
	}
	// the untouched sample (createBlock output) must NOT pass: implicit policies, no Idemix org
	if _, bad := inspectConfig(sampleConfig(), banks, 3, true); len(bad) == 0 {
		t.Error("the createBlock sample config passed inspect")
	}
}

func TestFinalizeWritesAReadableGenesisThatInspectAccepts(t *testing.T) {
	in := writeBlock(t, sampleConfig())
	out := filepath.Join(t.TempDir(), "final.block")
	finalizeBlock(in, "testdata/idemix", out, banks, 3)
	_, cfg := configEnvelope(out)
	if _, bad := inspectConfig(cfg, banks, 3, true); len(bad) != 0 {
		t.Fatalf("violations after finalize: %s", joined(bad))
	}
	raw, _ := os.ReadFile(out)
	block := &cb.Block{}
	if err := proto.Unmarshal(raw, block); err != nil {
		t.Fatal(err)
	}
	if string(block.Header.DataHash) != string(protoutil.ComputeBlockDataHash(block.Data)) {
		t.Fatal("data hash of the rewritten genesis block is stale")
	}
}

func TestParseBankIDs(t *testing.T) {
	ids, err := parseIDs("org1, org2,org3,org4")
	if err != nil || len(ids) != 4 || ids[1] != "org2" {
		t.Fatalf("got %v %v", ids, err)
	}
	for _, bad := range []string{"", "org1,org1,org2,org3", "org1,,org2", "org1 org2"} {
		if _, err := parseIDs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFinalizeWithoutIdemixIsTheS6FailBranch(t *testing.T) {
	in := writeBlock(t, sampleConfig())
	out := filepath.Join(t.TempDir(), "c.block")
	finalizeBlock(in, "", out, banks, 3)
	_, cfg := configEnvelope(out)
	if _, ok := cfg.ChannelGroup.Groups["Application"].Groups[idemixOrgName]; ok {
		t.Fatal("an Idemix org was added although no Idemix dir was given")
	}
	if _, bad := inspectConfig(cfg, banks, 3, false); len(bad) != 0 {
		t.Fatalf("violations: %s", joined(bad))
	}
	if _, bad := inspectConfig(cfg, banks, 3, true); len(bad) == 0 {
		t.Fatal("inspect with -idemix=true accepted a genesis without the Idemix org")
	}
}

func TestChannelCapabilityOverride(t *testing.T) {
	saved := capabilities[""]
	defer func() { capabilities[""] = saved }()
	capabilities[""] = "V2_0"
	in := writeBlock(t, sampleConfig())
	out := filepath.Join(t.TempDir(), "b.block")
	finalizeBlock(in, "testdata/idemix", out, banks, 3)
	_, cfg := configEnvelope(out)
	if _, bad := inspectConfig(cfg, banks, 3, true); len(bad) != 0 {
		t.Fatalf("violations with the override: %s", joined(bad))
	}
	capabilities[""] = "V3_0"
	if _, bad := inspectConfig(cfg, banks, 3, true); len(bad) == 0 {
		t.Fatal("a V2_0 channel passed the V3_0 expectation")
	}
}
