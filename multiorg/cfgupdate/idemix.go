package main

// The complete genesis (lead + orchestrator decisions 2026-11-11, PLAN S10):
//
//	cfgupdate finalize     -block <createBlock output> -idemix-dir <dir> -out <genesis> [-bank-ids org1,org2,org3,org4] [-threshold 3]
//	cfgupdate inspect      -block <genesis> [-bank-ids ...] [-threshold 3] [-idemix=true]
//	cfgupdate check-admins -block <genesis> -admin org1=<msp dir> [-admin org2=<msp dir> ...] -expect pass|fail
//
// finalize adds the ONE shared Idemix org (IdemixOrgMSP, an Application org of MSP type idemix, upstream shape: Ansible
// hyperledger.fabricx roles/configtxgen/templates/configtx.yaml.j2) and replaces the three implicit MAJORITY policies of the Application
// group by explicit signature policies over the four bank MSPs, so that the Idemix org can never count towards an admin, endorsement or
// lifecycle decision (a bank would otherwise count twice: its own MSP and an Idemix creator):
//
//	Application/Admins               OutOf(3, bankN.admin  x4)
//	Application/Endorsement          OutOf(3, bankN.member x4)
//	Application/LifecycleEndorsement OutOf(3, bankN.member x4)
//
// The roles mirror the org-level policies of the sample (Admins = OR(admin), Endorsement = OR(member), sampleconfig/configtx.yaml:66-69).
// The MSP ids are the ones createBlock gives the orgs: org1..org4 (orderer config/generate/config_block_gen.go:56,102-103). Readers and Writers
// stay ANY, Idemix included. The Idemix MSP dir holds msp/IssuerPublicKey and msp/RevocationPublicKey (IBM/idemix idemixmsp.go:898-921).

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mb "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/common/policydsl"
	fxmsp "github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-committer/service/verifier/policy"
	orderpolicy "github.com/hyperledger/fabric-x-orderer/common/policy"
	"github.com/hyperledger/fabric-x-orderer/common/types"
	"github.com/hyperledger/fabric-x-orderer/config/verify"
	"google.golang.org/protobuf/proto"
)

const (
	idemixOrgName = "IdemixOrg"
	idemixMSPID   = "IdemixOrgMSP"
	modAppAdmins  = "/Channel/Application/Admins"
)

func signaturePolicy(n int32, role mb.MSPRole_MSPRoleType, ids []string) *cb.Policy {
	return &cb.Policy{
		Type:  int32(cb.Policy_SIGNATURE),
		Value: protoutil.MarshalOrPanic(policydsl.SignedByNOutOfGivenRole(n, role, ids)),
	}
}

// parseIDs splits a comma separated list of distinct, non-empty MSP ids.
func parseIDs(csv string) ([]string, error) {
	var ids []string
	seen := map[string]bool{}
	for _, id := range strings.Split(csv, ",") {
		id = strings.TrimSpace(id)
		if id == "" || strings.ContainsAny(id, " \t'\"()") {
			return nil, fmt.Errorf("bad MSP id %q in %q", id, csv)
		}
		if seen[id] {
			return nil, fmt.Errorf("duplicate MSP id %q", id)
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}

// explicitPolicies replaces the implicit MAJORITY policies of the Application group (ModPolicy kept).
func explicitPolicies(cfg *cb.Config, ids []string, n int32) {
	app := cfg.ChannelGroup.Groups["Application"]
	for name, role := range map[string]mb.MSPRole_MSPRoleType{
		"LifecycleEndorsement": mb.MSPRole_MEMBER, "Endorsement": mb.MSPRole_MEMBER, "Admins": mb.MSPRole_ADMIN,
	} {
		p, ok := app.Policies[name]
		if !ok {
			must(fmt.Errorf("Application has no %s policy", name), "explicit policies")
		}
		p.Policy = signaturePolicy(n, role, ids)
	}
}

// addIdemixOrg adds the shared Idemix org to the Application group: MSP value from the Idemix MSP dir, Readers/Writers only.
func addIdemixOrg(cfg *cb.Config, dir string) {
	app := cfg.ChannelGroup.Groups["Application"]
	if _, ok := app.Groups[idemixOrgName]; ok {
		must(fmt.Errorf("%s already in Application", idemixOrgName), "idemix org")
	}
	mc, err := fxmsp.GetVerifyingMspConfig(dir, idemixMSPID, "idemix")
	must(err, "idemix msp config from "+dir)
	member := signaturePolicy(1, mb.MSPRole_MEMBER, []string{idemixMSPID})
	app.Groups[idemixOrgName] = &cb.ConfigGroup{
		ModPolicy: modAppAdmins, // changes to the Idemix org need the bank majority
		Values:    map[string]*cb.ConfigValue{channelconfig.MSPKey: {Value: protoutil.MarshalOrPanic(mc), ModPolicy: modAppAdmins}},
		Policies: map[string]*cb.ConfigPolicy{
			"Readers": {Policy: member, ModPolicy: modAppAdmins},
			"Writers": {Policy: member, ModPolicy: modAppAdmins},
		},
	}
}

// rewriteGenesis writes a copy of the genesis block with the config edited and the data hash recomputed.
func rewriteGenesis(blockPath, out string, edit func(*cb.Config)) {
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
	edit(ce.Config)
	payload.Data = protoutil.MarshalOrPanic(ce)
	env.Payload = protoutil.MarshalOrPanic(payload)
	block.Data.Data[0] = protoutil.MarshalOrPanic(env)
	block.Header.DataHash = protoutil.ComputeBlockDataHash(block.Data)
	must(os.WriteFile(out, protoutil.MarshalOrPanic(block), 0o600), "write genesis")
}

// setChannelCapability sets the Channel-level capability (V3_0 as in the sample unless told otherwise).
func setChannelCapability(cfg *cb.Config, name string) {
	cfg.ChannelGroup.Values[channelconfig.CapabilitiesKey] = &cb.ConfigValue{
		ModPolicy: channelconfig.AdminsPolicyKey,
		Value:     protoutil.MarshalOrPanic(&cb.Capabilities{Capabilities: map[string]*cb.Capability{name: {}}}),
	}
}

func finalizeBlock(blockPath, idemixDir, out string, ids []string, n int32) {
	rewriteGenesis(blockPath, out, func(cfg *cb.Config) {
		if idemixDir != "" { // empty = the S6 FAIL branch: the explicit bank-majority policies without the Idemix org
			addIdemixOrg(cfg, idemixDir)
		}
		explicitPolicies(cfg, ids, n)
		setChannelCapability(cfg, capabilities[""])
	})
	fmt.Printf("complete genesis written to %s (not reproducible: build once, publish its sha256)\n", out)
}

// decodeOutOf reads a signature policy of the shape OutOf(n, SignedBy x k) and returns n and the (MSP id, role) of each principal in order.
func decodeOutOf(p *cb.Policy) (int32, []string, []mb.MSPRole_MSPRoleType, error) {
	if p == nil || p.Type != int32(cb.Policy_SIGNATURE) {
		return 0, nil, nil, errors.New("not a signature policy (implicit MAJORITY policies are not allowed here)")
	}
	env := &cb.SignaturePolicyEnvelope{}
	if err := proto.Unmarshal(p.Value, env); err != nil {
		return 0, nil, nil, err
	}
	nof := env.Rule.GetNOutOf()
	if nof == nil {
		return 0, nil, nil, errors.New("rule is not NOutOf")
	}
	var ids []string
	var roles []mb.MSPRole_MSPRoleType
	for _, r := range nof.Rules {
		sb, ok := r.Type.(*cb.SignaturePolicy_SignedBy)
		if !ok || int(sb.SignedBy) >= len(env.Identities) {
			return 0, nil, nil, errors.New("rule is not a plain SignedBy")
		}
		pr := env.Identities[sb.SignedBy]
		if pr.PrincipalClassification != mb.MSPPrincipal_ROLE {
			return 0, nil, nil, errors.New("principal is not a role")
		}
		role := &mb.MSPRole{}
		if err := proto.Unmarshal(pr.Principal, role); err != nil {
			return 0, nil, nil, err
		}
		ids, roles = append(ids, role.MspIdentifier), append(roles, role.Role)
	}
	return nof.N, ids, roles, nil
}

func capabilityNames(g *cb.ConfigGroup) []string {
	v, ok := g.Values[channelconfig.CapabilitiesKey]
	if !ok {
		return nil
	}
	c := &cb.Capabilities{}
	if err := proto.Unmarshal(v.Value, c); err != nil {
		return []string{"<undecodable>"}
	}
	var names []string
	for name := range c.Capabilities {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// inspectConfig reports what the config says and returns every deviation from the decided shape (empty = clean).
func inspectConfig(cfg *cb.Config, ids []string, n int32, wantIdemix bool) (lines, bad []string) {
	root := cfg.ChannelGroup
	app, ord := root.Groups["Application"], root.Groups["Orderer"]
	deviation := func(f string, a ...any) { bad = append(bad, fmt.Sprintf(f, a...)) }
	say := func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }

	for group, want := range capabilities {
		g := root
		if group != "" {
			g = root.Groups[group]
		}
		got := capabilityNames(g)
		say("capabilities %q: %v", group, got)
		if len(got) != 1 || got[0] != want {
			deviation("capabilities of %q are %v, want [%s]", group, got, want)
		}
	}

	wantOrgs := map[string]bool{}
	for _, id := range ids {
		wantOrgs[id] = true
	}
	if wantIdemix {
		wantOrgs[idemixOrgName] = true
	}
	for name := range app.Groups {
		if !wantOrgs[name] {
			deviation("unexpected Application org %q", name)
		}
	}
	for name := range wantOrgs {
		if _, ok := app.Groups[name]; !ok {
			deviation("Application org %q is missing", name)
		}
	}
	for _, id := range ids {
		g, ok := app.Groups[id]
		if !ok {
			continue
		}
		mc := &mb.MSPConfig{}
		fc := &msppb.FabricMSPConfig{}
		if v, ok := g.Values[channelconfig.MSPKey]; !ok || proto.Unmarshal(v.Value, mc) != nil || mc.Type != 0 || proto.Unmarshal(mc.Config, fc) != nil {
			deviation("Application/%s: MSP value is not a readable Fabric MSP", id)
			continue
		}
		say("Application/%s: fabric MSP name=%s admins=%d known_certs=%d", id, fc.Name, len(fc.Admins), len(fc.KnownCerts))
		if len(fc.Admins) == 0 {
			deviation("Application/%s: no admin certificate (no config transaction could be authorized)", id)
		}
		if len(fc.KnownCerts) == 0 {
			deviation("Application/%s: no known_certs (the FSC endorser cert is missing)", id)
		}
		if _, ok := ord.Groups[id]; !ok {
			deviation("Orderer org %q is missing", id)
		}
	}
	if _, ok := ord.Groups[idemixOrgName]; ok {
		deviation("%s must not be an Orderer org", idemixOrgName)
	}
	if g, ok := app.Groups[idemixOrgName]; ok {
		mc := &mb.MSPConfig{}
		ic := &mb.IdemixMSPConfig{}
		if v, ok := g.Values[channelconfig.MSPKey]; !ok || proto.Unmarshal(v.Value, mc) != nil || mc.Type != 1 || proto.Unmarshal(mc.Config, ic) != nil || ic.Name != idemixMSPID {
			deviation("Application/%s: MSP value is not an idemix MSP named %s", idemixOrgName, idemixMSPID)
		} else {
			say("Application/%s: idemix MSP name=%s issuer key %d B, revocation key %d B", idemixOrgName, ic.Name, len(ic.Ipk), len(ic.RevocationPk))
		}
		for name := range g.Policies {
			if name != "Readers" && name != "Writers" {
				deviation("Application/%s has a %q policy: it may only read and write", idemixOrgName, name)
			}
		}
	}

	for name, role := range map[string]mb.MSPRole_MSPRoleType{
		"Admins": mb.MSPRole_ADMIN, "Endorsement": mb.MSPRole_MEMBER, "LifecycleEndorsement": mb.MSPRole_MEMBER,
	} {
		p, ok := app.Policies[name]
		if !ok {
			deviation("Application has no %s policy", name)
			continue
		}
		got, gotIDs, roles, err := decodeOutOf(p.Policy)
		if err != nil {
			deviation("Application/%s: %v", name, err)
			continue
		}
		var rendered []string
		for i, id := range gotIDs {
			rendered = append(rendered, fmt.Sprintf("%s.%s", id, strings.ToLower(roles[i].String())))
		}
		say("Application/%s: OutOf(%d, %s)", name, got, strings.Join(rendered, ", "))
		sortedGot, sortedWant := append([]string(nil), gotIDs...), append([]string(nil), ids...)
		sort.Strings(sortedGot)
		sort.Strings(sortedWant)
		if got != n || strings.Join(sortedGot, ",") != strings.Join(sortedWant, ",") {
			deviation("Application/%s is OutOf(%d) over %v, want OutOf(%d) over exactly %v", name, got, gotIDs, n, ids)
		}
		for i, r := range roles {
			if r != role {
				deviation("Application/%s: principal %s has role %s, want %s", name, gotIDs[i], r, role)
			}
		}
	}

	// the Idemix MSP must appear in NO admin, endorsement or lifecycle policy, at Channel or Application level
	for path, g := range map[string]*cb.ConfigGroup{"/Channel": root, "/Channel/Application": app} {
		for _, name := range []string{"Admins", "Endorsement", "LifecycleEndorsement"} {
			if p, ok := g.Policies[name]; ok && bytes.Contains(p.Policy.GetValue(), []byte(idemixMSPID)) {
				deviation("%s/%s references %s", path, name, idemixMSPID)
			}
		}
	}
	return lines, bad
}

func inspect(blockPath string, ids []string, n int32, wantIdemix bool) {
	_, cfg := configEnvelope(blockPath)
	lines, bad := inspectConfig(cfg, ids, n, wantIdemix)
	for _, l := range lines {
		fmt.Println(l)
	}
	if len(bad) > 0 {
		for _, b := range bad {
			fmt.Fprintln(os.Stderr, "FAIL", b)
		}
		os.Exit(1)
	}
	if wantIdemix {
		fmt.Println("PASS inspect: Idemix org present, known_certs and admins present, explicit OutOf policies, Idemix in no admin/endorsement/lifecycle policy")
	} else {
		fmt.Println("PASS inspect (no Idemix org, -idemix=false): known_certs and admins present, explicit OutOf policies")
	}
}

// listFlag collects a repeatable -admin org=dir flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// startupChecks runs what the orderer and the committer run when they start from the block: Arma ValidateNewConfig for every party and
// the committer's parse of LifecycleEndorsement (same calls as checkGenesis).
func startupChecks(env *cb.Envelope, bundle *channelconfig.Bundle) {
	rules := &verify.DefaultOrdererRules{}
	for p := types.PartyID(1); p <= 4; p++ {
		must(rules.ValidateNewConfig(env, factory.GetDefault(), p), fmt.Sprintf("ValidateNewConfig party %d", p))
	}
	_, err := policy.ParseLifecycleEndorsementPolicy(bundle)
	must(err, "committer ParseLifecycleEndorsementPolicy")
	fmt.Println("PASS start-up checks: bundle, Arma ValidateNewConfig (parties 1..4), committer ParseLifecycleEndorsementPolicy; MSP version", bundle.ChannelConfig().Capabilities().MSPVersion())
}

// checkAdmins signs with the given org admins and evaluates the three Application policies against the block's real bundle:
// expect "pass" = all three are satisfied, "fail" = Admins and LifecycleEndorsement are NOT satisfied (e.g. one admin only).
func checkAdmins(blockPath string, admins []string, expect string) {
	env, _ := configEnvelope(blockPath)
	bundle, err := orderpolicy.BuildBundleFromBlock(env, factory.GetDefault())
	must(err, "bundle (orderer start-up checks)")
	startupChecks(env, bundle)
	msg := []byte("admin majority check")
	var signed []*protoutil.SignedData
	for _, a := range admins {
		id, dir, ok := strings.Cut(a, "=")
		if !ok {
			must(fmt.Errorf("-admin %q is not org=dir", a), "admin flag")
		}
		s := loadSigner(dir, id)
		ident := &msppb.Identity{}
		must(proto.Unmarshal(s.creator, ident), "admin identity")
		sig, err := s.Sign(msg)
		must(err, "sign")
		signed = append(signed, &protoutil.SignedData{Data: msg, Identity: ident, Signature: sig})
	}
	satisfied := true
	for _, path := range []string{"/Channel/Application/Admins", "/Channel/Application/LifecycleEndorsement"} {
		pol, ok := bundle.PolicyManager().GetPolicy(path)
		if !ok {
			must(fmt.Errorf("policy %s not found", path), "policy")
		}
		err := pol.EvaluateSignedData(signed)
		fmt.Printf("%s with %d admin(s): satisfied=%v\n", path, len(signed), err == nil)
		satisfied = satisfied && err == nil
	}
	switch {
	case expect == "pass" && satisfied:
		fmt.Printf("PASS %d admin(s) satisfy Application/Admins and LifecycleEndorsement\n", len(signed))
	case expect == "fail" && !satisfied:
		fmt.Printf("PASS %d admin(s) do NOT satisfy the majority policies (as expected)\n", len(signed))
	default:
		fmt.Fprintf(os.Stderr, "FAIL expected %s, satisfied=%v\n", expect, satisfied)
		os.Exit(1)
	}
}
