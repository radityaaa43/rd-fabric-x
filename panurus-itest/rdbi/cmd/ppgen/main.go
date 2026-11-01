// Command ppgen re-creates ZKAT-DLOG (nogh v1) public parameters with another precision, keeping the
// Idemix issuer key, the curve, the issuers and the (empty) auditor list of the given parameters.
// The default 16-bit precision caps a token at 65535; the Lensa Privasi demo needs amounts up to 1e15.
//
//	ppgen <in public-params.bin> <out public-params.bin> [bits, default 64]
package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/setup"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatal("usage: ppgen <in> <out> [bits]")
	}
	bits := uint64(64)
	if len(os.Args) > 3 {
		b, err := strconv.ParseUint(os.Args[3], 10, 64)
		if err != nil {
			log.Fatal(err)
		}
		bits = b
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	old, err := setup.NewPublicParamsFromBytes(raw, setup.DLogNoGHDriverName, setup.ProtocolV1)
	if err != nil {
		log.Fatal(err)
	}
	if len(old.IdemixIssuerPublicKeys) != 1 {
		log.Fatalf("expected one idemix issuer key, got %d", len(old.IdemixIssuerPublicKeys))
	}
	pp, err := setup.WithVersion(bits, old.IdemixIssuerPublicKeys[0].PublicKey, old.Curve, old.DriverVersion)
	if err != nil {
		log.Fatal(err)
	}
	pp.SetIssuers(old.Issuers())
	if err := pp.SetAuditors(old.Auditors()); err != nil {
		log.Fatal(err)
	}
	out, err := pp.Serialize()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(os.Args[2], out, 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("precision %d -> %d bits, max token value %d, issuers %d, auditors %d\n",
		old.Precision(), pp.Precision(), pp.MaxTokenValue(), len(pp.Issuers()), len(pp.Auditors()))
}
