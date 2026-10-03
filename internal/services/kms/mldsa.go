package kms

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/metacubex/mldsa/mldsa"

	"stackd/internal/awswire"
)

type mldsaParameterSet struct {
	oid          asn1.ObjectIdentifier
	generate     func() *mldsa.PrivateKey
	parsePrivate func([]byte) (*mldsa.PrivateKey, error)
}

// FIPS 204 parameters and RFC 9881 algorithm identifiers. The library owns the
// cryptographic implementation; this table binds AWS key specs to its API.
var mldsaParameterSets = map[string]mldsaParameterSet{
	"ML_DSA_44": {asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, mldsa.GenerateKey44, mldsa.NewPrivateKey44},
	"ML_DSA_65": {asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, mldsa.GenerateKey65, mldsa.NewPrivateKey65},
	"ML_DSA_87": {asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, mldsa.GenerateKey87, mldsa.NewPrivateKey87},
}

func mldsaSpec(spec string) bool { _, ok := mldsaParameterSets[spec]; return ok }

type mldsaSigner struct{ key *mldsa.PrivateKey }

func (s *mldsaSigner) Public() crypto.PublicKey { return s.key.PublicKey() }

func (s *mldsaSigner) Sign(_ io.Reader, message []byte, options crypto.SignerOpts) ([]byte, error) {
	if options.(mldsaSignerOptions).externalMu {
		return mldsa.SignExternalMu(s.key, message)
	}
	return mldsa.Sign(s.key, message, "")
}

// ML-DSA's external representative is not a conventional crypto.Hash digest.
type mldsaSignerOptions struct{ externalMu bool }

func (mldsaSignerOptions) HashFunc() crypto.Hash { return 0 }

func mldsaMessage(spec, messageType string, message []byte) ([]byte, crypto.SignerOpts, *awswire.Error) {
	// TODO: Comeback capture and enforce ML-DSA regional quotas, key/grant propagation and remaining authorization/error/partition conformance before KMS completion.
	switch messageType {
	case "RAW":
		return message, mldsaSignerOptions{}, nil
	case "EXTERNAL_MU":
		if len(message) != 64 {
			return nil, nil, failure("ValidationException", "External Mu is invalid length for algorithm ML_DSA_SHAKE_256.")
		}
		return message, mldsaSignerOptions{externalMu: true}, nil
	default:
		return nil, nil, failure("ValidationException", fmt.Sprintf("Message type %s is incompatible with key spec %s.", messageType, spec))
	}
}

func verifyMLDSA(public *mldsa.PublicKey, message, signature []byte, options crypto.SignerOpts) bool {
	if options.(mldsaSignerOptions).externalMu {
		return mldsa.VerifyExternalMu(public, message, signature) == nil
	}
	return mldsa.Verify(public, message, signature, "") == nil
}
