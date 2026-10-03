package kms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"

	"github.com/metacubex/mldsa/mldsa"
)

func marshalMLDSAPublic(public *mldsa.PublicKey) ([]byte, error) {
	parameters := mldsaParameterSets[strings.ReplaceAll(public.Parameters(), "-", "_")]
	encoded := public.Bytes()
	return asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		pkix.AlgorithmIdentifier{Algorithm: parameters.oid}, asn1.BitString{Bytes: encoded, BitLength: len(encoded) * 8},
	})
}

func marshalMLDSAPrivate(private *mldsa.PrivateKey) ([]byte, error) {
	parameters := mldsaParameterSets[strings.ReplaceAll(private.PublicKey().Parameters(), "-", "_")]
	seed := private.Bytes()
	defer clear(seed)
	// RFC 9881's seed-only choice is [0] IMPLICIT OCTET STRING.
	encoded, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: seed})
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return asn1.Marshal(privateKeyDER{Algorithm: pkix.AlgorithmIdentifier{Algorithm: parameters.oid}, PrivateKey: encoded})
}

func parseMLDSAPrivate(spec string, encoded []byte) (*mldsaSigner, error) {
	parameters := mldsaParameterSets[spec]
	var outer privateKeyDER
	rest, err := asn1.Unmarshal(encoded, &outer)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || outer.Version != 0 || !outer.Algorithm.Algorithm.Equal(parameters.oid) || len(outer.Algorithm.Parameters.FullBytes) != 0 {
		return nil, errors.New("invalid ML-DSA PKCS8 key")
	}
	var seed asn1.RawValue
	rest, err = asn1.Unmarshal(outer.PrivateKey, &seed)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || seed.Class != asn1.ClassContextSpecific || seed.Tag != 0 || seed.IsCompound {
		return nil, errors.New("invalid ML-DSA private seed encoding")
	}
	private, err := parameters.parsePrivate(seed.Bytes)
	if err != nil {
		return nil, err
	}
	return &mldsaSigner{key: private}, nil
}
