package kms

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type secp256k1Signer struct{ key *secp256k1.PrivateKey }

func (s *secp256k1Signer) Public() crypto.PublicKey { return s.key.PubKey() }

func (s *secp256k1Signer) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	// AWS ECDSA uses randomized nonces. The specialized Decred Sign function
	// uses deterministic RFC 6979, so use its standard-library key conversion
	// for signing while retaining native secp256k1 storage and verification.
	return s.key.ToECDSA().Sign(random, digest, options)
}

// crypto/x509 does not encode secp256k1. These are its standard RFC 5480 SPKI
// and RFC 5915/RFC 5208 private-key envelopes, not another cryptographic format.
var ecPublicKeyOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
var secp256k1OID = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

type ecPrivateDER struct {
	Version    int
	PrivateKey []byte
	NamedCurve asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func secp256k1Algorithm() pkix.AlgorithmIdentifier {
	encoded, _ := asn1.Marshal(secp256k1OID)
	return pkix.AlgorithmIdentifier{Algorithm: ecPublicKeyOID, Parameters: asn1.RawValue{FullBytes: encoded}}
}

func marshalSecp256k1Public(public *secp256k1.PublicKey) ([]byte, error) {
	point := public.SerializeUncompressed()
	return asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{secp256k1Algorithm(), asn1.BitString{Bytes: point, BitLength: len(point) * 8}})
}

func marshalSecp256k1Private(private *secp256k1.PrivateKey) ([]byte, error) {
	scalar := private.Serialize()
	inner, err := asn1.Marshal(ecPrivateDER{Version: 1, PrivateKey: scalar})
	clear(scalar)
	if err != nil {
		return nil, err
	}
	defer clear(inner)
	return asn1.Marshal(privateKeyDER{Version: 0, Algorithm: secp256k1Algorithm(), PrivateKey: inner})
}

func parseSecp256k1Private(encoded []byte) (*secp256k1Signer, error) {
	var outer privateKeyDER
	rest, err := asn1.Unmarshal(encoded, &outer)
	if err != nil {
		return nil, err
	}
	var curve asn1.ObjectIdentifier
	curveRest, err := asn1.Unmarshal(outer.Algorithm.Parameters.FullBytes, &curve)
	if err != nil || len(rest) != 0 || len(curveRest) != 0 || outer.Version != 0 || !outer.Algorithm.Algorithm.Equal(ecPublicKeyOID) || !curve.Equal(secp256k1OID) {
		return nil, errors.New("invalid secp256k1 PKCS8 key")
	}
	var inner ecPrivateDER
	rest, err = asn1.Unmarshal(outer.PrivateKey, &inner)
	if err != nil {
		return nil, err
	}
	var d secp256k1.ModNScalar
	defer d.Zero()
	if len(rest) != 0 || inner.Version != 1 || len(inner.PrivateKey) != 32 || d.SetByteSlice(inner.PrivateKey) || d.IsZero() {
		return nil, errors.New("invalid secp256k1 private scalar")
	}
	return &secp256k1Signer{key: secp256k1.NewPrivateKey(&d)}, nil
}
