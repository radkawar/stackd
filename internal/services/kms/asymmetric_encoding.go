package kms

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/metacubex/mldsa/mldsa"
)

type privateKeyDER struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func parseAsymmetricPrivate(spec string, material []byte) (crypto.Signer, error) {
	if spec == "ECC_SECG_P256K1" {
		return parseSecp256k1Private(material)
	}
	if mldsaSpec(spec) {
		return parseMLDSAPrivate(spec, material)
	}
	decoded, err := x509.ParsePKCS8PrivateKey(material)
	if err != nil {
		return nil, err
	}
	private, ok := decoded.(crypto.Signer)
	if !ok {
		return nil, errors.New("material is not an asymmetric private key")
	}
	return private, nil
}

func marshalAsymmetricPrivate(private crypto.Signer) ([]byte, error) {
	switch private := private.(type) {
	case *secp256k1Signer:
		return marshalSecp256k1Private(private.key)
	case *mldsaSigner:
		return marshalMLDSAPrivate(private.key)
	default:
		return x509.MarshalPKCS8PrivateKey(private)
	}
}

func marshalAsymmetricPublic(public crypto.PublicKey) ([]byte, error) {
	switch public := public.(type) {
	case *secp256k1.PublicKey:
		return marshalSecp256k1Public(public)
	case *mldsa.PublicKey:
		return marshalMLDSAPublic(public)
	default:
		return x509.MarshalPKIXPublicKey(public)
	}
}
