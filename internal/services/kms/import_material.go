package kms

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"slices"

	"stackd/internal/awswire"
)

// importedMaterial validates actual key bytes, then canonicalizes private keys
// so equivalent BER/DER encodings retain the same reimport identity.
func importedMaterial(spec string, material []byte) ([]byte, *awswire.Error) {
	if spec == "SYMMETRIC_DEFAULT" {
		if len(material) != 32 {
			return nil, invalidImportCiphertext()
		}
		return slices.Clone(material), nil
	}
	if _, hash := hmacSpec(spec); hash != 0 {
		if len(material) < hash.Size() || len(material) > 128 {
			return nil, invalidImportCiphertext()
		}
		return slices.Clone(material), nil
	}
	if spec != "ECC_NIST_EDWARDS25519" {
		der, err := importPKCS8DER(material)
		if err != nil {
			return nil, invalidImportCiphertext()
		}
		defer clear(der)
		material = der
	}
	private, err := parseAsymmetricPrivate(spec, material)
	if err != nil {
		return nil, invalidImportCiphertext()
	}
	valid := false
	switch private := private.(type) {
	case *rsa.PrivateKey:
		valid = private.N.BitLen() == rsaBits(spec) && len(private.Primes) == 2 && private.Validate() == nil
	case *ecdsa.PrivateKey:
		valid = private.Curve == nistCurve(spec)
	case *secp256k1Signer:
		valid = spec == "ECC_SECG_P256K1"
	case ed25519.PrivateKey:
		valid = spec == "ECC_NIST_EDWARDS25519"
	}
	if !valid {
		return nil, invalidImportCiphertext()
	}
	encoded, err := marshalAsymmetricPrivate(private)
	if err != nil {
		return nil, failure("KMSInternalException", "Unable to encode imported key material.")
	}
	return encoded, nil
}

func importedMaterialID(keyID string, material []byte) string {
	hash := sha256.New()
	hash.Write([]byte(keyID))
	hash.Write(material)
	return hex.EncodeToString(hash.Sum(nil))
}

func importPKCS8DER(material []byte) ([]byte, error) {
	der, rest, err := importBER(material, 0)
	if err != nil || len(rest) != 0 {
		return nil, errImportBER
	}
	defer clear(der)
	var outer privateKeyDER
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) != 0 {
		return nil, errImportBER
	}
	// RSA and EC PKCS8 envelopes contain another ASN.1 private key. Scalar
	// octets inside that private key are data, not recursive ASN.1 values.
	inner, rest, err := importBER(outer.PrivateKey, 0)
	if err != nil || len(rest) != 0 {
		return nil, errImportBER
	}
	defer clear(inner)
	outer.PrivateKey = inner
	return asn1.Marshal(outer)
}
