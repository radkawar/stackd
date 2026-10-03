package jwt

import (
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"errors"
	"math/big"
)

// KeySet contains public issuer material, never private keys or session state.
type KeySet struct {
	Issuer string
	Keys   map[string]*rsa.PublicKey
}

// RSAKey decodes RSA JWK integers for providers using the standard n/e form.
func RSAKey(modulus, exponent string) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil || len(n) == 0 {
		return nil, errors.New("invalid RSA modulus")
	}
	e, err := base64.RawURLEncoding.DecodeString(exponent)
	if err != nil || len(e) == 0 || len(e) > 4 {
		return nil, errors.New("invalid RSA exponent")
	}
	v := new(big.Int).SetBytes(e).Int64()
	if v < 3 || v > 1<<31-1 || v%2 == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(v)}, nil
}

// VerifyRSA verifies only the signed bytes. Each service owns issuer, audience,
// lifetime, scope and key-selection admission semantics.
func VerifyRSA(token Token, key *rsa.PublicKey) error {
	var algorithm crypto.Hash
	switch token.Algorithm {
	case "RS256":
		algorithm = crypto.SHA256
	case "RS384":
		algorithm = crypto.SHA384
	case "RS512":
		algorithm = crypto.SHA512
	default:
		return ErrAlgorithm
	}
	hash := algorithm.New()
	_, _ = hash.Write([]byte(token.SigningInput))
	return rsa.VerifyPKCS1v15(key, algorithm, hash.Sum(nil), token.Signature)
}
