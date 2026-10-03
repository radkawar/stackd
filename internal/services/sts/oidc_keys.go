package sts

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"slices"

	"stackd/internal/awswire"
	"stackd/internal/jwt"
)

// OIDCSigningKey contains public JWK material obtained from configured issuer
// metadata. Token-provided keys and URLs never enter this contract.
type OIDCSigningKey struct {
	ID, Type, Use, Algorithm string
	N, E, Curve, X, Y        string
	Certificates             [][]byte
	Operations               []string
}
type oidcAlgorithm struct {
	hash            crypto.Hash
	keyType, curve  string
	coordinateBytes int
}

var oidcAlgorithms = map[string]oidcAlgorithm{
	"RS256": {hash: crypto.SHA256, keyType: "RSA"}, "RS384": {hash: crypto.SHA384, keyType: "RSA"}, "RS512": {hash: crypto.SHA512, keyType: "RSA"},
	"ES256": {hash: crypto.SHA256, keyType: "EC", curve: "P-256", coordinateBytes: 32}, "ES384": {hash: crypto.SHA384, keyType: "EC", curve: "P-384", coordinateBytes: 48}, "ES512": {hash: crypto.SHA512, keyType: "EC", curve: "P-521", coordinateBytes: 66},
}

func verifyOIDCSignature(token jwt.Token, keys []OIDCSigningKey, algorithms []string) *awswire.Error {
	algorithm := oidcAlgorithms[token.Algorithm]
	if len(algorithms) > 0 && !slices.Contains(algorithms, token.Algorithm) {
		return invalidOIDCToken("The issuer does not advertise the token's signing algorithm.")
	}
	count := 0
	// AWS indexes public signing keys by kid; later duplicate IDs replace
	// earlier ones. A missing JWT kid is usable only with one indexed key.
	candidates := map[string]OIDCSigningKey{}
	for _, key := range keys {
		if key.Type == algorithm.keyType {
			count++
		}
		if key.Type != algorithm.keyType || key.ID == "" || (key.Use != "" && key.Use != "sig") {
			continue
		}
		candidates[key.ID] = key
	}
	if count > 100 {
		return invalidOIDCToken("The issuer has more than 100 keys of the token's signing key type.")
	}
	var selected OIDCSigningKey
	if token.KeyID != "" {
		selected = candidates[token.KeyID]
	} else if len(candidates) == 1 {
		for _, key := range candidates {
			selected = key
		}
	}
	if selected.ID == "" {
		return invalidOIDCToken("No unambiguous verification key was found for the token.")
	}
	// Captured AWS behavior rejects key_ops, including ["verify"]. JWK alg
	// metadata does not select the hash; the signed JWT alg does, and is always
	// restricted to the six supported algorithms with matching RSA/EC keys.
	if len(selected.Operations) != 0 {
		return invalidOIDCToken("The issuer's key_ops metadata is not supported.")
	}
	public, err := oidcPublicKey(selected, algorithm)
	if err != nil {
		return invalidOIDCToken("The issuer's verification key is invalid.")
	}
	switch key := public.(type) {
	case *rsa.PublicKey:
		if jwt.VerifyRSA(token, key) != nil {
			return invalidOIDCToken("The web identity token signature is invalid.")
		}
	case *ecdsa.PublicKey:
		digest := algorithm.hash.New()
		_, _ = digest.Write([]byte(token.SigningInput))
		hashed := digest.Sum(nil)
		size := algorithm.coordinateBytes
		if len(token.Signature) != 2*size || !ecdsa.Verify(key, hashed, new(big.Int).SetBytes(token.Signature[:size]), new(big.Int).SetBytes(token.Signature[size:])) {
			return invalidOIDCToken("The web identity token signature is invalid.")
		}
	default:
		return invalidOIDCToken("The issuer's key type is unsupported.")
	}
	return nil
}
func oidcPublicKey(key OIDCSigningKey, algorithm oidcAlgorithm) (crypto.PublicKey, error) {
	var public crypto.PublicKey
	switch key.Type {
	case "RSA":
		if key.N != "" || key.E != "" {
			n, err := oidcUnsigned(key.N, 0)
			if err != nil {
				return nil, err
			}
			e, err := oidcUnsigned(key.E, 0)
			if err != nil || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 2147483647 || e.Bit(0) != 1 || n.BitLen() < 1024 || n.BitLen() > 16384 {
				return nil, fmt.Errorf("invalid RSA JWK")
			}
			public = &rsa.PublicKey{N: n, E: int(e.Int64())}
		}
	case "EC":
		if key.Curve != algorithm.curve {
			return nil, fmt.Errorf("EC curve does not match algorithm")
		}
		if key.X != "" || key.Y != "" {
			x, err := oidcUnsigned(key.X, algorithm.coordinateBytes)
			if err != nil {
				return nil, err
			}
			y, err := oidcUnsigned(key.Y, algorithm.coordinateBytes)
			if err != nil {
				return nil, err
			}
			var curve elliptic.Curve
			switch key.Curve {
			case "P-256":
				curve = elliptic.P256()
			case "P-384":
				curve = elliptic.P384()
			case "P-521":
				curve = elliptic.P521()
			default:
				return nil, fmt.Errorf("unsupported EC curve")
			}
			point := make([]byte, 1+2*algorithm.coordinateBytes)
			point[0] = 4
			x.FillBytes(point[1 : 1+algorithm.coordinateBytes])
			y.FillBytes(point[1+algorithm.coordinateBytes:])
			public, err = ecdsa.ParseUncompressedPublicKey(curve, point)
			if err != nil {
				return nil, fmt.Errorf("invalid EC point")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported JWK key type")
	}
	if len(key.Certificates) > 0 {
		certificate, err := x509.ParseCertificate(key.Certificates[0])
		if err != nil {
			return nil, err
		}
		certKey := certificate.PublicKey
		if public != nil {
			equal, ok := public.(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !equal.Equal(certKey) {
				return nil, fmt.Errorf("certificate and JWK public key disagree")
			}
		} else {
			return nil, fmt.Errorf("JWK must contain its public key parameters")
		}
	}
	if public == nil {
		return nil, fmt.Errorf("JWK contains no public key")
	}
	switch key := public.(type) {
	case *rsa.PublicKey:
		if algorithm.keyType != "RSA" || key.N.BitLen() < 1024 || key.N.BitLen() > 16384 {
			return nil, fmt.Errorf("invalid RSA verification key")
		}
	case *ecdsa.PublicKey:
		if algorithm.keyType != "EC" || key.Curve.Params().Name != algorithm.curve {
			return nil, fmt.Errorf("invalid EC verification key")
		}
	default:
		return nil, fmt.Errorf("unsupported certificate key")
	}
	return public, nil
}
func oidcUnsigned(value string, size int) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) == 0 || (size > 0 && len(raw) != size) || (size == 0 && raw[0] == 0) {
		return nil, fmt.Errorf("invalid base64url unsigned integer")
	}
	return new(big.Int).SetBytes(raw), nil
}
