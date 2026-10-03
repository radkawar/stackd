package awsenvelope

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
)

const signingContextKey = "aws-crypto-public-key"

// Signer owns the ephemeral P-384 key included in a signed envelope's context.
// Create it before requesting a KMS data key so PublicKey can be bound by KMS.
type Signer struct {
	key       *ecdsa.PrivateKey
	publicKey string
}

// NewSigner creates a fresh AWS Encryption SDK signing key.
func NewSigner() (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	var compressed [49]byte
	compressed[0] = 2 | (encoded[len(encoded)-1] & 1)
	copy(compressed[1:], encoded[1:49])
	return &Signer{key: key, publicKey: base64.StdEncoding.EncodeToString(compressed[:])}, nil
}

// PublicKey returns the base64-encoded SEC1 compressed P-384 public key.
func (s *Signer) PublicKey() string { return s.publicKey }

// Seal emits suite 0x0578 with the exact context and this signer's public key.
// Context must not contain the reserved signing key and is never modified.
func (s *Signer) Seal(key, wrapped []byte, keyARN string, context map[string]string, plaintext []byte) ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, errInvalid
	}
	return seal(key, wrapped, keyARN, context, plaintext, s)
}

func parsePublicKey(encoded string) (*ecdsa.PublicKey, error) {
	if len(encoded) != 68 {
		return nil, errInvalid
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != 49 || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, errInvalid
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P384(), raw)
	if x == nil {
		return nil, errInvalid
	}
	var uncompressed [97]byte
	uncompressed[0] = 4
	x.FillBytes(uncompressed[1:49])
	y.FillBytes(uncompressed[49:])
	return ecdsa.ParseUncompressedPublicKey(elliptic.P384(), uncompressed[:])
}

func (s *Signer) sign(message []byte) ([]byte, error) {
	digest := sha512.Sum384(message)
	// Match the AWS SDK's static-length DER encoding. Negating s normally
	// changes the length by one; retry the rare remaining cases.
	for {
		r, scalar, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
		if err != nil {
			return nil, err
		}
		pair := struct{ R, S *big.Int }{r, scalar}
		der, err := asn1.Marshal(pair)
		if err != nil {
			return nil, err
		}
		if len(der) == 103 {
			return der, nil
		}
		pair.S.Sub(s.key.Curve.Params().N, pair.S)
		der, err = asn1.Marshal(pair)
		if err != nil {
			return nil, err
		}
		if len(der) == 103 {
			return der, nil
		}
	}
}
