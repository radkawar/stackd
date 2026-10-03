package iam

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"

	"stackd/internal/awsctx"
)

// SignWebIdentityToken signs the claims authorized by STS in the current IAM
// session transaction. IAM supplies iss from its current enabled issuer. The
// input map is unchanged and the token is publishable only after commit.
func (s *Service) SignWebIdentityToken(ctx context.Context, algorithm string, claims map[string]any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	transaction, ok := ctx.Value(transactionKey{}).(serviceTransaction)
	if _, writable := transaction.tx.(WriteTx); !ok || transaction.service != s || !writable {
		return "", errors.New("outbound token signing requires the IAM session transaction")
	}
	m := awsctx.FromContext(ctx)
	settings, err := transaction.tx.AccountSettings(Scope{Partition: m.Partition, AccountID: m.AccountID})
	if err != nil {
		return "", err
	}
	record := settings.OutboundWebIdentity
	enabled := false
	if record != nil {
		enabled, _ = record.Enabled.valueAt(transaction.currentTime)
	}
	if !enabled {
		return "", outboundIdentityError("OutboundWebIdentityFederationDisabledException", "Outbound web identity federation is disabled for this account.", http.StatusForbidden)
	}
	var stored OutboundSigningKey
	switch algorithm {
	case "RS256":
		stored = record.RS256
	case "ES384":
		stored = record.ES384
	default:
		return "", errors.New("unsupported outbound token signing algorithm")
	}
	private, err := outboundPrivateKey(stored, algorithm)
	if err != nil {
		return "", outboundIdentityFailure()
	}
	payload := maps.Clone(claims)
	if payload == nil {
		payload = make(map[string]any)
	}
	payload["iss"] = record.IssuerURL
	header, err := json.Marshal(struct {
		Type      string `json:"typ"`
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}{"JWT", algorithm, stored.ID})
	if err != nil {
		return "", err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return "", err
	}
	body := bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'})
	// Owned AWS user and role probes accept 14,984 UTF-8 payload bytes and
	// reject the next byte for both algorithms, including escaped/Unicode text.
	// This measures decoded claims, not the much larger compact signed token.
	if len(body) > 14984 {
		return "", outboundIdentityError("JWTPayloadSizeExceededException", "JWT payload exceeds maximum allowed size", http.StatusBadRequest)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	var signature []byte
	switch key := private.(type) {
	case *rsa.PrivateKey:
		digest := sha256.Sum256([]byte(input))
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	case *ecdsa.PrivateKey:
		digest := sha512.Sum384([]byte(input))
		r, ss, signErr := ecdsa.Sign(rand.Reader, key, digest[:])
		err = signErr
		if err == nil {
			// JOSE encodes the two P-384 integers as fixed-width octet strings.
			signature = make([]byte, 96)
			r.FillBytes(signature[:48])
			ss.FillBytes(signature[48:])
		}
	}
	if err != nil {
		return "", outboundIdentityFailure()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func outboundPrivateKey(stored OutboundSigningKey, algorithm string) (crypto.PrivateKey, error) {
	if stored.ID == "" {
		return nil, errors.New("missing outbound signing key ID")
	}
	private, err := x509.ParsePKCS8PrivateKey(stored.PKCS8DER)
	if err != nil {
		return nil, err
	}
	switch key := private.(type) {
	case *rsa.PrivateKey:
		if algorithm == "RS256" {
			return key, key.Validate()
		}
	case *ecdsa.PrivateKey:
		if algorithm == "ES384" && key.Curve == elliptic.P384() {
			return key, nil
		}
	}
	return nil, errors.New("outbound signing key does not match its algorithm")
}
