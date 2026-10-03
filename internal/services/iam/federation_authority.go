package iam

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

// FederationProviderReference identifies the exact configuration used to verify
// a federation token before entering IAM's atomic session-issuance transaction.
type FederationProviderReference struct {
	ARN, ID, Version string
}

// ErrFederationProviderChanged means that previously verified trust material no
// longer belongs to the same provider incarnation or current configuration.
var ErrFederationProviderChanged = errors.New("federation provider configuration changed")

// ErrFederationRoleNotFound distinguishes a missing destination role from a
// missing provider while retaining the repository's not-found classification.
var ErrFederationRoleNotFound = fmt.Errorf("federation role does not exist: %w", ErrRecordNotFound)

// OIDCProviderVersion identifies the authentication-relevant provider snapshot.
// Administrative tags and creation times cannot change token verification.
func OIDCProviderVersion(provider OIDCProviderRecord) string {
	h := newFederationVersion("oidc-v1")
	h.text(provider.ARN)
	h.text(provider.ID)
	h.text(provider.URL)
	h.texts(provider.ClientIDs)
	h.texts(provider.Thumbprints)
	return h.sum()
}

// SAMLProviderVersion includes issuer-specific certificate material and private
// key bytes explicitly: SAMLPrivateKeyRecord's JSON representation omits DER.
// Key creation times matter because consumers try rotated keys newest first.
func SAMLProviderVersion(provider SAMLProviderRecord) string {
	h := newFederationVersion("saml-v1")
	h.text(provider.ARN)
	h.text(provider.UUID)
	h.text(provider.AssertionEncryptionMode)
	h.count(len(provider.Issuers))
	for _, issuer := range provider.Issuers {
		h.text(issuer.EntityID)
		h.count(len(issuer.SigningCertificates))
		for _, certificate := range issuer.SigningCertificates {
			h.bytes(certificate)
		}
	}
	h.count(len(provider.PrivateKeys))
	for _, key := range provider.PrivateKeys {
		h.text(key.ID)
		h.text(key.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z"))
		h.bytes(key.PKCS8DER)
	}
	return h.sum()
}

type federationVersion struct{ hash.Hash }

func newFederationVersion(kind string) federationVersion {
	h := federationVersion{sha256.New()}
	h.text(kind)
	return h
}
func (h federationVersion) count(n int) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(n))
	_, _ = h.Write(length[:])
}
func (h federationVersion) bytes(value []byte) { h.count(len(value)); _, _ = h.Write(value) }
func (h federationVersion) text(value string)  { h.bytes([]byte(value)) }
func (h federationVersion) texts(values []string) {
	h.count(len(values))
	for _, value := range values {
		h.text(value)
	}
}
func (h federationVersion) sum() string { return hex.EncodeToString(h.Sum(nil)) }

// WithFederationSession revalidates a verified provider and reads the current
// role while holding the same write transaction that publishes credentials.
// STS owns token verification, current trust evaluation and issuance policy.
// The callback's context and repository may only be used during the callback;
// they must not be retained, used concurrently, or used for outbound discovery.
func (s *Service) WithFederationSession(ctx context.Context, provider FederationProviderReference, roleARN string, fn func(context.Context, RoleSnapshot, identity.Repository) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if fn == nil {
		return errors.New("federation session callback is required")
	}
	metadata := awsctx.FromContext(ctx)
	roleParts := strings.SplitN(roleARN, ":", 6)
	if len(roleParts) != 6 || roleParts[0] != "arn" || roleParts[1] == "" || roleParts[1] != metadata.Partition || roleParts[2] != "iam" || roleParts[3] != "" || !strings.HasPrefix(roleParts[5], "role/") || strings.HasSuffix(roleParts[5], "/") || !federationAccountID(roleParts[4]) {
		return ErrFederationRoleNotFound
	}
	scope := Scope{Partition: roleParts[1], AccountID: roleParts[4]}
	// Managed session policies are resolved in the destination role account.
	// Keep the actual caller identity intact; this is not a synthetic AWS root.
	metadata.AccountID = scope.AccountID
	ctx = awsctx.WithMetadata(ctx, metadata)
	return s.withAuthorityTransaction(ctx, func(callbackCtx context.Context, tx WriteTx, credentials identity.Repository, now time.Time) error {
		if err := currentFederationProvider(tx, scope, provider); err != nil {
			return err
		}
		name := roleParts[5][strings.LastIndexByte(roleParts[5], '/')+1:]
		role, err := tx.Role(scope, name)
		if err != nil {
			if errors.Is(err, ErrRecordNotFound) {
				return ErrFederationRoleNotFound
			}
			return err
		}
		if role.Arn != roleARN {
			return ErrFederationRoleNotFound
		}
		snapshot, err := s.RoleForAssumption(callbackCtx, roleARN)
		if err != nil {
			return err
		}
		snapshot.EvaluationTime = now
		return fn(callbackCtx, snapshot, credentials)
	})
}

func currentFederationProvider(tx ReadTx, scope Scope, reference FederationProviderReference) error {
	switch reference.ARN {
	case "accounts.google.com", "cognito-identity.amazonaws.com", "www.amazon.com", "graph.facebook.com":
		if reference.ID != reference.ARN || reference.Version != "builtin-v1" {
			return ErrFederationProviderChanged
		}
		return nil
	}
	parts := strings.SplitN(reference.ARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "iam" || parts[3] != "" || parts[4] != scope.AccountID {
		return ErrRecordNotFound
	}
	var id, version string
	switch {
	case strings.HasPrefix(parts[5], "oidc-provider/"):
		provider, err := tx.OIDCProvider(scope, reference.ARN)
		if err != nil {
			return err
		}
		if provider.ARN != reference.ARN {
			return ErrRecordNotFound
		}
		id, version = provider.ID, OIDCProviderVersion(provider)
	case strings.HasPrefix(parts[5], "saml-provider/"):
		provider, err := tx.SAMLProvider(scope, reference.ARN)
		if err != nil {
			return err
		}
		if provider.ARN != reference.ARN {
			return ErrRecordNotFound
		}
		id, version = provider.UUID, SAMLProviderVersion(provider)
	default:
		return ErrRecordNotFound
	}
	if id == "" || reference.ID != id || reference.Version != version {
		return ErrFederationProviderChanged
	}
	return nil
}

func federationAccountID(account string) bool {
	if len(account) != 12 {
		return false
	}
	for _, digit := range account {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
