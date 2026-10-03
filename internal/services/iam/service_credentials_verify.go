package iam

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"strings"
	"time"

	"stackd/internal/identity"
)

// VerifyServiceCredential authenticates against current credential and user
// records in one snapshot. Reset, revocation, expiry and user deletion take
// effect on the next verification; renaming cannot transfer credential ownership.
func (s *Service) VerifyServiceCredential(ctx context.Context, scope Scope, service, identifier, secret string) (identity.Principal, error) {
	if scope.Partition == "" || scope.AccountID == "" || secret == "" || len(secret) > 8192 || len(identifier) > 200 {
		return identity.Principal{}, ErrInvalidServiceCredential
	}
	service = strings.ToLower(service)
	digest := sha256.Sum256([]byte(secret))
	var principal identity.Principal
	err := s.viewAt(ctx, func(tx ReadTx, now time.Time) error {
		records, err := tx.ServiceCredentials(scope)
		if err != nil {
			return err
		}
		userID := ""
		for _, record := range records {
			matches := subtle.ConstantTimeCompare(digest[:], record.SecretDigest[:]) == 1
			validIdentifier := identifier == record.ServiceUserName && record.ServiceUserName != ""
			if record.ServiceCredentialAlias != "" {
				validIdentifier = identifier == "" || identifier == record.ServiceCredentialAlias
			}
			if matches && validIdentifier && record.ServiceName == service && serviceCredentialStatus(record, now) == "Active" {
				userID = record.UserID
			}
		}
		if userID == "" {
			return ErrInvalidServiceCredential
		}
		users, err := tx.Users(scope)
		if err != nil {
			return err
		}
		for _, u := range users {
			if u.UserId == userID {
				principal = identity.Principal{AccountID: scope.AccountID, ARN: u.Arn, ID: u.UserId, UserName: u.UserName}
				return nil
			}
		}
		return ErrInvalidServiceCredential
	})
	if err != nil {
		return identity.Principal{}, err
	}
	return principal, nil
}
