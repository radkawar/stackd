package iam

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/identity"
)

// VerifyPassword validates against current IAM records and computes expiry from
// the current account policy. It performs no AWS authorization or credential
// issuance. The consumer must enforce PasswordChangeRequired and MFA before
// creating a session. Root users, roles, and federation identities have no IAM
// login profile and cannot authenticate through this boundary.
func (s *Service) VerifyPassword(ctx context.Context, scope Scope, username, password string) (PasswordAuthentication, error) {
	if scope.Partition == "" || scope.AccountID == "" || len(password) > 512 {
		return PasswordAuthentication{}, ErrInvalidPassword
	}
	var result PasswordAuthentication
	err := s.repository.Update(ctx, func(tx WriteTx) error {
		now := s.clock.Now().UTC()
		u, err := tx.User(scope, username)
		if errors.Is(err, ErrRecordNotFound) {
			return hideMissingPassword(password)
		}
		if err != nil {
			return err
		}
		p, err := tx.LoginProfile(scope, u.UserId)
		if errors.Is(err, ErrRecordNotFound) {
			return hideMissingPassword(password)
		}
		if err != nil {
			return err
		}
		match, err := matchesPassword(password, p.Password)
		if err != nil {
			return err
		}
		if !match {
			return ErrInvalidPassword
		}
		settings, err := tx.AccountSettings(scope)
		if err != nil {
			return err
		}
		result = passwordAuthentication(u, p, settings.PasswordPolicy, now)
		// IAM records only the first password use in a five-minute span.
		// Keep the timestamp monotonic if an injected clock moves backward.
		// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
		if !result.PasswordChangeRequired &&
			(u.PasswordLastUsed == nil || now.Sub(*u.PasswordLastUsed) >= 5*time.Minute) {
			u.PasswordLastUsed = &now
			return tx.PutUser(scope, u)
		}
		return nil
	})
	if err != nil {
		return PasswordAuthentication{}, err
	}
	return result, nil
}

func hideMissingPassword(password string) error {
	// Match the password hashing cost of an existing user's incorrect password
	// so the sign-in boundary does not expose profile existence through timing.
	_, err := matchesPassword(password, PasswordDigest{Algorithm: passwordAlgorithm, Iterations: passwordIterations, Salt: make([]byte, 16), Hash: make([]byte, 32)})
	if err != nil {
		return err
	}
	return ErrInvalidPassword
}

func passwordAuthentication(u User, p LoginProfileRecord, policy *AccountPasswordPolicy, now time.Time) PasswordAuthentication {
	parts := strings.SplitN(u.Arn, ":", 6)
	accountID := ""
	if len(parts) == 6 {
		accountID = parts[4]
	}
	result := PasswordAuthentication{Principal: identity.Principal{AccountID: accountID, ARN: u.Arn, ID: u.UserId, UserName: u.UserName}, PasswordChangeRequired: p.PasswordResetRequired}
	if policy != nil && policy.MaxPasswordAge > 0 {
		expires := p.PasswordChangedAt.Add(time.Duration(policy.MaxPasswordAge) * 24 * time.Hour)
		result.PasswordExpiresAt = &expires
		result.PasswordExpired = !now.Before(expires)
		result.PasswordChangeRequired = result.PasswordChangeRequired || result.PasswordExpired
		result.AdministratorResetRequired = policy.HardExpiry && result.PasswordExpired
	}
	return result
}
