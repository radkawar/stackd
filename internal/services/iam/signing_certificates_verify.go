package iam

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"stackd/internal/identity"
)

func certificatePrincipal(tx ReadTx, scope Scope, userID string) (identity.Principal, error) {
	root := "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":root"
	if userID == root {
		return identity.Principal{AccountID: scope.AccountID, ARN: root, ID: scope.AccountID}, nil
	}
	users, err := tx.Users(scope)
	if err != nil {
		return identity.Principal{}, err
	}
	for _, u := range users {
		if u.UserId == userID {
			return identity.Principal{AccountID: scope.AccountID, ARN: u.Arn, ID: u.UserId, UserName: u.UserName}, nil
		}
	}
	return identity.Principal{}, ErrRecordNotFound
}

// VerifySigningCertificate checks current status, validity and the cryptographic
// signature in the same snapshot as the credential's current IAM identity.
func (s *Service) VerifySigningCertificate(ctx context.Context, scope Scope, id string, algorithm x509.SignatureAlgorithm, message, signature []byte) (identity.Principal, error) {
	var principal identity.Principal
	err := s.viewAt(ctx, func(tx ReadTx, now time.Time) error {
		r, err := tx.SigningCertificate(scope, id)
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(r.DER)
		if err != nil {
			return ErrInvalidSigningCertificate
		}
		if r.Status != "Active" || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.CheckSignature(algorithm, message, signature) != nil {
			return ErrInvalidSigningCertificate
		}
		principal, err = certificatePrincipal(tx, scope, r.UserID)
		return err
	})
	if errors.Is(err, ErrRecordNotFound) {
		err = ErrInvalidSigningCertificate
	}
	return principal, err
}
