package iam

import (
	"context"
	"errors"

	"golang.org/x/crypto/ssh"
	"stackd/internal/identity"
)

// VerifySSHPublicKey validates a real SSH signature against the currently active
// credential and resolves its owner's current identity in the same snapshot.
func (s *Service) VerifySSHPublicKey(ctx context.Context, scope Scope, id string, message, signature []byte) (identity.Principal, error) {
	var principal identity.Principal
	err := s.view(ctx, func(tx ReadTx) error {
		r, err := tx.SSHPublicKey(scope, id)
		if err != nil {
			return err
		}
		if r.Status != "Active" {
			return ErrInvalidSSHPublicKey
		}
		key, err := ssh.ParsePublicKey(r.Wire)
		if err != nil {
			return ErrInvalidSSHPublicKey
		}
		var parsed ssh.Signature
		if ssh.Unmarshal(signature, &parsed) != nil || key.Verify(message, &parsed) != nil {
			return ErrInvalidSSHPublicKey
		}
		principal, err = certificatePrincipal(tx, scope, r.UserID)
		return err
	})
	if errors.Is(err, ErrRecordNotFound) {
		err = ErrInvalidSSHPublicKey
	}
	return principal, err
}
