package account

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	netmail "net/mail"
	"strings"
	"time"

	api "stackd/internal/awsapi/account"
	"stackd/internal/awsctx"
	"stackd/internal/services/organizations"
	"stackd/mail"
)

// EmailSender delivers a service-authored verification message after commit.
// Implementations must honor cancellation. Delivery is at least once; a lost
// acknowledgement can repeat the same message and verification code.
type EmailSender interface {
	Send(context.Context, mail.Message) error
}

const primaryEmailOTPLifetime = 24 * time.Hour
const primaryEmailCompletionDelay = time.Second

func (s *Service) getPrimaryEmail(ctx context.Context, in api.GetPrimaryEmailInput) (any, error) {
	var output *api.GetPrimaryEmailOutput
	err := s.repository.View(ctx, func(reader Reader) error {
		ctx := reader.Context()
		target, err := s.authorize(ctx, "GetPrimaryEmail", value(in.AccountId), nil, s.clock.Now().UTC())
		if err != nil {
			return err
		}
		record, err := s.organizations.AccountIdentity(ctx, awsctx.FromContext(ctx).Partition, target)
		if err != nil {
			return err
		}
		output = &api.GetPrimaryEmailOutput{PrimaryEmail: ptr(api.PrimaryEmailAddress(record.Email))}
		return nil
	})
	return output, err
}

func (s *Service) getPrimaryEmailUpdateStatus(ctx context.Context, in api.GetPrimaryEmailUpdateStatusInput) (any, error) {
	var output *api.GetPrimaryEmailUpdateStatusOutput
	err := s.repository.View(ctx, func(reader Reader) error {
		ctx := reader.Context()
		target, err := s.authorize(ctx, "GetPrimaryEmailUpdateStatus", value(in.AccountId), nil, s.clock.Now().UTC())
		if err != nil {
			return err
		}
		record, found, err := reader.PrimaryEmailUpdate(Scope{awsctx.FromContext(ctx).Partition, target})
		if err != nil {
			return err
		}
		if !found {
			return failure("ValidationException", "No email update found for account", 400)
		}
		output = &api.GetPrimaryEmailUpdateStatusOutput{Status: ptr(api.PrimaryEmailUpdateStatus(record.Status)), UpdatedAt: &record.UpdatedAt}
		return nil
	})
	return output, err
}

func (s *Service) startPrimaryEmailUpdate(ctx context.Context, in api.StartPrimaryEmailUpdateInput) (any, error) {
	// TODO: Comeback capture the primary-email OTP lifecycle, replacement/retry limits, email validation/normalization, expiry/status errors and delivery timing against AWS before Account completion.
	output := &api.StartPrimaryEmailUpdateOutput{Status: ptr(api.PrimaryEmailUpdateStatus(PrimaryEmailPending))}
	err := s.repository.Update(ctx, func(writer Writer) error {
		ctx, now := writer.Context(), s.clock.Now().UTC()
		target, err := s.authorize(ctx, "StartPrimaryEmailUpdate", value(in.AccountId), nil, now)
		if err != nil {
			return err
		}
		email := strings.TrimSpace(value(in.PrimaryEmail))
		address, err := netmail.ParseAddress(email)
		if err != nil || address.Name != "" || address.Address != email {
			return failure("ValidationException", "The primary email must be a valid email address.", 400)
		}
		scope := Scope{awsctx.FromContext(ctx).Partition, target}
		previous, _, err := writer.PrimaryEmailUpdate(scope)
		if err != nil {
			return err
		}
		if previous.Status == PrimaryEmailAccepted {
			return failure("ConflictException", "A primary email update is being completed.", 409)
		}
		if err := s.organizations.CheckPrimaryEmail(ctx, scope.Partition, email); err != nil {
			return emailConflict(err)
		}
		if s.emailSender == nil {
			return failure("InternalServerException", "Primary email verification delivery is not configured.", 500)
		}
		code, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
		if err != nil {
			return err
		}
		if err := writer.PutPrimaryEmailUpdate(PrimaryEmailUpdate{Scope: scope, Generation: previous.Generation + 1, Email: email, OTP: fmt.Sprintf("%06d", code), Status: PrimaryEmailPending, UpdatedAt: now, ExpiresAt: now.Add(primaryEmailOTPLifetime), Due: now, NoticePending: true}); err != nil {
			return err
		}
		return s.recordAPICall(ctx, "StartPrimaryEmailUpdate", &in, output, nil)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return output, err
}

func (s *Service) acceptPrimaryEmailUpdate(ctx context.Context, in api.AcceptPrimaryEmailUpdateInput) (any, error) {
	output := &api.AcceptPrimaryEmailUpdateOutput{Status: ptr(api.PrimaryEmailUpdateStatus(PrimaryEmailAccepted))}
	err := s.repository.Update(ctx, func(writer Writer) error {
		ctx, now := writer.Context(), s.clock.Now().UTC()
		target, err := s.authorize(ctx, "AcceptPrimaryEmailUpdate", value(in.AccountId), nil, now)
		if err != nil {
			return err
		}
		scope := Scope{awsctx.FromContext(ctx).Partition, target}
		record, found, err := writer.PrimaryEmailUpdate(scope)
		if err != nil {
			return err
		}
		if !found || !strings.EqualFold(record.Email, strings.TrimSpace(value(in.PrimaryEmail))) {
			return failure("ResourceNotFoundException", "No matching primary email update was found.", 404)
		}
		if record.Status != PrimaryEmailPending {
			return failure("ConflictException", "The primary email update is no longer pending verification.", 409)
		}
		if !now.Before(record.ExpiresAt) {
			return failure("ValidationException", "The verification code has expired.", 400)
		}
		if subtle.ConstantTimeCompare([]byte(record.OTP), []byte(value(in.Otp))) != 1 {
			return failure("ValidationException", "The verification code is incorrect.", 400)
		}
		if err := s.organizations.CheckPrimaryEmail(ctx, scope.Partition, record.Email); err != nil {
			return emailConflict(err)
		}
		record.Status, record.UpdatedAt = PrimaryEmailAccepted, now
		record.OTP, record.NoticePending = "", false
		record.Due = now.Add(primaryEmailCompletionDelay)
		if err := writer.PutPrimaryEmailUpdate(record); err != nil {
			return err
		}
		return s.recordAPICall(ctx, "AcceptPrimaryEmailUpdate", &in, output, nil)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return output, err
}

func emailConflict(err error) error {
	if errors.Is(err, organizations.ErrPrimaryEmailInUse) {
		return failure("ConflictException", "The primary email address is already in use.", 409)
	}
	return err
}
