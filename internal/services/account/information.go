package account

import (
	"context"
	"strings"
	"time"

	api "stackd/internal/awsapi/account"
	"stackd/internal/awsctx"
)

func (s *Service) getAccountInformation(ctx context.Context, in api.GetAccountInformationInput) (any, error) {
	var output *api.GetAccountInformationOutput
	err := s.repository.Update(ctx, func(writer Writer) error {
		ctx, instant := writer.Context(), s.clock.Now().UTC()
		target, err := s.authorize(ctx, "GetAccountInformation", value(in.AccountId), nil, instant)
		if err != nil {
			return err
		}
		if s.organizations == nil || s.creationTimes == nil {
			return failure("InternalServerException", "Account identity storage is not configured.", 500)
		}
		partition := awsctx.FromContext(ctx).Partition
		record, err := s.organizations.AccountIdentity(ctx, partition, target)
		if err != nil {
			return err
		}
		created, err := s.creationTimes.AccountCreationTime(ctx, partition, target)
		if err != nil {
			return err
		}
		// TODO: Comeback capture Account state and access during closure/suspension, name propagation and partition behavior; the Organizations closure lifecycle remains incomplete.
		output = &api.GetAccountInformationOutput{AccountId: ptr(api.AccountId(target)), AccountName: ptr(api.AccountName(record.Name)), AccountState: ptr(api.AccountState(record.State)), AccountCreatedDate: ptr(created.UTC().Truncate(time.Second))}
		return s.recordAPICall(ctx, "GetAccountInformation", &in, output, nil)
	})
	return output, err
}

func (s *Service) putAccountName(ctx context.Context, in api.PutAccountNameInput) (any, error) {
	err := s.repository.Update(ctx, func(writer Writer) error {
		ctx, instant := writer.Context(), s.clock.Now().UTC()
		target, err := s.authorize(ctx, "PutAccountName", value(in.AccountId), nil, instant)
		if err != nil {
			return err
		}
		name := strings.TrimSpace(value(in.AccountName))
		if name == "" {
			// AWS omits the error type; the Go SDK reports UnknownError while
			// the CLI uses the HTTP status as its fallback code.
			return failure("", "The input AccountName must not be null or only whitespace.", 400)
		}
		if s.organizations == nil {
			return failure("InternalServerException", "Account identity storage is not configured.", 500)
		}
		if err := s.organizations.PutAccountName(ctx, awsctx.FromContext(ctx).Partition, target, name); err != nil {
			return err
		}
		return s.recordAPICall(ctx, "PutAccountName", &in, &api.PutAccountNameOutput{}, nil)
	})
	return &api.PutAccountNameOutput{}, err
}
