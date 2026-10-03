package apigateway

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/apigateway"
)

func accountSettings(r Reader, scope Scope) (AccountRecord, error) {
	row, err := r.Account(scope)
	if errors.Is(err, ErrNotFound) {
		return AccountRecord{Scope: scope}, nil
	}
	return row, err
}

func accountOutput(row AccountRecord) *api.Account {
	return &api.Account{
		CloudwatchRoleArn: optional(row.CloudWatchRoleARN),
		ThrottleSettings:  &api.ThrottleSettings{BurstLimit: new(api.Integer(5000)), RateLimit: new(api.Double(10000))},
		Features:          api.ListOfString{"UsagePlans"},
		ApiKeyVersion:     ptr("4"),
	}
}

func (s *Service) getAccount(tx Transaction, _ *api.GetAccountRequest) (*api.Account, error) {
	if err := s.authorize(tx, "GET", "/account", nil); err != nil {
		return nil, err
	}
	row, err := accountSettings(tx, scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	return accountOutput(row), nil
}

func (s *Service) updateAccount(tx Transaction, in *api.UpdateAccountRequest) (*api.Account, error) {
	if err := s.authorize(tx, "PATCH", "/account", nil); err != nil {
		return nil, err
	}
	row, err := accountSettings(tx, scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	changed := false
	for _, patch := range in.PatchOperations {
		if value(patch.Path) != "/cloudwatchRoleArn" {
			return nil, unsupported("account patch path " + value(patch.Path))
		}
		if err := replace(patch, &row.CloudWatchRoleARN); err != nil {
			return nil, err
		}
		changed = true
	}
	if changed && row.CloudWatchRoleARN != "" {
		if s.logs == nil {
			return nil, unsupported("CloudWatch logging role admission")
		}
		if err := s.logs.ConfigureLoggingRole(tx.Context(), row.CloudWatchRoleARN); err != nil {
			return nil, err
		}
	}
	if changed {
		if err := tx.PutAccount(row); err != nil {
			return nil, err
		}
	}
	return accountOutput(row), nil
}

// CloudWatchRole reads the regional setting for an internal service consumer.
// The supplied context determines scope, not authority to perform public calls.
func (s *Service) CloudWatchRole(ctx context.Context) (string, error) {
	var role string
	err := s.repository.View(ctx, func(r Reader) error {
		row, err := accountSettings(r, scopeFor(ctx))
		role = row.CloudWatchRoleARN
		return err
	})
	return role, err
}
