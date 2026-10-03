package iam

import (
	"context"
	"errors"
	"time"

	"stackd/internal/authorization"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/organizations"
)

// RootAccessSource owns the organization-wide root features. Implementations
// authorize the IAM action against current organization state before returning
// or changing it; callers need no organizations:* permission. Related storage
// must join the supplied IAM transaction context; external effects are forbidden.
type RootAccessSource interface {
	RootAccessFeatures(context.Context) (string, organizations.RootAccessFeatures, error)
	SetRootAccessFeature(context.Context, organizations.RootAccessFeature, bool) (string, organizations.RootAccessFeatures, error)
}

type rootAccessCommand struct {
	feature organizations.RootAccessFeature
	enabled bool
}

var rootAccessActions = map[string]rootAccessCommand{
	"ListOrganizationsFeatures":                     {},
	"EnableOrganizationsRootCredentialsManagement":  {organizations.RootCredentialsManagement, true},
	"DisableOrganizationsRootCredentialsManagement": {organizations.RootCredentialsManagement, false},
	"EnableOrganizationsRootSessions":               {organizations.RootSessions, true},
	"DisableOrganizationsRootSessions":              {organizations.RootSessions, false},
}

func (s *Service) executeRootAccess(ctx context.Context, action string, command rootAccessCommand, prepareResponse func(any) error) (any, *awswire.Error) {
	result, err := s.rootAccessResponse(ctx, action, command, prepareResponse)
	if err == nil {
		return result, nil
	}
	var apiErr *awswire.Error
	if !errors.As(err, &apiErr) {
		apiErr = &awswire.Error{Code: "ServiceFailure", Message: "Unable to update organization root access.", StatusCode: 500}
	}
	if err := s.appendAPICall(ctx, s.clock.Now(), nil, apiErr); err != nil {
		apiErr = &awswire.Error{Code: "ServiceFailure", Message: "Unable to record IAM API outcome.", StatusCode: 500}
	}
	return nil, apiErr
}

func (s *Service) rootAccessResponse(ctx context.Context, action string, command rootAccessCommand, prepareResponse func(any) error) (any, error) {
	if s.rootAccess == nil {
		s.mu.Lock()
		authorizer := s.authorizer
		s.mu.Unlock()
		if err := authorizer.Authorize(ctx, authorization.Request{Action: "iam:" + action, ResourceARN: "*"}); err != nil {
			return nil, err
		}
		return nil, &awswire.Error{Code: "OrganizationNotFoundException", Message: "The account does not belong to an organization.", StatusCode: 400}
	}
	var result any
	err := s.withAuthorityTransaction(ctx, func(ctx context.Context, _ WriteTx, _ identity.Repository, now time.Time) error {
		var id string
		var features organizations.RootAccessFeatures
		var err error
		if command.feature == "" {
			id, features, err = s.rootAccess.RootAccessFeatures(ctx)
		} else {
			id, features, err = s.rootAccess.SetRootAccessFeature(ctx, command.feature, command.enabled)
		}
		if err != nil {
			return err
		}
		organizationID := wirePointer(iamapi.OrganizationIdType(id))
		enabled := make(iamapi.FeaturesListType, 0, 2)
		if features.CredentialsManagement {
			enabled = append(enabled, iamapi.FeatureType("RootCredentialsManagement"))
		}
		if features.Sessions {
			enabled = append(enabled, iamapi.FeatureType("RootSessions"))
		}
		switch action {
		case "ListOrganizationsFeatures":
			result = &iamapi.ListOrganizationsFeaturesOutput{OrganizationId: organizationID, EnabledFeatures: enabled}
		case "EnableOrganizationsRootCredentialsManagement":
			result = &iamapi.EnableOrganizationsRootCredentialsManagementOutput{OrganizationId: organizationID, EnabledFeatures: enabled}
		case "DisableOrganizationsRootCredentialsManagement":
			result = &iamapi.DisableOrganizationsRootCredentialsManagementOutput{OrganizationId: organizationID, EnabledFeatures: enabled}
		case "EnableOrganizationsRootSessions":
			result = &iamapi.EnableOrganizationsRootSessionsOutput{OrganizationId: organizationID, EnabledFeatures: enabled}
		default:
			result = &iamapi.DisableOrganizationsRootSessionsOutput{OrganizationId: organizationID, EnabledFeatures: enabled}
		}
		if prepareResponse != nil {
			if err := prepareResponse(result); err != nil {
				return err
			}
		}
		return s.appendAPICall(ctx, now, result, nil)
	})
	return result, err
}
