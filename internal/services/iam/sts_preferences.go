package iam

import (
	"context"
	"time"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func setSecurityTokenServicePreferences(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.SetSecurityTokenServicePreferencesInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	// Required enum membership is enforced by the generated request boundary.
	a.settings.GlobalEndpointAllRegions.set(*in.GlobalEndpointTokenVersion == iamapi.GlobalEndpointTokenVersionV2Token, a.currentTime)
	return &iamapi.SetSecurityTokenServicePreferencesOutput{}, nil
}

// GlobalEndpointAllRegions reads the credential owner's preference. STS calls
// it inside the current signed or federated IAM issuance transaction; a role
// assumption reads the destination account, independently of the caller account.
func (s *Service) GlobalEndpointAllRegions(ctx context.Context, accountID string) (bool, error) {
	var enabled bool
	err := s.viewAt(ctx, func(tx ReadTx, now time.Time) error {
		settings, err := tx.AccountSettings(Scope{Partition: awsctx.FromContext(ctx).Partition, AccountID: accountID})
		if err != nil {
			return err
		}
		enabled, _ = settings.GlobalEndpointAllRegions.valueAt(now)
		return nil
	})
	return enabled, err
}
