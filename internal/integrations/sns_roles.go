package integrations

import (
	"context"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/sns"
)

// SNSRoles checks current SNS trust without issuing credentials. SNS owns the
// caller's PassRole check; destination permissions remain delivery-time facts.
type SNSRoles struct{ Roles ServiceRoles }

// ValidateSubscriptionRole checks current SNS trust without issuing credentials.
// SNS owns PassRole and attribute validation; Firehose permission is checked only
// by the eventual producer command.
func (a SNSRoles) ValidateSubscriptionRole(ctx context.Context, topic sns.TopicKey, roleARN string) *awswire.Error {
	if a.Roles.IAM == nil || a.Roles.Authorizer == nil {
		return &awswire.Error{Code: "InternalFailure", Message: "SNS role authority is not configured.", StatusCode: 500}
	}
	metadata := awsctx.FromContext(ctx)
	caller := metadata.PrincipalARN
	metadata.AccountID = topic.AccountID
	ctx = awsctx.WithServicePrincipal(awsctx.WithMetadata(ctx, metadata), awsctx.ServicePrincipal{Name: "sns.amazonaws.com", SourceARN: topic.ARN(), Type: "AWSService"})
	unavailable := &awswire.Error{Code: "InvalidParameter", Message: "SubscriptionRoleArn: " + roleARN + " is not a valid role to be assumed by SNS", StatusCode: 400}
	err := a.Roles.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		role, err := a.Roles.IAM.RoleForAssumption(ctx, roleARN)
		if err != nil {
			return &awswire.Error{Code: "AuthorizationError", Message: "User: " + caller + " is not authorized to perform: iam:PassRole on resource: " + roleARN, StatusCode: 403}
		}
		if rejected := a.Roles.trust(ctx, role, identity.RoleSessionSpec{SessionName: "AWS-SNS"}, now, ""); rejected != nil {
			if rejected.StatusCode >= 500 {
				return rejected
			}
			return unavailable
		}
		return nil
	})
	if err != nil {
		return serviceRoleFailure(err)
	}
	return nil
}

func (a SNSRoles) ValidateFeedbackRole(ctx context.Context, topic sns.TopicKey, roleARN string) *awswire.Error {
	if rejected := a.ValidateSubscriptionRole(ctx, topic, roleARN); rejected != nil {
		if rejected.StatusCode >= 500 || rejected.Code == "AuthorizationError" {
			return rejected
		}
		return &awswire.Error{Code: "InvalidParameter", Message: roleARN + " is not a valid role to allow SNS to write to Cloudwatch Logs", StatusCode: 400}
	}
	return nil
}
