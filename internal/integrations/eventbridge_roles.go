package integrations

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/eventbridge"
)

// ValidateRuleRole checks current trust without issuing execution credentials.
// PutRule owns PassRole; target roles are resolved only when selected work runs.
func (a EventBridgeTargets) ValidateRuleRole(ctx context.Context, roleARN string, rule eventbridge.RuleKey) *awswire.Error {
	if a.Roles.IAM == nil || a.Roles.Authorizer == nil {
		return &awswire.Error{Code: "InternalFailure", Message: "EventBridge role authority is not configured.", StatusCode: 500}
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = rule.Bus.Partition, rule.Bus.Account, rule.Bus.Region
	metadata.SourceIP, metadata.UserAgent = "events.amazonaws.com", "events.amazonaws.com"
	ctx = awsctx.WithServicePrincipal(awsctx.WithMetadata(ctx, metadata), awsctx.ServicePrincipal{Name: "events.amazonaws.com", SourceARN: rule.ARN(), Type: "Service"})
	unavailable := &awswire.Error{Code: "ValidationException", Message: "Role " + roleARN + " cannot be assumed by EventBridge.", StatusCode: 400}
	err := a.Roles.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		role, err := a.Roles.IAM.RoleForAssumption(ctx, roleARN)
		if err != nil {
			return unavailable
		}
		if rejected := a.Roles.trust(ctx, role, identity.RoleSessionSpec{SessionName: rule.Name}, now, ""); rejected != nil {
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

func (a EventBridgeTargets) targetContext(ctx context.Context, request eventbridge.DeliveryRequest, target arn.ARN) (context.Context, *awswire.Error) {
	d, event := request.Delivery, request.Event
	metadata := awsctx.Metadata{Partition: event.Bus.Partition, AccountID: event.Bus.Account, Region: event.Bus.Region, RequestID: event.RequestID, ParentEventID: event.ID}
	source := awsctx.ServicePrincipal{Name: "events.amazonaws.com", SourceARN: d.RuleARN, Type: "Service"}
	if d.RoleARN == "" {
		metadata.Region = target.Region
		source.Type = "User"
		return awsctx.WithServicePrincipal(awsctx.WithMetadata(ctx, metadata), source), nil
	}
	ctx = awsctx.WithMetadata(ctx, metadata)
	// Native assumptions reuse an opaque name for the selected rule target.
	// Derivation preserves that identity without a credential cache or new state.
	sessionID := uuid.NewMD5(uuid.NameSpaceURL, []byte(d.RuleARN+"/"+d.TargetID))
	credential, rejected := a.Roles.assume(ctx, source, d.RoleARN, identity.RoleSessionSpec{SessionName: hex.EncodeToString(sessionID[:])}, "")
	if rejected != nil {
		if rejected.StatusCode >= 500 {
			return ctx, rejected
		}
		if target.Service == "events" && strings.HasPrefix(target.Resource, "event-bus/") {
			return ctx, &awswire.Error{Code: "NO_PERMISSIONS", Message: "Lack of permissions to invoke cross account target.", StatusCode: 400}
		}
		return ctx, &awswire.Error{Code: "FAILED_TO_ASSUME_ROLE", Message: rejected.Message, StatusCode: 400}
	}
	region := target.Region
	if target.Service == "firehose" {
		// Firehose resolves the retained target's stream name in the rule's
		// Region, even when the target ARN names another Region.
		rule, err := arn.Parse(d.RuleARN)
		if err != nil {
			return ctx, &awswire.Error{Code: "InternalFailure", Message: "Invalid retained EventBridge rule ARN.", StatusCode: 500}
		}
		region = rule.Region
	}
	return serviceRoleRequestContext(ctx, credential, region, "events.amazonaws.com")
}
