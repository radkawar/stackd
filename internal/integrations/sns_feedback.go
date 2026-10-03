package integrations

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/google/uuid"

	"stackd/clock"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/sns"
)

// SNSFeedbackLogs exposes ordinary authorized ingestion without granting write
// access merely because a delivery stream already exists.
type SNSFeedbackLogs interface {
	EnsureLogGroup(context.Context, string) *awswire.Error
	EnsureLogStream(context.Context, string, string) *awswire.Error
	PutLogEvents(context.Context, *api.PutLogEventsRequest) (*api.PutLogEventsResponse, *awswire.Error)
}

// SNSFeedback runs after source delivery commits. Its execution role and failures
// belong only to feedback; they cannot change an accepted notification.
type SNSFeedback struct {
	Logs  SNSFeedbackLogs
	Roles ServiceRoles
	Clock clock.Clock

	streamOnce sync.Once
	stream     string
}

func (a *SNSFeedback) WriteFeedback(ctx context.Context, roleARN string, record sns.FeedbackRecord) *awswire.Error {
	metadata := awsctx.FromContext(ctx)
	credential, wire := a.Roles.assume(ctx, metadata.ServicePrincipal, roleARN, identity.RoleSessionSpec{SessionName: "AWS-SNS"}, "")
	if wire != nil {
		return wire
	}
	ctx, wire = serviceRoleRequestContext(ctx, credential, metadata.Region, "sns.amazonaws.com")
	if wire != nil {
		return wire
	}
	// Topic identity is source-owned, independent of the execution role account.
	parts := strings.SplitN(record.Notification.TopicARN, ":", 6)
	group := "sns/" + parts[3] + "/" + parts[4] + "/" + parts[5]
	if record.Status == "FAILURE" {
		group += "/Failure"
	}
	a.streamOnce.Do(func() { a.stream = uuid.NewString() })
	if wire := a.Logs.EnsureLogGroup(ctx, group); wire != nil {
		return wire
	}
	if wire := a.Logs.EnsureLogStream(snsFeedbackCommand(ctx), group, a.stream); wire != nil {
		return wire
	}
	// Feedback contains only source-owned strings and integers.
	body, _ := json.Marshal(record)
	out, wire := a.Logs.PutLogEvents(snsFeedbackCommand(ctx), &api.PutLogEventsRequest{
		LogGroupName: new(api.LogGroupName(group)), LogStreamName: new(api.LogStreamName(a.stream)),
		LogEvents: api.InputLogEvents{{Message: new(api.EventMessage(body)), Timestamp: new(api.Timestamp(a.Clock.Now().UnixMilli()))}},
	})
	if wire != nil {
		return wire
	}
	if out.RejectedLogEventsInfo != nil {
		return &awswire.Error{Code: "InvalidParameterException", Message: "CloudWatch Logs rejected SNS feedback timestamps.", StatusCode: 400}
	}
	return nil
}

func snsFeedbackCommand(ctx context.Context) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID = uuid.NewString()
	return awsctx.WithMetadata(ctx, metadata)
}
