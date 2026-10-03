package logs

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// ConfigureServiceDelivery is the internal log-delivery admission boundary.
// CreateLogDelivery is an IAM permission, not a public command in the Logs SDK
// model. The source's logging configuration owns the subscription; Logs owns the
// destination, resource policy and validation ingestion. These local commands
// may join the source's shared transaction; actual source delivery runs after commit.
func (s *Service) ConfigureServiceDelivery(ctx context.Context, groupARN string) *awswire.Error {
	if wire := s.authorizer.Authorize(ctx, authorization.Request{Action: "logs:CreateLogDelivery", ResourceARN: "*"}); wire != nil {
		return wire
	}
	groupARN = strings.TrimSuffix(groupARN, ":*")
	key, wire := policyGroupKey(ctx, groupARN)
	if wire != nil {
		return wire
	}
	const stream = "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"
	var group GroupRecord
	var policy PolicyRecord
	var deliveryDenied *awswire.Error
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		group, err = r.Group(key)
		if err != nil {
			return err
		}
		// Both account policies and the current group's RESOURCE policy enter
		// ordinary Logs authorization. A preconfigured policy is never rewritten.
		delivery := serviceDeliveryReader{Reader: r, ctx: serviceDeliveryContext(r.Context(), key)}
		for _, action := range []string{"CreateLogStream", "PutLogEvents"} {
			if wire := s.authorize(delivery, action, group, stream, nil, nil); wire != nil {
				if wire.Code != "AccessDenied" && wire.Code != "AccessDeniedException" {
					return wire
				}
				deliveryDenied = wire
				break
			}
		}
		if deliveryDenied == nil {
			return nil
		}
		policy, err = r.ResourcePolicy(PolicyKey{Scope: key.Scope, PolicyScope: PolicyScopeResource, Name: groupARN})
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	})
	if err != nil {
		return wireError(err)
	}
	if deliveryDenied != nil {
		// Automatic setup is resource-scoped, preserves customer statements, and
		// uses the same authorized, revision-fenced command as PutResourcePolicy.
		// No account-wide policy or synthetic public CreateLogDelivery is created.
		document, err := serviceDeliveryPolicy(policy.Document, key)
		if err != nil {
			return wireError(err)
		}
		input := &api.PutResourcePolicyRequest{ResourceArn: new(api.Arn(groupARN)), PolicyDocument: new(api.PolicyDocument(document))}
		if policy.Revision != 0 {
			input.ExpectedRevisionId = new(api.ExpectedRevisionId(strconv.FormatInt(policy.Revision, 10)))
		}
		if _, wire := s.command(serviceDeliveryCommand(ctx), "PutResourcePolicy", input); wire != nil {
			return wire
		}
	}
	delivery := serviceDeliveryContext(ctx, key)
	if wire := s.EnsureLogStream(serviceDeliveryCommand(delivery), key.Name, stream); wire != nil {
		return wire
	}
	// Validation really writes through PutLogEvents. A successful policy edit
	// cannot bypass an explicit Deny, a recreated group, or ingestion failure.
	out, wire := s.PutLogEvents(serviceDeliveryCommand(delivery), &api.PutLogEventsRequest{
		LogGroupName: new(api.LogGroupName(key.Name)), LogStreamName: new(api.LogStreamName(stream)),
		LogEvents: api.InputLogEvents{{
			Timestamp: new(api.Timestamp(s.clock.Now().UnixMilli())),
			Message:   new(api.EventMessage("Permissions are set correctly to allow AWS CloudWatch Logs to write into your logs while creating a subscription.")),
		}},
	})
	if wire != nil {
		return wire
	}
	if out.RejectedLogEventsInfo != nil {
		return invalid("CloudWatch Logs rejected the delivery validation event.")
	}
	return nil
}

type serviceDeliveryReader struct {
	Reader
	ctx context.Context
}

func (r serviceDeliveryReader) Context() context.Context { return r.ctx }

func serviceDeliveryContext(ctx context.Context, key GroupKey) context.Context {
	origin := awsctx.FromContext(ctx)
	return awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		SourceIP: "delivery.logs.amazonaws.com", UserAgent: "delivery.logs.amazonaws.com",
		ServicePrincipal: awsctx.ServicePrincipal{Name: "delivery.logs.amazonaws.com", SourceARN: key.ARN(), Type: "AWSService"},
	})
}

func serviceDeliveryCommand(ctx context.Context) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID = uuid.NewString()
	return awsctx.WithMetadata(ctx, metadata)
}

func serviceDeliveryPolicy(existing string, key GroupKey) (string, error) {
	document := map[string]json.RawMessage{"Version": json.RawMessage(`"2012-10-17"`)}
	if existing != "" {
		if err := json.Unmarshal([]byte(existing), &document); err != nil {
			return "", err
		}
	}
	var statements []json.RawMessage
	if raw := document["Statement"]; len(raw) != 0 {
		if raw[0] == '[' {
			if err := json.Unmarshal(raw, &statements); err != nil {
				return "", err
			}
		} else {
			statements = append(statements, raw)
		}
	}
	statement, err := json.Marshal(map[string]any{
		"Sid": "AWSLogDeliveryWrite1", "Effect": "Allow", "Principal": map[string]string{"Service": "delivery.logs.amazonaws.com"},
		"Action": []string{"logs:CreateLogStream", "logs:PutLogEvents"}, "Resource": key.ARN() + ":log-stream:*",
		"Condition": map[string]any{
			"StringEquals": map[string]string{"aws:SourceAccount": key.AccountID},
			"ArnLike":      map[string]string{"aws:SourceArn": "arn:" + key.Partition + ":logs:" + key.Region + ":" + key.AccountID + ":*"},
		},
	})
	if err != nil {
		return "", err
	}
	// Repeated failed setup (for example an explicit Deny) must not grow policy.
	for _, old := range statements {
		var canonical any
		if err := json.Unmarshal(old, &canonical); err != nil {
			return "", err
		}
		encoded, err := json.Marshal(canonical)
		if err != nil {
			return "", err
		}
		if string(encoded) == string(statement) {
			return existing, nil
		}
	}
	document["Statement"], err = json.Marshal(append(statements, statement))
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(document)
	return string(encoded), err
}
