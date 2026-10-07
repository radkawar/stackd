package logs

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/logs/filterpattern"
)

// SubscriptionDestination admits the native gzip-compressed subscription body
// through ordinary destination authorization, outside every Logs transaction.
type SubscriptionDestination interface {
	Check(context.Context, SubscriptionDelivery) *awswire.Error
	Send(context.Context, SubscriptionDelivery) *awswire.Error
}

const maxSubscriptionFilters = 5

func parseSubscription(ctx context.Context, in *api.PutSubscriptionFilterRequest) (GroupKey, SubscriptionRecord, *awswire.Error) {
	if in == nil {
		return GroupKey{}, SubscriptionRecord{}, invalid("A request is required.")
	}
	g, w := groupKey(ctx, value(in.LogGroupName))
	if w != nil {
		return g, SubscriptionRecord{}, w
	}
	v := SubscriptionRecord{Key: SubscriptionKey{Name: value(in.FilterName)}, Pattern: value(in.FilterPattern), DestinationARN: value(in.DestinationArn), RoleARN: value(in.RoleArn), ApplyOnTransformedLogs: enabled(in.ApplyOnTransformedLogs), Distribution: value(in.Distribution), FieldSelection: value(in.FieldSelectionCriteria)}
	if w := resourceName(v.Key.Name, "subscription filter"); w != nil {
		return g, v, w
	}
	if in.FilterPattern == nil {
		return g, v, invalid("A filter pattern is required.")
	}
	if _, err := filterpattern.Compile(v.Pattern); err != nil {
		return g, v, invalid(err.Error())
	}
	// TODO: Comeback capture delivery with applyOnTransformedLogs and no transformer.
	// Native admits the flag; this implementation currently matches original events.
	parts := strings.Split(v.DestinationARN, ":")
	if len(parts) < 6 || parts[0] != "arn" {
		return g, v, invalid("The destination ARN is invalid.")
	}
	if parts[1] != g.Partition || parts[3] != g.Region {
		return g, v, invalid("The subscription destination must be in the same partition and Region as the log group.")
	}
	switch parts[2] {
	case "lambda":
		if parts[4] != g.AccountID {
			return g, v, invalid("The Lambda destination must be in the same account and Region as the log group.")
		}
		if len(parts) < 7 || parts[5] != "function" || parts[6] == "" || len(parts) > 8 || len(parts) == 8 && parts[7] == "" {
			return g, v, invalid("The Lambda destination ARN is invalid.")
		}
		if in.RoleArn != nil {
			return g, v, invalid("destinationArn for vendor lambda cannot be used with roleArn")
		}
	case "kinesis", "firehose":
		if w := validateStreamingTarget(g.Scope, v.DestinationARN, true); w != nil {
			return g, v, w
		}
		if w := validateSubscriptionRole(g.Scope, v.RoleARN); w != nil {
			return g, v, w
		}
		v.TargetARN, v.RoleSourceARN = v.DestinationARN, g.ARN()+":*"
	case "logs":
		if _, w := destinationARN(v.DestinationARN); w != nil {
			return g, v, w
		}
		if in.RoleArn != nil {
			if w := validateSubscriptionRole(g.Scope, v.RoleARN); w != nil {
				return g, v, w
			}
			// TODO: Comeback implement cross-account organization sender-role
			// validation; native same-account logical subscriptions retain this
			// optional role without requiring sender logs:PutLogEvents permission.
			if parts[4] != g.AccountID {
				return g, v, unsupported("Cross-account organization sender-role validation is not implemented.")
			}
			v.SenderRoleARN = v.RoleARN
		}
	default:
		return g, v, invalid("The subscription destination ARN is invalid.")
	}
	if v.Distribution == "" {
		v.Distribution = "ByLogStream"
	}
	if v.Distribution != "ByLogStream" && v.Distribution != "Random" {
		return g, v, invalid("The distribution is invalid.")
	}
	if _, err := filterpattern.CompileSelection(v.FieldSelection); err != nil {
		return g, v, invalid(err.Error())
	}
	for _, field := range in.EmitSystemFields {
		f := string(field)
		if f != "@aws.account" && f != "@aws.region" && f != "@source.log" {
			return g, v, invalid("Only @aws.account, @aws.region and @source.log can be emitted as system fields.")
		}
		v.EmitSystemFields = append(v.EmitSystemFields, f)
	}
	slices.Sort(v.EmitSystemFields)
	v.EmitSystemFields = slices.Compact(v.EmitSystemFields)
	return g, v, nil
}

// checkSubscription rechecks only live IAM, group identity and filter capacity.
// The caller's static request is compiled once before independent preflight.
func (s *Service) checkSubscription(r Reader, key GroupKey, v SubscriptionRecord) (GroupRecord, SubscriptionRecord, *awswire.Error) {
	g, w := s.loadGroup(r, key.Name, "PutSubscriptionFilter", "")
	if w != nil {
		return g, v, w
	}
	if strings.Contains(v.DestinationARN, ":logs:") {
		k, w := destinationARN(v.DestinationARN)
		if w != nil {
			return g, v, w
		}
		if v.SenderRoleARN != "" {
			if w := s.passSubscriptionRole(r.Context(), v.SenderRoleARN, g.Key.ARN()+":*"); w != nil {
				return g, v, w
			}
		}
		d, err := r.Destination(k)
		if err != nil {
			return g, v, wireError(err)
		}
		if w := s.authorizeDestination(r, "PutSubscriptionFilter", d, nil, nil); w != nil {
			return g, v, w
		}
		v.TargetARN, v.RoleARN, v.RoleSourceARN = d.TargetARN, d.RoleARN, g.Key.ARN()+":*"
	} else if v.RoleARN != "" {
		if w := s.passSubscriptionRole(r.Context(), v.RoleARN, g.Key.ARN()+":*"); w != nil {
			return g, v, w
		}
	}
	v.Key.GroupID = g.ID
	rows, err := r.Subscriptions(SubscriptionQuery{GroupID: g.ID, Limit: maxSubscriptionFilters + 1})
	if err != nil {
		return g, v, wireError(err)
	}
	for _, old := range rows {
		if old.Key == v.Key {
			v.Created = old.Created
			v.CFNOwner, w = cloudFormationClaim(r.Context(), old.CFNOwner, true)
			if w != nil {
				return g, v, w
			}
			return g, v, nil
		}
	}
	if len(rows) >= maxSubscriptionFilters {
		return g, v, failure("LimitExceededException", "Resource limit exceeded.")
	}
	v.Created = s.clock.Now().UnixMilli()
	v.CFNOwner, w = cloudFormationClaim(r.Context(), "", false)
	if w != nil {
		return g, v, w
	}
	return g, v, nil
}
func (s *Service) putSubscriptionFilter(ctx context.Context, in *api.PutSubscriptionFilterRequest) (*api.PutSubscriptionFilterOutput, *awswire.Error) {
	key, prepared, wire := parseSubscription(ctx, in)
	if wire != nil {
		return nil, wire
	}
	var group GroupRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var w *awswire.Error
		group, prepared, w = s.checkSubscription(r, key, prepared)
		if w != nil {
			return w
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	if s.subscriptions == nil {
		return nil, unsupported("No subscription destination is configured.")
	}
	// Logical registration authorizes the destination's access policy. Its
	// physical stream was tested by PutDestination; native registration itself
	// does not emit another CONTROL_MESSAGE. Current role trust is enforced at
	// every actual delivery, not replaced with the subscriber's authority.
	if !strings.Contains(prepared.DestinationARN, ":logs:") {
		child := awsctx.FromContext(ctx)
		if id := apievents.EventID(ctx); id != "" {
			child.ParentEventID = id
		}
		control, err := s.subscriptionControl(group.Key, prepared)
		if err != nil {
			return nil, storageFailure()
		}
		if w := s.subscriptions.Check(awsctx.WithMetadata(ctx, child), control); w != nil {
			if w.StatusCode >= 500 || w.StatusCode == 429 {
				return nil, &awswire.Error{Code: "ServiceUnavailableException", Message: "The subscription destination is temporarily unavailable.", StatusCode: 500}
			}
			if strings.Contains(prepared.DestinationARN, ":lambda:") {
				return nil, invalid("Could not execute the lambda function. Make sure you have given CloudWatch Logs permission to execute your function.")
			}
			if strings.Contains(prepared.DestinationARN, ":firehose:") {
				return nil, invalid("Could not deliver test message to specified Firehose stream. Check if the given Firehose stream is in ACTIVE state and the role has permission to perform PutRecord.")
			}
			return nil, invalid("Could not deliver test message to specified Kinesis stream. Check if the given kinesis stream is in ACTIVE state and the role has permission to perform PutRecord.")
		}
	}
	out := &api.PutSubscriptionFilterOutput{}
	// TODO: Comeback model native subscription configuration propagation; desired
	// settings currently become effective at this commit, not after a staged delay.
	err = s.update(ctx, func(tx Transaction) (any, *awswire.Error) {
		g, v, w := s.checkSubscription(tx, key, prepared)
		if w != nil {
			return nil, w
		}
		if g.ID != group.ID {
			return nil, failure("OperationAbortedException", "The log group changed during destination validation.")
		}
		if v.TargetARN != prepared.TargetARN || v.RoleARN != prepared.RoleARN {
			return nil, failure("OperationAbortedException", "The destination changed during validation.")
		}
		if owner, constrained := tx.Context().Value(cloudFormationOwnerKey{}).(cloudFormationOwner); constrained && owner.Create {
			old, err := tx.Subscription(v.Key)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return nil, wireError(err)
			}
			if err == nil && subscriptionConfigurationEqual(old, v) {
				return out, nil
			}
		}
		v.ID = uuid.NewString()
		if err := tx.PutSubscription(v); err != nil {
			return nil, wireError(err)
		}
		return out, nil
	})
	return out, wireError(err)
}
func (s *Service) describeSubscriptionFilters(tx Transaction, in *api.DescribeSubscriptionFiltersRequest) (*api.DescribeSubscriptionFiltersResponse, *awswire.Error) {
	g, w := s.loadGroup(tx, value(in.LogGroupName), "DescribeSubscriptionFilters", "")
	if w != nil {
		return nil, w
	}
	limit, w := pageLimit(in.Limit, 50, 50)
	if w != nil {
		return nil, w
	}
	identity := queryIdentity("subscriptions", g.Key, g.ID, value(in.FilterNamePrefix))
	token, w := s.decodeToken(value(in.NextToken), identity)
	if w != nil {
		return nil, w
	}
	rows, err := tx.Subscriptions(SubscriptionQuery{GroupID: g.ID, Prefix: value(in.FilterNamePrefix), After: token.Name, Limit: limit + 1})
	if err != nil {
		return nil, wireError(err)
	}
	out := &api.DescribeSubscriptionFiltersResponse{SubscriptionFilters: api.SubscriptionFilters{}}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	for _, v := range rows {
		f := api.SubscriptionFilter{FilterName: new(api.FilterName(v.Key.Name)), LogGroupName: new(api.LogGroupName(g.Key.Name)), FilterPattern: new(api.FilterPattern(v.Pattern)), DestinationArn: new(api.DestinationArn(v.DestinationARN)), Distribution: new(api.Distribution(v.Distribution)), CreationTime: new(api.Timestamp(v.Created)), ApplyOnTransformedLogs: new(api.ApplyOnTransformedLogs(v.ApplyOnTransformedLogs))}
		if v.RoleARN != "" && !strings.Contains(v.DestinationARN, ":logs:") {
			f.RoleArn = new(api.RoleArn(v.RoleARN))
		}
		if v.SenderRoleARN != "" {
			f.RoleArn = new(api.RoleArn(v.SenderRoleARN))
		}
		if v.FieldSelection != "" {
			f.FieldSelectionCriteria = new(api.FieldSelectionCriteria(v.FieldSelection))
		}
		for _, field := range v.EmitSystemFields {
			f.EmitSystemFields = append(f.EmitSystemFields, api.SystemField(field))
		}
		out.SubscriptionFilters = append(out.SubscriptionFilters, f)
	}
	if more {
		token.Name = rows[len(rows)-1].Key.Name
		out.NextToken = encodeToken(token)
	}
	return out, nil
}
func (s *Service) deleteSubscriptionFilter(tx Transaction, in *api.DeleteSubscriptionFilterRequest) (*api.DeleteSubscriptionFilterOutput, *awswire.Error) {
	g, w := s.loadGroup(tx, value(in.LogGroupName), "DeleteSubscriptionFilter", "")
	if w != nil {
		return nil, w
	}
	key := SubscriptionKey{g.ID, value(in.FilterName)}
	if w := resourceName(key.Name, "subscription filter"); w != nil {
		return nil, w
	}
	old, err := tx.Subscription(key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, failure("ResourceNotFoundException", "The specified subscription filter does not exist.")
		}
		return nil, wireError(err)
	}
	if w := cloudFormationDelete(tx.Context(), old.CFNOwner); w != nil {
		return nil, w
	}
	return &api.DeleteSubscriptionFilterOutput{}, wireError(tx.DeleteSubscription(key))
}

func subscriptionConfigurationEqual(a, b SubscriptionRecord) bool {
	return a.Key == b.Key && a.Pattern == b.Pattern && a.DestinationARN == b.DestinationARN &&
		a.Distribution == b.Distribution && a.FieldSelection == b.FieldSelection && a.RoleARN == b.RoleARN &&
		a.TargetARN == b.TargetARN && a.RoleSourceARN == b.RoleSourceARN && a.SenderRoleARN == b.SenderRoleARN &&
		a.ApplyOnTransformedLogs == b.ApplyOnTransformedLogs && slices.Equal(a.EmitSystemFields, b.EmitSystemFields)
}
