package logs

import (
	"context"
	"errors"
	"strings"

	"stackd/iam/policy"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func destinationARN(arn string) (DestinationKey, *awswire.Error) {
	parts := strings.SplitN(arn, ":", 7)
	if len(parts) != 7 || parts[0] != "arn" || parts[2] != "logs" || parts[5] != "destination" || len(parts[4]) != 12 {
		return DestinationKey{}, invalid("The logical destination ARN is invalid.")
	}
	k := DestinationKey{Scope: Scope{Partition: parts[1], Region: parts[3], AccountID: parts[4]}, Name: parts[6]}
	return k, resourceName(k.Name, "destination")
}
func validateStreamingTarget(scope Scope, arn string, sameRegion bool) *awswire.Error {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || parts[0] != "arn" {
		return invalid("The streaming destination ARN is invalid.")
	}
	prefix := ""
	switch parts[2] {
	case "kinesis":
		prefix = "stream/"
	case "firehose":
		prefix = "deliverystream/"
	default:
		return invalid("The streaming destination ARN is invalid.")
	}
	if !strings.HasPrefix(parts[5], prefix) || len(strings.TrimPrefix(parts[5], prefix)) == 0 {
		return invalid("The streaming destination ARN is invalid.")
	}
	if parts[1] != scope.Partition || parts[4] != scope.AccountID || parts[3] == "" || sameRegion && parts[3] != scope.Region {
		return invalid("The stream must belong to this account and satisfy the destination Region scope.")
	}
	return nil
}
func validateSubscriptionRole(scope Scope, arn string) *awswire.Error {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "iam" || parts[3] != "" || parts[4] != scope.AccountID || !strings.HasPrefix(parts[5], "role/") || len(strings.TrimPrefix(parts[5], "role/")) == 0 {
		return invalid("A valid roleArn in the same account is required for streaming delivery.")
	}
	return nil
}
func (s *Service) passSubscriptionRole(ctx context.Context, role, source string) *awswire.Error {
	return logsAuthorizationError(s.authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: role, Context: map[string][]string{"iam:PassedToService": {"logs.amazonaws.com"}, "iam:AssociatedResourceArn": {source}}}))
}
func logsAuthorizationError(w *awswire.Error) *awswire.Error {
	if w != nil && w.Code == "AccessDenied" {
		out := *w
		out.Code, out.StatusCode = "AccessDeniedException", 400
		return &out
	}
	return w
}
func (s *Service) authorizeDestination(r Reader, action string, d DestinationRecord, tags map[string]string, keys []string) *awswire.Error {
	arn := d.Key.ARN()
	if action == "DescribeDestinations" {
		arn = "*"
	}
	conditions := map[string][]string{}
	for k, v := range d.Tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	for k, v := range tags {
		conditions["aws:RequestTag/"+k] = []string{v}
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		conditions["aws:TagKeys"] = keys
	}
	var policies []authorization.BoundPolicy
	if action == "PutSubscriptionFilter" {
		if d.AccessPolicy == "" {
			return failure("AccessDeniedException", "The destination does not have an access policy.")
		}
		policies = []authorization.BoundPolicy{{Document: d.AccessPolicy}}
	}
	// A policy must exist, but same-account IAM permissions do not require a
	// matching resource allow. Cross-account grants and explicit denies retain
	// their ordinary IAM semantics.
	return logsAuthorizationError(s.authorizer.Authorize(r.Context(), authorization.Request{Action: "logs:" + action, ResourceARN: arn, ResourceAccountID: d.Key.AccountID, ResourcePolicies: policies, Context: conditions}))
}
func destinationOutput(d DestinationRecord) *api.Destination {
	out := &api.Destination{DestinationName: new(api.DestinationName(d.Key.Name)), Arn: new(api.Arn(d.Key.ARN())), TargetArn: new(api.TargetArn(d.TargetARN)), RoleArn: new(api.RoleArn(d.RoleARN)), CreationTime: new(api.Timestamp(d.Created))}
	if d.AccessPolicy != "" {
		out.AccessPolicy = new(api.AccessPolicy(d.AccessPolicy))
	}
	return out
}
func (s *Service) prepareDestination(r Reader, input DestinationRecord, tags map[string]string) (DestinationRecord, *awswire.Error) {
	old, err := r.Destination(input.Key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return input, wireError(err)
	}
	old.Key = input.Key
	if w := s.authorizeDestination(r, "PutDestination", old, tags, nil); w != nil {
		return input, w
	}
	if w := s.passSubscriptionRole(r.Context(), input.RoleARN, input.Key.ARN()); w != nil {
		return input, w
	}
	if err == nil {
		input.Created, input.AccessPolicy, input.Tags = old.Created, old.AccessPolicy, old.Tags
	} else {
		input.Created, input.Tags = s.clock.Now().UnixMilli(), map[string]string{}
	}
	if len(tags) > 0 {
		if w := s.authorizeDestination(r, "TagResource", old, tags, nil); w != nil {
			return input, w
		}
	}
	if input.Tags == nil {
		input.Tags = map[string]string{}
	}
	for k, v := range tags {
		input.Tags[k] = v
	}
	if len(input.Tags) > 50 {
		return input, invalid("A resource can have at most 50 tags.")
	}
	return input, nil
}
func (s *Service) putDestination(ctx context.Context, in *api.PutDestinationRequest) (*api.PutDestinationResponse, *awswire.Error) {
	d := DestinationRecord{Key: DestinationKey{Scope: scopeFor(ctx), Name: value(in.DestinationName)}, TargetARN: value(in.TargetArn), RoleARN: value(in.RoleArn)}
	if w := resourceName(d.Key.Name, "destination"); w != nil {
		return nil, w
	}
	if strings.Contains(d.TargetARN, ":firehose:") {
		// TODO: Comeback — capture logical Firehose destination admission and cross-account delivery.
		return nil, unsupported("Firehose logical destinations are not implemented.")
	}
	// Logical destinations remain regional to the source, but their physical
	// Kinesis target may be in another Region of the destination account.
	if w := validateStreamingTarget(d.Key.Scope, d.TargetARN, false); w != nil {
		return nil, w
	}
	if w := validateSubscriptionRole(d.Key.Scope, d.RoleARN); w != nil {
		return nil, w
	}
	tags, w := tagValues(in.Tags)
	if w != nil {
		return nil, w
	}
	err := s.repository.View(ctx, func(r Reader) error {
		var w *awswire.Error
		d, w = s.prepareDestination(r, d, tags)
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
	control, err := s.subscriptionControl(GroupKey{Scope: d.Key.Scope}, SubscriptionRecord{Key: SubscriptionKey{Name: d.Key.Name}, DestinationARN: d.Key.ARN(), TargetARN: d.TargetARN, RoleARN: d.RoleARN, RoleSourceARN: d.Key.ARN()})
	if err != nil {
		return nil, storageFailure()
	}
	child := awsctx.FromContext(ctx)
	if id := apievents.EventID(ctx); id != "" {
		child.ParentEventID = id
	}
	if w := s.subscriptions.Check(awsctx.WithMetadata(ctx, child), control); w != nil {
		if w.StatusCode >= 500 || w.StatusCode == 429 {
			return nil, &awswire.Error{Code: "ServiceUnavailableException", Message: "The destination is temporarily unavailable.", StatusCode: 500}
		}
		return nil, invalid("Could not deliver test message to specified Kinesis stream. Check if the given kinesis stream is in ACTIVE state and the role has permission to perform PutRecord.")
	}
	out := &api.PutDestinationResponse{}
	err = s.update(ctx, func(tx Transaction) (any, *awswire.Error) {
		current, w := s.prepareDestination(tx, d, tags)
		if w != nil {
			return nil, w
		}
		if err := tx.PutDestination(current); err != nil {
			return nil, wireError(err)
		}
		out.Destination = destinationOutput(current)
		return out, nil
	})
	return out, wireError(err)
}
func (s *Service) loadDestination(r Reader, name, action string) (DestinationRecord, *awswire.Error) {
	k := DestinationKey{Scope: scopeFor(r.Context()), Name: name}
	if w := resourceName(name, "destination"); w != nil {
		return DestinationRecord{}, w
	}
	d, err := r.Destination(k)
	d.Key = k
	if w := s.authorizeDestination(r, action, d, nil, nil); w != nil {
		return d, w
	}
	if errors.Is(err, ErrNotFound) {
		if action == "PutDestinationPolicy" {
			return d, invalid("Destination with name " + name + " does not exist")
		}
		return d, failure("ResourceNotFoundException", "The specified destination does not exist.")
	}
	return d, wireError(err)
}
func (s *Service) putDestinationPolicy(tx Transaction, in *api.PutDestinationPolicyRequest) (*api.PutDestinationPolicyOutput, *awswire.Error) {
	d, w := s.loadDestination(tx, value(in.DestinationName), "PutDestinationPolicy")
	if w != nil {
		return nil, w
	}
	document := value(in.AccessPolicy)
	const malformed = "Error occurred while parsing accessPolicy. Please check if the accessPolicy has been constructed correctly using IAM grammar."
	if len(document) > 5120 {
		return nil, invalid(malformed)
	}
	parsed, err := policy.ParseResource([]byte(document))
	if err != nil || len(parsed.FederatedPrincipals()) != 0 {
		return nil, invalid(malformed)
	}
	keys := parsed.ConditionKeys()
	for _, key := range keys {
		if key != "aws:PrincipalOrgID" && key != "aws:PrincipalOrgPaths" {
			return nil, invalid("Only 'aws:PrincipalOrgID' and 'aws:PrincipalOrgPaths' condition keys are allowed in Condition block of the policy.")
		}
	}
	organization := len(keys) != 0
	principals := parsed.AWSPrincipals()
	if len(principals) == 0 {
		return nil, invalid(malformed)
	}
	for _, principal := range principals {
		if strings.HasPrefix(principal, "arn:") {
			return nil, invalid("Principal section of policy contains ARN instead of account ID: " + principal)
		}
		if principal == "*" && !organization {
			return nil, invalid("Principal section of policy contains `*` instead of account ID: *")
		}
	}
	if organization && d.AccessPolicy != "" && (in.ForceUpdate == nil || !bool(*in.ForceUpdate)) {
		previous, err := policy.ParseResource([]byte(d.AccessPolicy))
		if err != nil {
			return nil, storageFailure()
		}
		if len(previous.ConditionKeys()) == 0 {
			return nil, invalid("Cannot update existing policy on Subscription Destination. The existing policy specifies AWS Principals by Account Id while the provided policy specifies AWS Principals by Org Id. This can cause subscription delivery failures for Subscriptions using this destination that are not configured with a Role. Use the Force flag to accept this risk.")
		}
	}
	d.AccessPolicy = document
	return &api.PutDestinationPolicyOutput{}, wireError(tx.PutDestination(d))
}
func (s *Service) deleteDestination(tx Transaction, in *api.DeleteDestinationRequest) (*api.DeleteDestinationOutput, *awswire.Error) {
	d, w := s.loadDestination(tx, value(in.DestinationName), "DeleteDestination")
	if w != nil {
		return nil, w
	}
	return &api.DeleteDestinationOutput{}, wireError(tx.DeleteDestination(d.Key))
}
func (s *Service) describeDestinations(tx Transaction, in *api.DescribeDestinationsRequest) (*api.DescribeDestinationsResponse, *awswire.Error) {
	scope := scopeFor(tx.Context())
	if w := s.authorizeDestination(tx, "DescribeDestinations", DestinationRecord{Key: DestinationKey{Scope: scope}}, nil, nil); w != nil {
		return nil, w
	}
	limit, w := pageLimit(in.Limit, 50, 50)
	if w != nil {
		return nil, w
	}
	identity := queryIdentity("destinations", scope, value(in.DestinationNamePrefix))
	token, w := s.decodeToken(value(in.NextToken), identity)
	if w != nil {
		return nil, w
	}
	rows, err := tx.Destinations(DestinationQuery{Scope: scope, Prefix: value(in.DestinationNamePrefix), After: token.Name, Limit: limit + 1})
	if err != nil {
		return nil, wireError(err)
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := &api.DescribeDestinationsResponse{Destinations: api.Destinations{}}
	for _, d := range rows {
		out.Destinations = append(out.Destinations, *destinationOutput(d))
	}
	if more {
		token.Name = rows[len(rows)-1].Key.Name
		out.NextToken = encodeToken(token)
	}
	return out, nil
}
