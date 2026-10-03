package dynamodb

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/authorization"
)

func parseTableKey(ctx context.Context, selector string) (TableKey, error) {
	scope := scopeFor(ctx)
	if !strings.HasPrefix(selector, "arn:") {
		return TableKey{Scope: scope, Name: selector}, nil
	}
	parsed, err := arn.Parse(selector)
	if err != nil || parsed.Service != "dynamodb" || !strings.HasPrefix(parsed.Resource, "table/") {
		return TableKey{}, failure("ValidationException", "Invalid DynamoDB table ARN: "+selector)
	}
	name := strings.TrimPrefix(parsed.Resource, "table/")
	if parsed.Region != scope.Region {
		return TableKey{}, failure("ValidationException", "Invalid AWS region")
	}
	if name == "" || strings.Contains(name, "/") || parsed.AccountID == "" || parsed.Partition != scope.Partition {
		return TableKey{}, failure("ValidationException", "The table ARN must identify a table in the requested partition.")
	}
	return TableKey{Scope: Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}, Name: name}, nil
}

func (s *Service) authorize(ctx context.Context, action, resource string, conditions map[string][]string) error {
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "dynamodb:" + action, ResourceARN: resource, Context: conditions, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}

// authorizeTable composes current table tags, resource bindings and identity
// policies in the caller's existing transaction. Index calls use index ARNs but
// inherit the table's resource policy and tags.
func (s *Service) authorizeTable(ctx context.Context, r Reader, key TableKey, action, index string, conditions map[string][]string) error {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	tags, err := r.Tags(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	for _, tag := range tags.Tags {
		conditions["aws:ResourceTag/"+value(tag.Key)] = []string{value(tag.Value)}
	}
	resource := key.ARN()
	if index != "" {
		resource += "/index/" + index
	}
	bound, err := r.Policy(PolicyKey{Scope: key.Scope, ResourceARN: key.ARN()})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	now := s.clock.Now()
	request := authorization.Request{Action: "dynamodb:" + action, ResourceARN: resource, Context: conditions, EvaluationTime: &now, ContextTypes: map[string]string{"dynamodb:LeadingKeys": "stringList", "dynamodb:Attributes": "stringList"}}
	if bound.Policy.Document != "" {
		request.ResourcePolicies = []authorization.BoundPolicy{bound.Policy}
	}
	if rejected := s.authorizer.Authorize(ctx, request); rejected != nil {
		return rejected
	}
	return nil
}
