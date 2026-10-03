package kinesis

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/kinesis"
)

var streamNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)
var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)

func streamKey(ctx context.Context, name, resource string) (StreamKey, error) {
	scope := scopeFor(ctx)
	if resource == "" {
		if name == "" {
			return StreamKey{}, failure("InvalidArgumentException", "Stream arn and stream name can't be empty at the same time")
		}
		if !streamNamePattern.MatchString(name) {
			return StreamKey{}, failure("ValidationException", "Invalid stream name")
		}
		return StreamKey{Scope: scope, Name: name}, nil
	}
	parsed, err := arn.Parse(resource)
	if err != nil || parsed.Service != "kinesis" || !strings.HasPrefix(parsed.Resource, "stream/") || parsed.Partition != scope.Partition || !accountPattern.MatchString(parsed.AccountID) {
		return StreamKey{}, failure("InvalidArgumentException", "Invalid stream ARN: "+resource)
	}
	if parsed.Region != scope.Region {
		return StreamKey{}, failure("InvalidArgumentException", "The region specified in the ARN '"+resource+"' does not match the endpoint region")
	}
	inferred := strings.TrimPrefix(parsed.Resource, "stream/")
	if !streamNamePattern.MatchString(inferred) {
		return StreamKey{}, failure("InvalidArgumentException", "Invalid stream ARN: "+resource)
	}
	if name != "" && name != inferred {
		return StreamKey{}, failure("InvalidArgumentException", "Input stream name "+name+" doesn't match the inferred name in stream arn "+inferred)
	}
	return StreamKey{Scope: Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}, Name: inferred}, nil
}

func consumerKey(ctx context.Context, resource string) (ConsumerKey, error) {
	streamARN, suffix, found := strings.Cut(resource, "/consumer/")
	name, created, ok := strings.Cut(suffix, ":")
	timestamp, err := strconv.ParseInt(created, 10, 64)
	if !found || !ok || err != nil || timestamp < 0 || !streamNamePattern.MatchString(name) {
		return ConsumerKey{}, failure("InvalidArgumentException", "Invalid consumer ARN: "+resource)
	}
	key, err := streamKey(ctx, "", streamARN)
	if err != nil {
		return ConsumerKey{}, err
	}
	result := ConsumerKey{Stream: key, Name: name, CreatedAt: timestamp}
	if result.ARN() != resource {
		return ConsumerKey{}, failure("InvalidArgumentException", "Invalid consumer ARN: "+resource)
	}
	return result, nil
}

func requireActive(stream StreamRecord) error {
	if value(stream.Data.StreamStatus) != string(api.StreamStatusACTIVE) {
		return failure("ResourceInUseException", fmt.Sprintf("Stream %s under account %s not ACTIVE, instead in state %s", stream.Key.Name, stream.Key.AccountID, value(stream.Data.StreamStatus)))
	}
	return nil
}

func requireReadable(stream StreamRecord) error {
	if value(stream.Data.StreamStatus) == string(api.StreamStatusACTIVE) || value(stream.Data.StreamStatus) == string(api.StreamStatusUPDATING) {
		return nil
	}
	return requireActive(stream)
}

func (s *Service) stream(ctx context.Context, r Reader, name, resource string, actions ...string) (StreamRecord, error) {
	key, err := streamKey(ctx, name, resource)
	if err != nil {
		return StreamRecord{}, err
	}
	if err = s.authorizeResource(ctx, r, ResourceKey{Scope: key.Scope, ARN: key.ARN()}, nil, actions...); err != nil {
		return StreamRecord{}, err
	}
	stream, err := r.Stream(key)
	if errors.Is(err, ErrNotFound) {
		return StreamRecord{}, failure("ResourceNotFoundException", fmt.Sprintf("Stream %s under account %s not found.", key.Name, key.AccountID))
	}
	return stream, err
}

func (s *Service) authorize(ctx context.Context, action, resource string, conditions map[string][]string) error {
	rememberResource(ctx, action, ResourceKey{Scope: scopeFor(ctx), ARN: resource})
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "kinesis:" + action, ResourceARN: resource, Context: conditions, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return s.admitControl(ctx, action, resource)
}

func (s *Service) authorizeResource(ctx context.Context, r Reader, key ResourceKey, conditions map[string][]string, actions ...string) error {
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
	policy, err := r.Policy(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	now := s.clock.Now()
	bound := policy.Policy
	if now.Before(policy.PublishAt) {
		bound = policy.Effective
	}
	request := authorization.Request{ResourceARN: key.ARN, Context: conditions, EvaluationTime: &now, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}}
	if bound.Document != "" {
		request.ResourcePolicies = []authorization.BoundPolicy{bound}
	}
	for _, action := range actions {
		rememberResource(ctx, action, key)
		request.Action = "kinesis:" + action
		if rejected := s.authorizer.Authorize(ctx, request); rejected != nil {
			return rejected
		}
		if err := s.admitControl(ctx, action, key.ARN); err != nil {
			return err
		}
	}
	return nil
}

// resourceTarget authorizes the exact resource, never the consumer's parent.
func (s *Service) resourceTarget(ctx context.Context, r Reader, resource, action string, conditions map[string][]string) (ResourceKey, error) {
	mutating := action == "AddTagsToStream" || action == "RemoveTagsFromStream" || action == "TagResource" || action == "UntagResource" || action == "PutResourcePolicy" || action == "DeleteResourcePolicy"
	if strings.Contains(resource, "/consumer/") {
		consumer, err := consumerKey(ctx, resource)
		if err != nil {
			return ResourceKey{}, err
		}
		key := ResourceKey{Scope: consumer.Stream.Scope, ARN: consumer.ARN()}
		if err = s.authorizeResource(ctx, r, key, conditions, action); err != nil {
			return key, err
		}
		record, err := r.Consumer(consumer)
		if errors.Is(err, ErrNotFound) {
			return key, failure("ResourceNotFoundException", "Consumer "+resource+" not found.")
		}
		if err == nil && mutating && value(record.Data.ConsumerStatus) != "ACTIVE" {
			return key, failure("ResourceInUseException", "Consumer "+resource+" is not ACTIVE.")
		}
		return key, err
	}
	stream, err := streamKey(ctx, "", resource)
	if err != nil {
		return ResourceKey{}, err
	}
	key := ResourceKey{Scope: stream.Scope, ARN: stream.ARN()}
	if err = s.authorizeResource(ctx, r, key, conditions, action); err != nil {
		return key, err
	}
	record, err := r.Stream(stream)
	if errors.Is(err, ErrNotFound) {
		return key, failure("ResourceNotFoundException", "Stream "+stream.Name+" under account "+stream.AccountID+" not found.")
	}
	if err == nil && mutating {
		err = requireActive(record)
	}
	return key, err
}
