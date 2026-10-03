package lambda

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func (s *Service) registerTags() {
	register(s, "ListTags", s.listTags)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
}

func tagParameterError(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidParameterValueException", Message: message, StatusCode: 400, Type: "User"}
}

// Generated TagKey/TagValue constraints own character and length validation.
// These semantic constraints also apply to CreateFunction's optional tag map.
func validateFunctionTags(tags map[string]string) *awswire.Error {
	if len(tags) > 50 {
		return tagParameterError("A function cannot have more than 50 tags.")
	}
	for key := range tags {
		if reservedTagKey(key) {
			return tagParameterError("Tag keys must not start with aws:.")
		}
	}
	return nil
}

func reservedTagKey(key string) bool {
	return len(key) >= 4 && strings.EqualFold(key[:4], "aws:")
}

// A missing function still needs an IAM decision. Return lookup presence
// separately so semantic request validation follows authorization but precedes
// resource existence, as it does in native Lambda.
func (s *Service) tagFunction(r Reader, ref FunctionReference, action string, requested map[string]string, keys []string) (FunctionRecord, bool, error) {
	function, lookup := r.Function(ref.FunctionKey)
	if lookup != nil && !errors.Is(lookup, ErrNotFound) {
		return FunctionRecord{}, false, lookup
	}
	function.Key = ref.FunctionKey
	policy, err := r.FunctionPolicy(ref)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return FunctionRecord{}, false, err
	}
	conditions := tagConditions(nil, requested)
	if len(keys) > 0 {
		conditions["aws:TagKeys"] = keys
	}
	if wire := s.authorizeFunctionPolicy(r.Context(), function, ref.ARN(), action, policy, conditions); wire != nil {
		return FunctionRecord{}, false, wire
	}
	return function, lookup == nil, nil
}

func (s *Service) listTags(ctx context.Context, in *api.ListTagsInput) (*api.ListTagsOutput, *awswire.Error) {
	if strings.Contains(value(in.Resource), ":event-source-mapping:") {
		return s.listEventSourceMappingTags(ctx, in)
	}
	if strings.Contains(value(in.Resource), ":code-signing-config:") {
		return s.listCodeSigningTags(ctx, in)
	}
	if strings.Contains(value(in.Resource), ":capacity-provider:") {
		return s.listCapacityTags(ctx, in)
	}
	ref, wire := parseFunctionReference(ctx, value(in.Resource), "")
	if wire != nil {
		return nil, wire
	}
	out := &api.ListTagsOutput{Tags: api.Tags{}}
	err := s.repository.View(ctx, func(r Reader) error {
		function, found, err := s.tagFunction(r, ref, "ListTags", nil, nil)
		if err != nil {
			return err
		}
		if ref.Qualifier != "" {
			return tagParameterError("Tagging requires an unqualified function ARN.")
		}
		if !found {
			return ErrNotFound
		}
		for key, val := range function.Tags {
			out.Tags[api.TagKey(key)] = api.TagValue(val)
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) tagResource(ctx context.Context, in *api.TagResourceInput) (*api.TagResourceOutput, *awswire.Error) {
	if strings.Contains(value(in.Resource), ":event-source-mapping:") {
		return s.tagEventSourceMapping(ctx, in)
	}
	if strings.Contains(value(in.Resource), ":code-signing-config:") {
		return s.tagCodeSigning(ctx, in)
	}
	if strings.Contains(value(in.Resource), ":capacity-provider:") {
		return s.tagCapacityProvider(ctx, in)
	}
	ref, wire := parseFunctionReference(ctx, value(in.Resource), "")
	if wire != nil {
		return nil, wire
	}
	requested := make(map[string]string, len(in.Tags))
	for key, val := range in.Tags {
		requested[string(key)] = string(val)
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, found, err := s.tagFunction(tx, ref, "TagResource", requested, nil)
		if err != nil {
			return err
		}
		if ref.Qualifier != "" {
			return tagParameterError("Tagging requires an unqualified function ARN.")
		}
		if len(requested) == 0 {
			return tagParameterError("Tags must contain at least one entry.")
		}
		if wire := validateFunctionTags(requested); wire != nil {
			return wire
		}
		if !found {
			return ErrNotFound
		}
		if function.Tags == nil {
			function.Tags = make(map[string]string, len(requested))
		}
		for key, val := range requested {
			function.Tags[key] = val
		}
		if len(function.Tags) > 50 {
			return tagParameterError("A function cannot have more than 50 tags.")
		}
		if err := s.putFunctionTags(tx, function); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "TagResource", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.TagResourceOutput{}, nil
}

func (s *Service) untagResource(ctx context.Context, in *api.UntagResourceInput) (*api.UntagResourceOutput, *awswire.Error) {
	if strings.Contains(value(in.Resource), ":event-source-mapping:") {
		return s.untagEventSourceMapping(ctx, in)
	}
	if strings.Contains(value(in.Resource), ":code-signing-config:") {
		return s.untagCodeSigning(ctx, in)
	}
	if strings.Contains(value(in.Resource), ":capacity-provider:") {
		return s.untagCapacityProvider(ctx, in)
	}
	ref, wire := parseFunctionReference(ctx, value(in.Resource), "")
	if wire != nil {
		return nil, wire
	}
	keys := make([]string, len(in.TagKeys))
	for i, key := range in.TagKeys {
		keys[i] = string(key)
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, found, err := s.tagFunction(tx, ref, "UntagResource", nil, keys)
		if err != nil {
			return err
		}
		if ref.Qualifier != "" {
			return tagParameterError("Tagging requires an unqualified function ARN.")
		}
		for _, key := range keys {
			if reservedTagKey(key) {
				return tagParameterError("Tag keys must not start with aws:.")
			}
		}
		if !found {
			return ErrNotFound
		}
		for _, key := range keys {
			delete(function.Tags, key)
		}
		if err := s.putFunctionTags(tx, function); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "UntagResource", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.UntagResourceOutput{}, nil
}

func (s *Service) putFunctionTags(tx Transaction, function FunctionRecord) error {
	function.Revision = uuid.NewString()
	function.Modified = s.clock.Now()
	if err := tx.PutFunction(function); err != nil {
		return err
	}
	pending, err := tx.PendingFunction(function.Key)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	// A prepared deployment must not restore old tags at promotion. Preserve
	// both deployment identities so neither warm nor preparing code is retired.
	pending.Tags = function.Tags
	pending.Revision = function.Revision
	pending.Modified = function.Modified
	return tx.PutPendingFunction(pending)
}
