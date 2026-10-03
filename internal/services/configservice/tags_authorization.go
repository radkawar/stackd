package configservice

import (
	"context"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/configservice"
)

func (s *Service) authorizeResourceTags(ctx context.Context, action, arn string, tags map[string]string) error {
	values := requestTagContext(ctx)
	for key, val := range tags {
		values["aws:ResourceTag/"+key] = []string{val}
	}
	now := s.clock.Now()
	if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "config:" + action, ResourceARN: arn, Context: values, EvaluationTime: &now}); denied != nil {
		return denied
	}
	return nil
}

func requestTagContext(ctx context.Context) map[string][]string {
	values := map[string][]string{}
	request, ok := awsapi.FromContext(ctx)
	if !ok {
		return values
	}
	var tags []api.Tag
	var keys api.TagKeyList
	switch in := request.Input.(type) {
	case *api.PutConfigRuleInput:
		tags = in.Tags
	case *api.PutConfigurationAggregatorInput:
		tags = in.Tags
	case *api.PutAggregationAuthorizationInput:
		tags = in.Tags
	case *api.PutConfigurationRecorderInput:
		tags = in.Tags
	case *api.TagResourceInput:
		tags = in.Tags
	case *api.UntagResourceInput:
		keys = in.TagKeys
	}
	for _, tag := range tags {
		key := value(tag.Key)
		values["aws:RequestTag/"+key] = []string{value(tag.Value)}
		values["aws:TagKeys"] = append(values["aws:TagKeys"], key)
	}
	for _, key := range keys {
		values["aws:TagKeys"] = append(values["aws:TagKeys"], string(key))
	}
	return values
}

// Put APIs apply tags only to new resources. Their dependent TagResource
// permission is checked before any creation tags are written.
func (s *Service) putCreationTags(tx Transaction, arn string, input []api.Tag) error {
	if len(input) == 0 {
		return nil
	}
	tags, err := mergeTags(nil, input)
	if err != nil {
		return err
	}
	if err := s.authorizeResourceTags(tx.Context(), "TagResource", arn, nil); err != nil {
		return err
	}
	return tx.PutTags(scopeFor(tx.Context()), arn, tags)
}
