package integrations

import (
	"fmt"
	"strings"

	api "stackd/internal/awsapi/s3"
)

type cfnS3Notifications struct {
	EventBridgeConfiguration *struct{ EventBridgeEnabled *cfnMessagingBool }
	QueueConfigurations      []struct {
		Event  string
		Queue  string
		Filter *cfnS3NotificationFilter
	}
	TopicConfigurations []struct {
		Event  string
		Topic  string
		Filter *cfnS3NotificationFilter
	}
	LambdaConfigurations []struct {
		Event    string
		Function string
		Filter   *cfnS3NotificationFilter
	}
}
type cfnS3NotificationFilter struct {
	S3Key *struct {
		Rules []struct {
			Name  string
			Value string
		}
	}
}

func (f *cfnS3NotificationFilter) native() (*api.NotificationConfigurationFilter, error) {
	if f == nil {
		return nil, nil
	}
	if f.S3Key == nil || len(f.S3Key.Rules) == 0 {
		return nil, fmt.Errorf("notification Filter requires S3Key.Rules")
	}
	out := &api.NotificationConfigurationFilter{Key: &api.S3KeyFilter{}}
	for _, rule := range f.S3Key.Rules {
		// S3 admits filter rule names case-insensitively and normalizes them.
		if !strings.EqualFold(rule.Name, "prefix") && !strings.EqualFold(rule.Name, "suffix") {
			return nil, fmt.Errorf("notification filter Name must be prefix or suffix")
		}
		out.Key.FilterRules = append(out.Key.FilterRules, api.FilterRule{Name: new(api.FilterRuleName(strings.ToLower(rule.Name))), Value: new(api.FilterRuleValue(rule.Value))})
	}
	return out, nil
}
func (p *cfnS3Notifications) native() (*api.NotificationConfiguration, error) {
	out := &api.NotificationConfiguration{}
	if p == nil {
		return out, nil
	}
	if bridge := p.EventBridgeConfiguration; bridge != nil {
		if bridge.EventBridgeEnabled == nil {
			return nil, fmt.Errorf("EventBridgeEnabled is required")
		}
		if bool(*bridge.EventBridgeEnabled) {
			out.EventBridgeConfiguration = &api.EventBridgeConfiguration{}
		}
	}
	for i, rule := range p.QueueConfigurations {
		if rule.Event == "" || rule.Queue == "" {
			return nil, fmt.Errorf("queue notifications require Event and Queue")
		}
		filter, err := rule.Filter.native()
		if err != nil {
			return nil, err
		}
		out.QueueConfigurations = append(out.QueueConfigurations, api.QueueConfiguration{Id: new(api.NotificationId(fmt.Sprintf("cloudformation-queue-%d", i))), Events: api.EventList{api.Event(rule.Event)}, QueueArn: new(api.QueueArn(rule.Queue)), Filter: filter})
	}
	for i, rule := range p.TopicConfigurations {
		if rule.Event == "" || rule.Topic == "" {
			return nil, fmt.Errorf("topic notifications require Event and Topic")
		}
		filter, err := rule.Filter.native()
		if err != nil {
			return nil, err
		}
		out.TopicConfigurations = append(out.TopicConfigurations, api.TopicConfiguration{Id: new(api.NotificationId(fmt.Sprintf("cloudformation-topic-%d", i))), Events: api.EventList{api.Event(rule.Event)}, TopicArn: new(api.TopicArn(rule.Topic)), Filter: filter})
	}
	for i, rule := range p.LambdaConfigurations {
		if rule.Event == "" || rule.Function == "" {
			return nil, fmt.Errorf("lambda notifications require Event and Function")
		}
		filter, err := rule.Filter.native()
		if err != nil {
			return nil, err
		}
		out.LambdaFunctionConfigurations = append(out.LambdaFunctionConfigurations, api.LambdaFunctionConfiguration{Id: new(api.NotificationId(fmt.Sprintf("cloudformation-lambda-%d", i))), Events: api.EventList{api.Event(rule.Event)}, LambdaFunctionArn: new(api.LambdaFunctionArn(rule.Function)), Filter: filter})
	}
	return out, nil
}
