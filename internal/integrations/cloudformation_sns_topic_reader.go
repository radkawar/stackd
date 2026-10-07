package integrations

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/services/cloudformation"
)

func (h cfnSNSTopic) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	if err := cfnMessagingScopeARN(r, r.PhysicalID, "sns"); err != nil {
		return nil, err
	}
	ctx, err := h.ownedContext(ctx, r)
	if err != nil {
		return nil, err
	}
	out, _, err := h.observe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(r.PhysicalID, ":")
	model := cloudformation.Properties{"TopicName": parts[len(parts)-1]}
	for _, key := range []string{"DisplayName", "KmsMasterKeyId", "SignatureVersion", "TracingConfig", "FifoThroughputScope"} {
		if value := string(out.Attributes[api.AttributeName(key)]); value != "" {
			model[key] = value
		}
	}
	for _, key := range []string{"FifoTopic", "ContentBasedDeduplication"} {
		if value := string(out.Attributes[api.AttributeName(key)]); value != "" {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return nil, err
			}
			model[key] = parsed
		}
	}
	if raw := string(out.Attributes["ArchivePolicy"]); raw != "" {
		var policy map[string]any
		if err := json.Unmarshal([]byte(raw), &policy); err != nil {
			return nil, err
		}
		model["ArchivePolicy"] = policy
	}
	var logging []any
	for _, protocol := range []string{"http/s", "sqs", "lambda", "firehose"} {
		prefix := cfnSNSFeedbackPrefix(protocol)
		entry := map[string]any{"Protocol": protocol}
		for _, suffix := range []string{"FailureFeedbackRoleArn", "SuccessFeedbackRoleArn", "SuccessFeedbackSampleRate"} {
			value := string(out.Attributes[api.AttributeName(prefix+suffix)])
			if value == "" {
				continue
			}
			if suffix == "SuccessFeedbackSampleRate" {
				n, err := strconv.Atoi(value)
				if err != nil {
					return nil, err
				}
				entry[suffix] = n
			} else {
				entry[suffix] = value
			}
		}
		if len(entry) > 1 {
			logging = append(logging, entry)
		}
	}
	if len(logging) != 0 {
		model["DeliveryStatusLogging"] = logging
	}
	tags, err := h.tags(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	var customer []any
	for _, key := range cfnMessagingKeys(tags) {
		customer = append(customer, map[string]any{"Key": key, "Value": tags[key]})
	}
	if len(customer) != 0 {
		model["Tags"] = customer
	}
	var subscriptions []any
	input := &api.ListSubscriptionsByTopicInput{TopicArn: new(api.TopicARN(r.PhysicalID))}
	for {
		out, err := cfnMessagingCall[api.ListSubscriptionsByTopicOutput](ctx, h.commands, "sns", "ListSubscriptionsByTopic", input)
		if err != nil {
			return nil, err
		}
		for _, sub := range out.Subscriptions {
			if sub.Protocol != nil && sub.Endpoint != nil && (*sub.Protocol == "sqs" || *sub.Protocol == "lambda") {
				subscriptions = append(subscriptions, map[string]any{"Protocol": string(*sub.Protocol), "Endpoint": string(*sub.Endpoint)})
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		input.NextToken = out.NextToken
	}
	if len(subscriptions) != 0 {
		model["Subscription"] = subscriptions
	}
	return model, nil
}
func (h cfnSNSTopic) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	arns, err := cfnSNSListTopicARNs(ctx, h.commands, r)
	if err != nil {
		return nil, err
	}
	out := make([]cloudformation.ResourceDescription, 0, len(arns))
	for _, arn := range arns {
		r.PhysicalID = arn
		model, err := h.Read(ctx, r)
		if err != nil {
			return nil, err
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: arn, Properties: model})
	}
	return out, nil
}
func (h cfnSNSTopic) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(r.PhysicalID), nil
}

var _ cloudformation.ResourceReader = cfnSNSTopic{}
var _ cloudformation.ResourceResultReader = cfnSNSTopic{}
