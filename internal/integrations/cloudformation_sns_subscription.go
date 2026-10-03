package integrations

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/services/cloudformation"
)

type cfnSNSSubscription struct{ commands StepFunctionsCommands }
type cfnSNSSubscriptionProperties struct {
	TopicArn            string
	Protocol            string
	Endpoint            string
	Region              string
	FilterPolicy        map[string]any
	FilterPolicyScope   string
	RawMessageDelivery  *cfnMessagingBool
	RedrivePolicy       map[string]any
	SubscriptionRoleArn string
}

func (h cfnSNSSubscription) Validate(raw cloudformation.Properties) error {
	var p cfnSNSSubscriptionProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return err
	}
	if p.TopicArn == "" || p.Endpoint == "" {
		return fmt.Errorf("TopicArn and Endpoint are required")
	}
	if p.Protocol != "sqs" && p.Protocol != "lambda" && p.Protocol != "firehose" {
		return fmt.Errorf("CloudFormation subscriptions support sqs, lambda and firehose; confirmation-dependent protocols are unsupported")
	}
	if p.FilterPolicyScope != "" && p.FilterPolicyScope != "MessageAttributes" && p.FilterPolicyScope != "MessageBody" {
		return fmt.Errorf("invalid FilterPolicyScope")
	}
	if p.Protocol == "lambda" && p.RawMessageDelivery != nil {
		return fmt.Errorf("RawMessageDelivery is not supported for Lambda subscriptions")
	}
	if (p.Protocol == "firehose") != (p.SubscriptionRoleArn != "") {
		return fmt.Errorf("SubscriptionRoleArn is required only for Firehose subscriptions")
	}
	if p.RedrivePolicy != nil {
		var policy struct {
			DeadLetterTargetArn string `json:"deadLetterTargetArn"`
		}
		if err := cfnMessagingDecode(p.RedrivePolicy, &policy); err != nil {
			return err
		}
		if len(p.RedrivePolicy) > 0 && policy.DeadLetterTargetArn == "" {
			return fmt.Errorf("RedrivePolicy requires deadLetterTargetArn")
		}
	}
	return nil
}
func (h cfnSNSSubscription) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnMessagingChanged(a, b, "TopicArn", "Protocol", "Endpoint"), nil
}
func (p cfnSNSSubscriptionProperties) scope(r cloudformation.ResourceRequest) error {
	if p.Region != "" && p.Region != r.Scope.Region {
		return fmt.Errorf("cross-region SNS subscriptions are not supported")
	}
	if err := cfnMessagingScopeARN(r, p.TopicArn, "sns"); err != nil {
		return err
	}
	return cfnMessagingScopeARN(r, p.Endpoint, p.Protocol)
}
func (p cfnSNSSubscriptionProperties) markerKey() string {
	return "stackd:cloudformation:subscription:" + cfnMessagingHash(p.Protocol+"\x00"+p.Endpoint)
}
func (p cfnSNSSubscriptionProperties) attributes() (api.SubscriptionAttributesMap, error) {
	attrs := api.SubscriptionAttributesMap{"FilterPolicy": "{}", "FilterPolicyScope": "MessageAttributes", "RedrivePolicy": "{}"}
	if p.FilterPolicy != nil {
		doc, err := cfnMessagingJSON(p.FilterPolicy)
		if err != nil {
			return nil, err
		}
		attrs["FilterPolicy"] = api.AttributeValue(doc)
	}
	if p.FilterPolicyScope != "" {
		attrs["FilterPolicyScope"] = api.AttributeValue(p.FilterPolicyScope)
	}
	if p.RedrivePolicy != nil {
		doc, err := cfnMessagingJSON(p.RedrivePolicy)
		if err != nil {
			return nil, err
		}
		attrs["RedrivePolicy"] = api.AttributeValue(doc)
	}
	if p.Protocol != "lambda" {
		attrs["RawMessageDelivery"] = "false"
		if p.RawMessageDelivery != nil {
			attrs["RawMessageDelivery"] = api.AttributeValue(strconv.FormatBool(bool(*p.RawMessageDelivery)))
		}
	}
	if p.SubscriptionRoleArn != "" {
		attrs["SubscriptionRoleArn"] = api.AttributeValue(p.SubscriptionRoleArn)
	}
	return attrs, nil
}
func (h cfnSNSSubscription) find(ctx context.Context, p cfnSNSSubscriptionProperties) (string, error) {
	in := &api.ListSubscriptionsByTopicInput{TopicArn: new(api.TopicARN(p.TopicArn))}
	for {
		out, err := cfnMessagingCall[api.ListSubscriptionsByTopicOutput](ctx, h.commands, "sns", "ListSubscriptionsByTopic", in)
		if err != nil {
			return "", err
		}
		for _, sub := range out.Subscriptions {
			if sub.Protocol != nil && sub.Endpoint != nil && string(*sub.Protocol) == p.Protocol && string(*sub.Endpoint) == p.Endpoint {
				if sub.SubscriptionArn == nil {
					return "", fmt.Errorf("subscription owner returned no ARN")
				}
				arn := string(*sub.SubscriptionArn)
				if !strings.HasPrefix(arn, p.TopicArn+":") {
					return "", fmt.Errorf("existing subscription is pending or deleted")
				}
				return arn, nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return "", nil
		}
		in.NextToken = out.NextToken
	}
}
func (h cfnSNSSubscription) result(arn string) cloudformation.ResourceResult {
	out := cfnMessagingResult(arn)
	out.Attributes = map[string]any{"Arn": arn}
	return out
}
func (h cfnSNSSubscription) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	var p cfnSNSSubscriptionProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := p.scope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	topic := cfnSNSTopic(h)
	tags, err := topic.tags(ctx, p.TopicArn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	key := p.markerKey()
	reservation := cfnMessagingMarker(r)
	marker := tags[key]
	if marker != "" && marker != reservation && !strings.HasPrefix(marker, reservation+"|") {
		return cloudformation.ResourceResult{}, fmt.Errorf("subscription endpoint is owned by another CloudFormation resource")
	}
	arn, err := h.find(ctx, p)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if arn != "" {
		if marker == "" {
			return cloudformation.ResourceResult{}, fmt.Errorf("subscription already exists without this resource's ownership marker")
		}
		if marker != reservation && marker != reservation+"|"+cfnMessagingHash(arn) {
			return cloudformation.ResourceResult{}, fmt.Errorf("subscription incarnation changed outside CloudFormation")
		}
		result := h.result(arn)
		if marker == reservation {
			if err := topic.tag(ctx, p.TopicArn, map[string]string{key: reservation + "|" + cfnMessagingHash(arn)}); err != nil {
				return result, err
			}
		}
		return result, nil
	}
	if strings.Contains(marker, "|") {
		return cloudformation.ResourceResult{}, fmt.Errorf("previously created subscription is missing; refusing to recreate its incarnation")
	}
	attrs, err := p.attributes()
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if marker == "" {
		if err := topic.tag(ctx, p.TopicArn, map[string]string{key: reservation}); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	out, err := cfnMessagingCall[api.SubscribeOutput](ctx, h.commands, "sns", "Subscribe", &api.SubscribeInput{TopicArn: new(api.TopicARN(p.TopicArn)), Protocol: new(api.Protocol(p.Protocol)), Endpoint: new(api.Endpoint2(p.Endpoint)), ReturnSubscriptionArn: new(api.Boolean(true)), Attributes: attrs})
	if err != nil {
		if marker == "" {
			err = errors.Join(err, topic.untag(ctx, p.TopicArn, []string{key}))
		}
		return cloudformation.ResourceResult{}, err
	}
	arn = string(*out.SubscriptionArn)
	result := h.result(arn)
	if err := topic.tag(ctx, p.TopicArn, map[string]string{key: reservation + "|" + cfnMessagingHash(arn)}); err != nil {
		return result, err
	}
	return result, nil
}
func (h cfnSNSSubscription) owned(ctx context.Context, r cloudformation.ResourceRequest, p cfnSNSSubscriptionProperties) (bool, error) {
	out, err := cfnMessagingCall[api.GetSubscriptionAttributesOutput](ctx, h.commands, "sns", "GetSubscriptionAttributes", &api.GetSubscriptionAttributesInput{SubscriptionArn: new(api.SubscriptionARN(r.PhysicalID))})
	if cfnMessagingMissing(err, "NotFound", "ResourceNotFound") {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if string(out.Attributes["TopicArn"]) != p.TopicArn || string(out.Attributes["Protocol"]) != p.Protocol || string(out.Attributes["Endpoint"]) != p.Endpoint || string(out.Attributes["Owner"]) != r.Scope.Account {
		return false, fmt.Errorf("subscription does not match the retained resource identity")
	}
	tags, err := cfnSNSTopic(h).tags(ctx, p.TopicArn)
	if cfnMessagingMissing(err, "NotFound", "ResourceNotFound") {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	marker := tags[p.markerKey()]
	reservation := cfnMessagingMarker(r)
	if marker != reservation && marker != reservation+"|"+cfnMessagingHash(r.PhysicalID) {
		return false, fmt.Errorf("subscription ownership marker is missing or belongs to another incarnation")
	}
	return true, nil
}
func (h cfnSNSSubscription) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := h.result(r.PhysicalID)
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replace {
		return result, fmt.Errorf("subscription update requires replacement")
	}
	var p cfnSNSSubscriptionProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return result, err
	}
	if err := p.scope(r); err != nil {
		return result, err
	}
	exists, err := h.owned(ctx, r, p)
	if err != nil {
		return result, err
	}
	if !exists {
		return result, fmt.Errorf("subscription does not exist")
	}
	attrs, err := p.attributes()
	if err != nil {
		return result, err
	}
	set := func(name, value string) error {
		return cfnMessagingExec(ctx, h.commands, "sns", "SetSubscriptionAttributes", &api.SetSubscriptionAttributesInput{SubscriptionArn: new(api.SubscriptionARN(r.PhysicalID)), AttributeName: new(api.AttributeName(name)), AttributeValue: new(api.AttributeValue(value))})
	}
	// Clear the old filter before changing its scope: either policy may be
	// invalid under the other scope. The owner validates every transition.
	if err := set("FilterPolicy", "{}"); err != nil {
		return result, err
	}
	if err := set("FilterPolicyScope", string(attrs["FilterPolicyScope"])); err != nil {
		return result, err
	}
	if err := set("FilterPolicy", string(attrs["FilterPolicy"])); err != nil {
		return result, err
	}
	for _, name := range []string{"RawMessageDelivery", "RedrivePolicy", "SubscriptionRoleArn"} {
		if value, ok := attrs[api.AttributeName(name)]; ok {
			if err := set(name, string(value)); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}
func (h cfnSNSSubscription) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	var p cfnSNSSubscriptionProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return err
	}
	if err := p.scope(r); err != nil {
		return err
	}
	exists, err := h.owned(ctx, r, p)
	if err != nil {
		return err
	}
	if exists {
		if err := cfnMessagingExec(ctx, h.commands, "sns", "Unsubscribe", &api.UnsubscribeInput{SubscriptionArn: new(api.SubscriptionARN(r.PhysicalID))}); err != nil {
			return err
		}
	}
	topic := cfnSNSTopic(h)
	tags, err := topic.tags(ctx, p.TopicArn)
	if cfnMessagingMissing(err, "NotFound", "ResourceNotFound") {
		return nil
	}
	if err != nil {
		return err
	}
	marker := tags[p.markerKey()]
	if marker == cfnMessagingMarker(r) || marker == cfnMessagingMarker(r)+"|"+cfnMessagingHash(r.PhysicalID) {
		return topic.untag(ctx, p.TopicArn, []string{p.markerKey()})
	}
	return nil
}

type cfnSNSInlineSubscription struct {
	Endpoint string
	Protocol string
}

func (h cfnSNSTopic) subscriptions(ctx context.Context, r cloudformation.ResourceRequest, arn string, next, old []cfnSNSInlineSubscription) error {
	handler := cfnSNSSubscription(h)
	request := func(sub cfnSNSInlineSubscription) cloudformation.ResourceRequest {
		child := r
		child.LogicalID = r.LogicalID + "-subscription-" + cfnMessagingHash(sub.Protocol+"\x00"+sub.Endpoint)
		child.Type = "AWS::SNS::Subscription"
		child.PhysicalID = ""
		child.Properties = cloudformation.Properties{"TopicArn": arn, "Protocol": sub.Protocol, "Endpoint": sub.Endpoint}
		return child
	}
	wanted := make(map[cfnSNSInlineSubscription]bool, len(next))
	for _, sub := range next {
		wanted[sub] = true
		if _, err := handler.Create(ctx, request(sub)); err != nil {
			return err
		}
	}
	for _, sub := range old {
		if wanted[sub] {
			continue
		}
		child := request(sub)
		p := cfnSNSSubscriptionProperties{TopicArn: arn, Protocol: sub.Protocol, Endpoint: sub.Endpoint}
		id, err := handler.find(ctx, p)
		if err != nil {
			return err
		}
		if id != "" {
			child.PhysicalID = id
			if err := handler.Delete(ctx, child); err != nil {
				return err
			}
			continue
		}
		tags, err := h.tags(ctx, arn)
		if err != nil {
			return err
		}
		marker := tags[p.markerKey()]
		reservation := cfnMessagingMarker(child)
		if marker == reservation || strings.HasPrefix(marker, reservation+"|") {
			if err := h.untag(ctx, arn, []string{p.markerKey()}); err != nil {
				return err
			}
		}
	}
	return nil
}
