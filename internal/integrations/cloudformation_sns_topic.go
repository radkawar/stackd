package integrations

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sns"
)

type cfnSNSTopic struct{ commands StepFunctionsCommands }
type cfnSNSTopicProperties struct {
	TopicName                 string
	DisplayName               string
	FifoTopic                 *cfnMessagingBool
	ContentBasedDeduplication *cfnMessagingBool
	FifoThroughputScope       string
	KmsMasterKeyId            string
	SignatureVersion          string
	TracingConfig             string
	ArchivePolicy             map[string]any
	DeliveryStatusLogging     []cfnSNSLogging
	Subscription              []cfnSNSInlineSubscription
	Tags                      []cfnMessagingTag
}
type cfnSNSLogging struct {
	Protocol                  string
	FailureFeedbackRoleArn    string
	SuccessFeedbackRoleArn    string
	SuccessFeedbackSampleRate *cfnMessagingInt
}

func (p cfnSNSTopicProperties) fifo() bool { return p.FifoTopic != nil && bool(*p.FifoTopic) }
func cfnSNSFeedbackPrefix(protocol string) string {
	switch protocol {
	case "http/s":
		return "HTTP"
	case "sqs":
		return "SQS"
	case "lambda":
		return "Lambda"
	case "firehose":
		return "Firehose"
	default:
		return ""
	}
}
func (h cfnSNSTopic) Validate(raw cloudformation.Properties) error {
	var p cfnSNSTopicProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return err
	}
	if p.TopicName != "" && (len(p.TopicName) > 256 || strings.HasSuffix(p.TopicName, ".fifo") != p.fifo()) {
		return fmt.Errorf("TopicName must match FifoTopic and have at most 256 characters")
	}
	if !p.fifo() && (p.ContentBasedDeduplication != nil || p.FifoThroughputScope != "" || p.ArchivePolicy != nil) {
		return fmt.Errorf("FIFO topic properties require FifoTopic=true")
	}
	if p.TracingConfig != "" && p.TracingConfig != "PassThrough" {
		return fmt.Errorf("SNS Active tracing is not implemented by the SNS owner")
	}
	if p.SignatureVersion != "" && p.SignatureVersion != "1" && p.SignatureVersion != "2" {
		return fmt.Errorf("SignatureVersion must be 1 or 2")
	}
	if p.FifoThroughputScope != "" && p.FifoThroughputScope != "Topic" && p.FifoThroughputScope != "MessageGroup" {
		return fmt.Errorf("invalid FifoThroughputScope")
	}
	if p.ArchivePolicy != nil {
		var archive struct{ MessageRetentionPeriod *cfnMessagingInt }
		if err := cfnMessagingDecode(p.ArchivePolicy, &archive); err != nil {
			return err
		}
		if archive.MessageRetentionPeriod != nil && (*archive.MessageRetentionPeriod < 1 || *archive.MessageRetentionPeriod > 365) {
			return fmt.Errorf("archive retention must be 1 through 365 days")
		}
	}
	seen := map[string]bool{}
	for _, log := range p.DeliveryStatusLogging {
		if cfnSNSFeedbackPrefix(log.Protocol) == "" || seen[log.Protocol] {
			return fmt.Errorf("unsupported or duplicate logging protocol %q", log.Protocol)
		}
		seen[log.Protocol] = true
		if log.SuccessFeedbackSampleRate != nil && (*log.SuccessFeedbackSampleRate < 0 || *log.SuccessFeedbackSampleRate > 100) {
			return fmt.Errorf("feedback sample rate must be 0 through 100")
		}
	}
	subscriptions := map[cfnSNSInlineSubscription]bool{}
	for _, sub := range p.Subscription {
		if sub.Endpoint == "" || sub.Protocol != "sqs" && sub.Protocol != "lambda" || p.fifo() && sub.Protocol != "sqs" {
			return fmt.Errorf("inline subscriptions support SQS and Lambda endpoints (FIFO topics require SQS)")
		}
		if subscriptions[sub] {
			return fmt.Errorf("duplicate inline subscription")
		}
		subscriptions[sub] = true
	}
	_, err := cfnMessagingTags(cloudformation.ResourceRequest{}, p.Tags)
	return err
}
func (h cfnSNSTopic) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	var old, next cfnSNSTopicProperties
	if err := cfnMessagingDecode(a, &old); err != nil {
		return false, err
	}
	if err := cfnMessagingDecode(b, &next); err != nil {
		return false, err
	}
	changed := old.TopicName != next.TopicName || old.fifo() != next.fifo()
	if !changed && old.FifoThroughputScope == "MessageGroup" && next.FifoThroughputScope != "MessageGroup" {
		return false, fmt.Errorf("SNS does not permit changing MessageGroup throughput scope back to Topic")
	}
	return cfnMessagingReplacement(old.TopicName != "" && old.TopicName == next.TopicName, changed)
}
func (p cfnSNSTopicProperties) attributes(creating bool) (api.TopicAttributesMap, error) {
	attrs := api.TopicAttributesMap{"DisplayName": api.AttributeValue(p.DisplayName), "KmsMasterKeyId": api.AttributeValue(p.KmsMasterKeyId), "SignatureVersion": "1", "TracingConfig": "PassThrough"}
	if p.SignatureVersion != "" {
		attrs["SignatureVersion"] = api.AttributeValue(p.SignatureVersion)
	}
	if creating {
		attrs["FifoTopic"] = api.AttributeValue(strconv.FormatBool(p.fifo()))
	}
	if p.fifo() {
		attrs["ContentBasedDeduplication"] = "false"
		if p.ContentBasedDeduplication != nil {
			attrs["ContentBasedDeduplication"] = api.AttributeValue(strconv.FormatBool(bool(*p.ContentBasedDeduplication)))
		}
		attrs["FifoThroughputScope"] = "Topic"
		if p.FifoThroughputScope != "" {
			attrs["FifoThroughputScope"] = api.AttributeValue(p.FifoThroughputScope)
		}
		attrs["ArchivePolicy"] = "{}"
		if p.ArchivePolicy != nil {
			doc, err := cfnMessagingJSON(p.ArchivePolicy)
			if err != nil {
				return nil, err
			}
			attrs["ArchivePolicy"] = api.AttributeValue(doc)
		}
	}
	for _, log := range p.DeliveryStatusLogging {
		prefix := cfnSNSFeedbackPrefix(log.Protocol)
		attrs[api.AttributeName(prefix+"FailureFeedbackRoleArn")] = api.AttributeValue(log.FailureFeedbackRoleArn)
		attrs[api.AttributeName(prefix+"SuccessFeedbackRoleArn")] = api.AttributeValue(log.SuccessFeedbackRoleArn)
		if log.SuccessFeedbackSampleRate != nil {
			attrs[api.AttributeName(prefix+"SuccessFeedbackSampleRate")] = api.AttributeValue(strconv.FormatInt(int64(*log.SuccessFeedbackSampleRate), 10))
		}
	}
	return attrs, nil
}
func cfnSNSNativeTags(tags map[string]string) api.TagList {
	out := make(api.TagList, 0, len(tags))
	for _, k := range cfnMessagingKeys(tags) {
		out = append(out, api.Tag{Key: new(api.TagKey(k)), Value: new(api.TagValue(tags[k]))})
	}
	return out
}
func (h cfnSNSTopic) tags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := cfnMessagingCall[api.ListTagsForResourceOutput](ctx, h.commands, "sns", "ListTagsForResource", &api.ListTagsForResourceInput{ResourceArn: new(api.AmazonResourceName(arn))})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(out.Tags))
	for _, tag := range out.Tags {
		tags[string(*tag.Key)] = string(*tag.Value)
	}
	return tags, nil
}
func (h cfnSNSTopic) tag(ctx context.Context, arn string, tags map[string]string) error {
	return cfnMessagingExec(ctx, h.commands, "sns", "TagResource", &api.TagResourceInput{ResourceArn: new(api.AmazonResourceName(arn)), Tags: cfnSNSNativeTags(tags)})
}
func (h cfnSNSTopic) untag(ctx context.Context, arn string, keys []string) error {
	var native api.TagKeyList
	for _, key := range keys {
		native = append(native, api.TagKey(key))
	}
	return cfnMessagingExec(ctx, h.commands, "sns", "UntagResource", &api.UntagResourceInput{ResourceArn: new(api.AmazonResourceName(arn)), TagKeys: native})
}
func (h cfnSNSTopic) set(ctx context.Context, arn, name, value string) error {
	return cfnMessagingExec(ctx, h.commands, "sns", "SetTopicAttributes", &api.SetTopicAttributesInput{TopicArn: new(api.TopicARN(arn)), AttributeName: new(api.AttributeName(name)), AttributeValue: new(api.AttributeValue(value))})
}
func (h cfnSNSTopic) result(arn string) cloudformation.ResourceResult {
	out := cfnMessagingResult(arn)
	parts := strings.Split(arn, ":")
	out.Attributes = map[string]any{"TopicArn": arn, "TopicName": parts[len(parts)-1]}
	return out
}
func (h cfnSNSTopic) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	var p cfnSNSTopicProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := p.TopicName
	if name == "" {
		name = cfnMessagingName(r, 256, p.fifo())
	}
	tags, err := cfnSNSTopicTags(r, p.Tags)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	attrs, err := p.attributes(true)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = sns.WithCloudFormationTopicClaim(ctx, cfnSNSTopicClaim(r))
	out, err := cfnMessagingCall[api.CreateTopicOutput](ctx, h.commands, "sns", "CreateTopic", &api.CreateTopicInput{Name: new(api.TopicName(name)), Attributes: attrs, Tags: cfnSNSNativeTags(tags)})
	if err != nil {
		recovered, recoveryErr := h.RecoverCreation(ctx, r)
		if recoveryErr == nil {
			return recovered, err
		}
		return cloudformation.ResourceResult{}, err
	}
	arn := string(*out.TopicArn)
	r.PhysicalID = arn
	claim := cfnSNSTopicClaim(r)
	_, observation, err := h.observe(ctx, arn)
	if err != nil {
		return h.result(arn), err
	}
	claim.Incarnation = observation.Incarnation
	ctx = sns.WithCloudFormationTopicClaim(ctx, claim)
	return h.result(arn), h.subscriptions(ctx, r, arn, p.Subscription, nil)
}
func (h cfnSNSTopic) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := h.result(r.PhysicalID)
	replacement, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replacement {
		return result, fmt.Errorf("topic update requires replacement")
	}
	var old, next cfnSNSTopicProperties
	if err := cfnMessagingDecode(r.Previous, &old); err != nil {
		return result, err
	}
	if err := cfnMessagingDecode(r.Properties, &next); err != nil {
		return result, err
	}
	ctx, err = h.ownedContext(ctx, r)
	if err != nil {
		return result, err
	}
	tags, err := h.tags(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	attrs, err := next.attributes(false)
	if err != nil {
		return result, err
	}
	for _, log := range old.DeliveryStatusLogging {
		prefix := cfnSNSFeedbackPrefix(log.Protocol)
		for _, suffix := range []string{"FailureFeedbackRoleArn", "SuccessFeedbackRoleArn", "SuccessFeedbackSampleRate"} {
			key := api.AttributeName(prefix + suffix)
			if _, ok := attrs[key]; !ok {
				attrs[key] = ""
				if suffix == "SuccessFeedbackSampleRate" {
					attrs[key] = "0"
				}
			}
		}
	}
	for _, key := range cfnMessagingKeys(attrs) {
		if err := h.set(ctx, r.PhysicalID, string(key), string(attrs[key])); err != nil {
			return result, err
		}
	}
	if err := h.subscriptions(ctx, r, r.PhysicalID, next.Subscription, old.Subscription); err != nil {
		return result, err
	}
	wanted, err := cfnSNSTopicTags(r, next.Tags)
	if err != nil {
		return result, err
	}
	var remove []string
	for k := range tags {
		if _, ok := wanted[k]; !ok {
			remove = append(remove, k)
		}
	}
	if len(remove) > 0 {
		if err := h.untag(ctx, r.PhysicalID, remove); err != nil {
			return result, err
		}
	}
	if err := h.tag(ctx, r.PhysicalID, wanted); err != nil {
		return result, err
	}
	return result, nil
}
func (h cfnSNSTopic) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return fmt.Errorf("topic deletion requires a physical identifier")
	}
	ctx, err := h.ownedContext(ctx, r)
	if cfnMessagingMissing(err, "ResourceNotFound", "NotFound") {
		return nil
	}
	if err != nil {
		return err
	}
	if r.CloudControl {
		if _, _, err := h.observe(ctx, r.PhysicalID); err != nil {
			return err
		}
	}
	out, err := cfnMessagingCall[api.GetTopicAttributesOutput](ctx, h.commands, "sns", "GetTopicAttributes", &api.GetTopicAttributesInput{TopicArn: new(api.TopicARN(r.PhysicalID))})
	if err != nil {
		return err
	}
	if out.Attributes["ArchivePolicy"] != "" {
		if err := h.set(ctx, r.PhysicalID, "ArchivePolicy", "{}"); err != nil {
			return err
		}
	}
	return cfnMessagingExec(ctx, h.commands, "sns", "DeleteTopic", &api.DeleteTopicInput{TopicArn: new(api.TopicARN(r.PhysicalID))})
}
