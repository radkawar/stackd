package integrations

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/services/cloudformation"
)

type cfnSQSQueue struct{ commands StepFunctionsCommands }
type cfnSQSQueueProperties struct {
	QueueName                     string
	FifoQueue                     *cfnMessagingBool
	ContentBasedDeduplication     *cfnMessagingBool
	SqsManagedSseEnabled          *cfnMessagingBool
	DeduplicationScope            string
	FifoThroughputLimit           string
	KmsMasterKeyId                string
	DelaySeconds                  *cfnMessagingInt
	MaximumMessageSize            *cfnMessagingInt
	MessageRetentionPeriod        *cfnMessagingInt
	ReceiveMessageWaitTimeSeconds *cfnMessagingInt
	VisibilityTimeout             *cfnMessagingInt
	KmsDataKeyReusePeriodSeconds  *cfnMessagingInt
	RedrivePolicy                 map[string]any
	RedriveAllowPolicy            map[string]any
	Tags                          []cfnMessagingTag
}

func (p cfnSQSQueueProperties) fifo() bool { return p.FifoQueue != nil && bool(*p.FifoQueue) }
func (h cfnSQSQueue) Validate(raw cloudformation.Properties) error {
	var p cfnSQSQueueProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return err
	}
	if p.QueueName != "" && (len(p.QueueName) > 80 || strings.HasSuffix(p.QueueName, ".fifo") != p.fifo()) {
		return fmt.Errorf("QueueName must match FifoQueue and have at most 80 characters")
	}
	if !p.fifo() && (p.ContentBasedDeduplication != nil || p.DeduplicationScope != "" || p.FifoThroughputLimit != "") {
		return fmt.Errorf("FIFO properties require FifoQueue=true")
	}
	// TODO: Comeback admit per-message-group throughput after the SQS owner enforces its quotas.
	if p.FifoThroughputLimit != "" && p.FifoThroughputLimit != "perQueue" {
		return fmt.Errorf("SQS per-message-group FIFO throughput is not implemented by this resource handler")
	}
	if p.DeduplicationScope != "" && p.DeduplicationScope != "queue" && p.DeduplicationScope != "messageGroup" {
		return fmt.Errorf("DeduplicationScope must be queue or messageGroup")
	}
	if p.KmsMasterKeyId != "" && p.SqsManagedSseEnabled != nil && bool(*p.SqsManagedSseEnabled) {
		return fmt.Errorf("SSE-KMS and SSE-SQS are mutually exclusive")
	}
	for _, n := range []struct {
		name     string
		value    *cfnMessagingInt
		min, max int64
	}{
		{"DelaySeconds", p.DelaySeconds, 0, 900}, {"MaximumMessageSize", p.MaximumMessageSize, 1024, 1048576}, {"MessageRetentionPeriod", p.MessageRetentionPeriod, 60, 1209600}, {"ReceiveMessageWaitTimeSeconds", p.ReceiveMessageWaitTimeSeconds, 0, 20}, {"VisibilityTimeout", p.VisibilityTimeout, 0, 43200}, {"KmsDataKeyReusePeriodSeconds", p.KmsDataKeyReusePeriodSeconds, 60, 86400},
	} {
		if n.value != nil && (int64(*n.value) < n.min || int64(*n.value) > n.max) {
			return fmt.Errorf("%s must be between %d and %d", n.name, n.min, n.max)
		}
	}
	if p.RedrivePolicy != nil {
		var policy struct {
			DeadLetterTargetArn string          `json:"deadLetterTargetArn"`
			MaxReceiveCount     cfnMessagingInt `json:"maxReceiveCount"`
		}
		if err := cfnMessagingDecode(p.RedrivePolicy, &policy); err != nil {
			return err
		}
		if policy.DeadLetterTargetArn == "" || policy.MaxReceiveCount < 1 || policy.MaxReceiveCount > 1000 {
			return fmt.Errorf("invalid RedrivePolicy")
		}
	}
	if p.RedriveAllowPolicy != nil {
		var policy struct {
			RedrivePermission string   `json:"redrivePermission"`
			SourceQueueArns   []string `json:"sourceQueueArns"`
		}
		if err := cfnMessagingDecode(p.RedriveAllowPolicy, &policy); err != nil {
			return err
		}
	}
	_, err := cfnMessagingTags(cloudformation.ResourceRequest{}, p.Tags)
	return err
}
func (h cfnSQSQueue) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	var old, next cfnSQSQueueProperties
	if err := cfnMessagingDecode(a, &old); err != nil {
		return false, err
	}
	if err := cfnMessagingDecode(b, &next); err != nil {
		return false, err
	}
	changed := old.QueueName != next.QueueName || old.fifo() != next.fifo()
	return cfnMessagingReplacement(old.QueueName != "" && old.QueueName == next.QueueName, changed)
}
func (p cfnSQSQueueProperties) attributes(creating bool) (api.QueueAttributeMap, error) {
	attrs := make(api.QueueAttributeMap)
	for _, n := range []struct {
		key      api.QueueAttributeName
		value    *cfnMessagingInt
		fallback int64
	}{
		{"DelaySeconds", p.DelaySeconds, 0}, {"MaximumMessageSize", p.MaximumMessageSize, 1048576}, {"MessageRetentionPeriod", p.MessageRetentionPeriod, 345600}, {"ReceiveMessageWaitTimeSeconds", p.ReceiveMessageWaitTimeSeconds, 0}, {"VisibilityTimeout", p.VisibilityTimeout, 30}, {"KmsDataKeyReusePeriodSeconds", p.KmsDataKeyReusePeriodSeconds, 300},
	} {
		v := n.fallback
		if n.value != nil {
			v = int64(*n.value)
		}
		attrs[n.key] = api.String(strconv.FormatInt(v, 10))
	}
	attrs["KmsMasterKeyId"] = api.String(p.KmsMasterKeyId)
	managed := p.KmsMasterKeyId == ""
	if p.SqsManagedSseEnabled != nil {
		managed = bool(*p.SqsManagedSseEnabled)
	}
	attrs["SqsManagedSseEnabled"] = api.String(strconv.FormatBool(managed))
	if creating {
		attrs["FifoQueue"] = api.String(strconv.FormatBool(p.fifo()))
	}
	if p.fifo() {
		attrs["ContentBasedDeduplication"] = "false"
		if p.ContentBasedDeduplication != nil {
			attrs["ContentBasedDeduplication"] = api.String(strconv.FormatBool(bool(*p.ContentBasedDeduplication)))
		}
		attrs["DeduplicationScope"] = "queue"
		if p.DeduplicationScope != "" {
			attrs["DeduplicationScope"] = api.String(p.DeduplicationScope)
		}
		attrs["FifoThroughputLimit"] = "perQueue"
	}
	for key, doc := range map[api.QueueAttributeName]map[string]any{"RedrivePolicy": p.RedrivePolicy, "RedriveAllowPolicy": p.RedriveAllowPolicy} {
		attrs[key] = ""
		if doc != nil {
			body, err := cfnMessagingJSON(doc)
			if err != nil {
				return nil, err
			}
			attrs[key] = api.String(body)
		}
	}
	return attrs, nil
}
func cfnSQSNativeTags(tags map[string]string) api.TagMap {
	out := make(api.TagMap, len(tags))
	for k, v := range tags {
		out[api.TagKey(k)] = api.TagValue(v)
	}
	return out
}
func (h cfnSQSQueue) tags(ctx context.Context, url string) (map[string]string, error) {
	out, err := cfnMessagingCall[api.ListQueueTagsOutput](ctx, h.commands, "sqs", "ListQueueTags", &api.ListQueueTagsInput{QueueUrl: new(api.String(url))})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(out.Tags))
	for k, v := range out.Tags {
		tags[string(k)] = string(v)
	}
	return tags, nil
}
func (h cfnSQSQueue) tag(ctx context.Context, url string, tags map[string]string) error {
	return cfnMessagingExec(ctx, h.commands, "sqs", "TagQueue", &api.TagQueueInput{QueueUrl: new(api.String(url)), Tags: cfnSQSNativeTags(tags)})
}
func (h cfnSQSQueue) untag(ctx context.Context, url string, keys []string) error {
	var native api.TagKeyList
	for _, key := range keys {
		native = append(native, api.TagKey(key))
	}
	return cfnMessagingExec(ctx, h.commands, "sqs", "UntagQueue", &api.UntagQueueInput{QueueUrl: new(api.String(url)), TagKeys: native})
}
func (h cfnSQSQueue) result(ctx context.Context, url string) (cloudformation.ResourceResult, error) {
	out, err := cfnMessagingCall[api.GetQueueAttributesOutput](ctx, h.commands, "sqs", "GetQueueAttributes", &api.GetQueueAttributesInput{QueueUrl: new(api.String(url)), AttributeNames: api.AttributeNameList{"QueueArn"}})
	result := cfnMessagingResult(url)
	if err != nil {
		return result, err
	}
	arn := string(out.Attributes["QueueArn"])
	parts := strings.Split(arn, ":")
	if len(parts) != 6 {
		return result, fmt.Errorf("queue owner returned invalid ARN")
	}
	result.Attributes = map[string]any{"Arn": arn, "QueueName": parts[5], "QueueUrl": url}
	return result, nil
}
func (h cfnSQSQueue) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	var p cfnSQSQueueProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := p.QueueName
	if name == "" {
		name = cfnMessagingName(r, 80, p.fifo())
	}
	found, err := cfnMessagingCall[api.GetQueueUrlOutput](ctx, h.commands, "sqs", "GetQueueUrl", &api.GetQueueUrlInput{QueueName: new(api.String(name))})
	if err == nil {
		url := string(*found.QueueUrl)
		tags, err := h.tags(ctx, url)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if err := cfnMessagingOwned(tags, r); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		return h.result(ctx, url)
	}
	if !cfnMessagingMissing(err, "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue") {
		return cloudformation.ResourceResult{}, err
	}
	tags, err := cfnMessagingTags(r, p.Tags)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	attrs, err := p.attributes(true)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnMessagingCall[api.CreateQueueOutput](ctx, h.commands, "sqs", "CreateQueue", &api.CreateQueueInput{QueueName: new(api.String(name)), Attributes: attrs, Tags: cfnSQSNativeTags(tags)})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	url := string(*out.QueueUrl)
	actual, err := h.tags(ctx, url)
	if err != nil {
		return cfnMessagingResult(url), err
	}
	if err := cfnMessagingOwned(actual, r); err != nil {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
	}
	return h.result(ctx, url)
}
func (h cfnSQSQueue) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::SQS::Queue", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
		url, err := h.queueURL(ctx, r)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		r.PhysicalID = url
	}
	result := cfnMessagingResult(r.PhysicalID)
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replace {
		return result, fmt.Errorf("queue update requires replacement")
	}
	var p cfnSQSQueueProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return result, err
	}
	tags, err := h.tags(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	if err := cfnMessagingOwned(tags, r); !r.CloudControl && err != nil {
		return result, err
	}
	attrs, err := p.attributes(false)
	if err != nil {
		return result, err
	}
	if err := cfnMessagingExec(ctx, h.commands, "sqs", "SetQueueAttributes", &api.SetQueueAttributesInput{QueueUrl: new(api.String(r.PhysicalID)), Attributes: attrs}); err != nil {
		return result, err
	}
	next, err := cfnMessagingTags(r, p.Tags)
	if err != nil {
		return result, err
	}
	next = cfnResourceMutationTags(r, tags, next)
	var remove []string
	for k := range tags {
		if !strings.HasPrefix(k, "stackd:cloudformation:") {
			if _, ok := next[k]; !ok {
				remove = append(remove, k)
			}
		}
	}
	if len(remove) > 0 {
		if err := h.untag(ctx, r.PhysicalID, remove); err != nil {
			return result, err
		}
	}
	if len(next) > 0 {
		if err := h.tag(ctx, r.PhysicalID, next); err != nil {
			return result, err
		}
	}
	return h.result(ctx, r.PhysicalID)
}
func (h cfnSQSQueue) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.CloudControl {
		url, err := h.queueURL(ctx, r)
		if err != nil {
			return err
		}
		r.PhysicalID = url
	}
	tags, err := h.tags(ctx, r.PhysicalID)
	if cfnMessagingMissing(err, "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue") {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnMessagingOwned(tags, r); !r.CloudControl && err != nil {
		return err
	}
	return cfnMessagingExec(ctx, h.commands, "sqs", "DeleteQueue", &api.DeleteQueueInput{QueueUrl: new(api.String(r.PhysicalID))})
}
