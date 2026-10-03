package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/services/cloudformation"
)

func (h cfnSQSQueue) queueURL(ctx context.Context, r cloudformation.ResourceRequest) (string, error) {
	name := r.PhysicalID
	if strings.HasPrefix(name, "arn:") {
		if err := cfnMessagingScopeARN(r, name, "sqs"); err != nil {
			return "", err
		}
		name = strings.SplitN(name, ":", 6)[5]
	} else if strings.Contains(name, "://") {
		parsed, err := url.Parse(name)
		if err != nil {
			return "", fmt.Errorf("invalid queue identifier: %w", err)
		}
		host := parsed.Hostname()
		if strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn") {
			suffix := "amazonaws.com"
			if r.Scope.Partition == "aws-cn" {
				suffix = "amazonaws.com.cn"
			}
			if host != "sqs."+r.Scope.Region+"."+suffix {
				return "", fmt.Errorf("queue identifier must belong to the request region and partition")
			}
		}
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) != 2 || parts[0] != r.Scope.Account {
			return "", fmt.Errorf("queue identifier must belong to the request account")
		}
		name = parts[1]
	}
	out, err := cfnMessagingCall[api.GetQueueUrlOutput](ctx, h.commands, "sqs", "GetQueueUrl", &api.GetQueueUrlInput{QueueName: new(api.String(name)), QueueOwnerAWSAccountId: new(api.String(r.Scope.Account))})
	if err != nil {
		return "", err
	}
	return cfnComputeValue(out.QueueUrl), nil
}

func (h cfnSQSQueue) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	queueURL, err := h.queueURL(ctx, r)
	if err != nil {
		return nil, err
	}
	out, err := cfnMessagingCall[api.GetQueueAttributesOutput](ctx, h.commands, "sqs", "GetQueueAttributes", &api.GetQueueAttributesInput{QueueUrl: new(api.String(queueURL)), AttributeNames: api.AttributeNameList{"All"}})
	if err != nil {
		return nil, err
	}
	tags, err := h.tags(ctx, queueURL)
	if err != nil {
		return nil, err
	}
	arn := string(out.Attributes["QueueArn"])
	parts := strings.Split(arn, ":")
	if len(parts) != 6 {
		return nil, fmt.Errorf("queue owner returned invalid ARN")
	}
	p := cloudformation.Properties{"QueueName": parts[5], "QueueUrl": queueURL, "Arn": arn, "Tags": cfnResourcePublicTags(tags)}
	for _, key := range []string{"DelaySeconds", "MaximumMessageSize", "MessageRetentionPeriod", "ReceiveMessageWaitTimeSeconds", "VisibilityTimeout", "KmsDataKeyReusePeriodSeconds"} {
		if value := string(out.Attributes[api.QueueAttributeName(key)]); value != "" {
			number, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("queue owner returned invalid %s: %w", key, err)
			}
			p[key] = number
		}
	}
	for _, key := range []string{"FifoQueue", "ContentBasedDeduplication", "SqsManagedSseEnabled"} {
		if value := string(out.Attributes[api.QueueAttributeName(key)]); value != "" {
			flag, err := strconv.ParseBool(value)
			if err != nil {
				return nil, fmt.Errorf("queue owner returned invalid %s: %w", key, err)
			}
			p[key] = flag
		}
	}
	for _, key := range []string{"KmsMasterKeyId", "DeduplicationScope", "FifoThroughputLimit"} {
		if value := string(out.Attributes[api.QueueAttributeName(key)]); value != "" {
			p[key] = value
		}
	}
	for _, key := range []string{"RedrivePolicy", "RedriveAllowPolicy"} {
		if value := string(out.Attributes[api.QueueAttributeName(key)]); value != "" {
			var policy map[string]any
			if err := json.Unmarshal([]byte(value), &policy); err != nil {
				return nil, fmt.Errorf("queue owner returned invalid %s: %w", key, err)
			}
			p[key] = policy
		}
	}
	return p, nil
}

func (h cfnSQSQueue) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var resources []cloudformation.ResourceDescription
	input := &api.ListQueuesInput{MaxResults: new(api.BoxedInteger(1000))}
	for {
		out, err := cfnMessagingCall[api.ListQueuesOutput](ctx, h.commands, "sqs", "ListQueues", input)
		if err != nil {
			return nil, err
		}
		for _, queueURL := range out.QueueUrls {
			r.PhysicalID = string(queueURL)
			properties, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			resources = append(resources, cloudformation.ResourceDescription{Identifier: string(queueURL), Properties: properties})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return resources, nil
		}
		input.NextToken = out.NextToken
	}
}
