package integrations

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sqs"
)

type cfnSQSOwnerReader interface {
	CloudFormationQueueOwner(context.Context, string) (string, error)
}

func cfnSQSOwner(r cloudformation.ResourceRequest) string {
	return cfnMessagingHash(r.StackID + "\x00" + r.LogicalID + "\x00" + r.Token)
}

func cfnSQSContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return sqs.WithCloudFormationOwner(ctx, cfnSQSOwner(r))
}

func (h cfnSQSQueue) owner(ctx context.Context, name string) (string, error) {
	provider, exists := h.commands.providers["sqs"]
	if !exists {
		return "", fmt.Errorf("SQS native creation authority is not configured")
	}
	reader, ok := provider.executor.(cfnSQSOwnerReader)
	if !ok {
		return "", fmt.Errorf("SQS native creation authority is not implemented")
	}
	return reader.CloudFormationQueueOwner(ctx, name)
}

func queueNameFromURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid queue resource identifier")
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) != 2 || parts[1] == "" {
		return "", fmt.Errorf("invalid queue resource identifier")
	}
	return parts[1], nil
}

func (h cfnSQSQueue) owns(ctx context.Context, r cloudformation.ResourceRequest, queueURL string) error {
	name, err := queueNameFromURL(queueURL)
	if err != nil {
		return err
	}
	actual, err := h.owner(ctx, name)
	if err != nil {
		return err
	}
	if actual != cfnSQSOwner(r) {
		return fmt.Errorf("queue is not owned by this resource incarnation")
	}
	return nil
}

func (h cfnSQSQueue) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.StackID == "" || r.LogicalID == "" || r.Token == "" {
		return cloudformation.ResourceResult{}, fmt.Errorf("queue recovery requires an exact creation incarnation")
	}
	var properties cfnSQSQueueProperties
	if err := cfnMessagingDecode(r.Properties, &properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := properties.QueueName
	if name == "" {
		name = cfnMessagingName(r, 80, properties.fifo())
	}
	actual, err := h.owner(ctx, name)
	if cfnMessagingMissing(err, "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue") || err == nil && actual != cfnSQSOwner(r) {
		return cloudformation.ResourceResult{}, &awswire.Error{Code: "ResourceNotFoundException", Message: "This exact queue incarnation was not admitted.", StatusCode: 404}
	}
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = name
	queueURL, err := h.queueURL(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(sqs.WithCloudFormationOwner(ctx, cfnSQSOwner(r)), queueURL)
}
