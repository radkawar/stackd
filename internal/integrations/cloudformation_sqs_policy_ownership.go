package integrations

import (
	"context"
	"fmt"

	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sqs"
)

type cfnSQSPolicyOwnerReader interface {
	CloudFormationQueueClaims(context.Context, string) (sqs.QueueClaims, error)
}

func cfnSQSPolicyOwner(r cloudformation.ResourceRequest) string {
	return cfnMessagingHash("policy\x00" + r.Type + "\x00" + cfnSQSOwner(r))
}

func (h cfnSQSQueuePolicy) privatePolicyOwner(ctx context.Context, queueURL string) (string, error) {
	// Observe the actual URL first: scope, current IAM and resource-policy checks
	// must precede inspection of a same-named queue's private authority.
	if _, err := h.policy(ctx, queueURL); err != nil {
		return "", err
	}
	name, err := queueNameFromURL(queueURL)
	if err != nil {
		return "", err
	}
	provider, exists := h.commands.providers["sqs"]
	if !exists {
		return "", fmt.Errorf("SQS native policy authority is not configured")
	}
	reader, ok := provider.executor.(cfnSQSPolicyOwnerReader)
	if !ok {
		return "", fmt.Errorf("SQS native policy authority is not implemented")
	}
	claims, err := reader.CloudFormationQueueClaims(ctx, name)
	return claims.PolicyOwner, err
}

func (h cfnSQSQueuePolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.StackID == "" || r.LogicalID == "" || r.Token == "" {
		return cloudformation.ResourceResult{}, fmt.Errorf("queue policy recovery requires an exact creation incarnation")
	}
	var properties cfnSQSQueuePolicyProperties
	if err := cfnMessagingDecode(r.Properties, &properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	var admitted cloudformation.ResourceResult
	for _, queueURL := range properties.Queues {
		owner, err := h.privatePolicyOwner(ctx, queueURL)
		if cfnMessagingMissing(err, "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue") {
			continue
		}
		if err != nil {
			return admitted, err
		}
		if owner == cfnSQSPolicyOwner(r) {
			admitted = h.result(r)
		}
	}
	if admitted.PhysicalID != "" {
		return admitted, nil
	}
	return admitted, &awswire.Error{Code: "ResourceNotFoundException", Message: "This exact queue policy incarnation was not admitted.", StatusCode: 404}
}

func (h cfnSQSQueueInlinePolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	var properties cfnSQSQueueInlinePolicyProperties
	if err := cfnMessagingDecode(r.Properties, &properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	queueURL, err := h.queueURL(ctx, r, properties.Queue)
	if cfnMessagingMissing(err, "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue") {
		return cloudformation.ResourceResult{}, &awswire.Error{Code: "ResourceNotFoundException", Message: "This exact queue policy incarnation was not admitted.", StatusCode: 404}
	}
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	owner, err := h.policies().privatePolicyOwner(ctx, queueURL)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if owner != cfnSQSPolicyOwner(r) {
		return cloudformation.ResourceResult{}, &awswire.Error{Code: "ResourceNotFoundException", Message: "This exact queue policy incarnation was not admitted.", StatusCode: 404}
	}
	return cfnMessagingResult(queueURL), nil
}
