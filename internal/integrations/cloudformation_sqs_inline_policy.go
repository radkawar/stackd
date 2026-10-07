package integrations

import (
	"context"
	"errors"
	"fmt"

	"stackd/internal/services/cloudformation"
	sqsservice "stackd/internal/services/sqs"
)

// cfnSQSQueueInlinePolicy owns one native policy slot independently of the queue.
type cfnSQSQueueInlinePolicy struct{ commands StepFunctionsCommands }
type cfnSQSQueueInlinePolicyProperties struct {
	Queue          string
	PolicyDocument cfnStorageDocument
}

func (h cfnSQSQueueInlinePolicy) decode(raw cloudformation.Properties) (cfnSQSQueueInlinePolicyProperties, error) {
	var p cfnSQSQueueInlinePolicyProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return p, err
	}
	if p.Queue == "" {
		return p, fmt.Errorf("property Queue is required")
	}
	_, err := cfnMessagingPolicy(p.PolicyDocument)
	return p, err
}
func (h cfnSQSQueueInlinePolicy) Validate(raw cloudformation.Properties) error {
	_, err := h.decode(raw)
	return err
}
func (h cfnSQSQueueInlinePolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnMessagingChanged(a, b, "Queue"), nil
}
func (h cfnSQSQueueInlinePolicy) policies() cfnSQSQueuePolicy { return cfnSQSQueuePolicy(h) }

// queueURL resolves the registry identifier, which may be a URL, name or ARN,
// through the queue owner in the request account and Region.
func (h cfnSQSQueueInlinePolicy) queueURL(ctx context.Context, r cloudformation.ResourceRequest, queue string) (string, error) {
	r.PhysicalID = queue
	return cfnSQSQueue(h).queueURL(ctx, r)
}
func (h cfnSQSQueueInlinePolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.decode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	url, err := h.queueURL(ctx, r, p.Queue)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	err = h.policies().apply(sqsservice.WithCloudFormationPolicyOwner(ctx, cfnSQSPolicyOwner(r)), r, cfnSQSQueuePolicyProperties{Queues: []string{url}, PolicyDocument: p.PolicyDocument})
	if err == nil {
		return cfnMessagingResult(url), nil
	}
	if admitted, recoveryErr := h.RecoverCreation(ctx, r); admitted.PhysicalID != "" {
		return admitted, err
	} else if !cfnMessagingMissing(recoveryErr, "ResourceNotFoundException") {
		return cloudformation.ResourceResult{}, errors.Join(err, recoveryErr)
	}
	return cloudformation.ResourceResult{}, err
}
func (h cfnSQSQueueInlinePolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::SQS::QueueInlinePolicy", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	result := cfnMessagingResult(r.PhysicalID)
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replace {
		return result, fmt.Errorf("queue inline policy update requires replacement")
	}
	p, err := h.decode(r.Properties)
	if err != nil {
		return result, err
	}
	url, err := h.queueURL(ctx, r, r.PhysicalID)
	if err != nil {
		return result, err
	}
	if r.CloudControl {
		return cfnMessagingResult(url), h.policies().put(ctx, url, mustCFNPolicy(p.PolicyDocument))
	}
	return cfnMessagingResult(url), h.policies().apply(ctx, r, cfnSQSQueuePolicyProperties{Queues: []string{url}, PolicyDocument: p.PolicyDocument})
}

// mustCFNPolicy is called only after decode has validated the same document.
func mustCFNPolicy(document cfnStorageDocument) string {
	text, _ := cfnMessagingPolicy(document)
	return text
}
func (h cfnSQSQueueInlinePolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	queue := r.PhysicalID
	if queue == "" {
		queue, _ = r.Properties["Queue"].(string)
	}
	url, err := h.queueURL(ctx, r, queue)
	if cfnMessagingMissing(err, "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue") {
		if r.CloudControl {
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}
	if r.CloudControl {
		return h.policies().put(ctx, url, "")
	}
	var p cfnSQSQueueInlinePolicyProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return err
	}
	doc, err := cfnMessagingPolicy(p.PolicyDocument)
	if err != nil {
		return err
	}
	return h.policies().remove(ctx, r, url, doc)
}
func (h cfnSQSQueueInlinePolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	url, err := h.queueURL(ctx, r, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if !r.CloudControl {
		owner, err := h.policies().privatePolicyOwner(ctx, url)
		if err != nil {
			return nil, err
		}
		if owner != cfnSQSPolicyOwner(r) {
			return nil, fmt.Errorf("queue policy is not owned by this resource incarnation")
		}
	}
	doc, err := h.policies().policy(ctx, url)
	if err != nil {
		return nil, err
	}
	if doc == "" {
		return nil, cfnStorageNotFound("queue " + url + " has no inline policy")
	}
	var document map[string]any
	if err := cfnStorageJSON(doc, &document); err != nil {
		return nil, err
	}
	return cloudformation.Properties{"Queue": url, "PolicyDocument": document}, nil
}
func (h cfnSQSQueueInlinePolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	queues, err := cfnSQSQueue(h).List(ctx, r)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, queue := range queues {
		url, _ := queue.Properties["QueueUrl"].(string)
		if url == "" {
			continue
		}
		doc, err := h.policies().policy(ctx, url)
		if err != nil {
			return nil, err
		}
		if doc == "" {
			continue
		}
		var document map[string]any
		if err := cfnStorageJSON(doc, &document); err != nil {
			return nil, err
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: url, Properties: cloudformation.Properties{"Queue": url, "PolicyDocument": document}})
	}
	return out, nil
}

var _ cloudformation.ResourceReader = cfnSQSQueueInlinePolicy{}
