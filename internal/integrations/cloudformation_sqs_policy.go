package integrations

import (
	"context"
	"errors"
	"fmt"
	"slices"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/services/cloudformation"
	sqsservice "stackd/internal/services/sqs"
)

type cfnSQSQueuePolicy struct{ commands StepFunctionsCommands }
type cfnSQSQueuePolicyProperties struct {
	Queues         []string
	PolicyDocument cfnStorageDocument
}

func (h cfnSQSQueuePolicy) Validate(raw cloudformation.Properties) error {
	var p cfnSQSQueuePolicyProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return err
	}
	if err := cfnMessagingUnique(p.Queues, "Queues"); err != nil {
		return err
	}
	_, err := cfnMessagingPolicy(p.PolicyDocument)
	return err
}
func (h cfnSQSQueuePolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func (h cfnSQSQueuePolicy) policy(ctx context.Context, url string) (string, error) {
	out, err := cfnMessagingCall[api.GetQueueAttributesOutput](ctx, h.commands, "sqs", "GetQueueAttributes", &api.GetQueueAttributesInput{QueueUrl: new(api.String(url)), AttributeNames: api.AttributeNameList{"Policy"}})
	if err != nil {
		return "", err
	}
	return string(out.Attributes["Policy"]), nil
}
func (h cfnSQSQueuePolicy) put(ctx context.Context, url, doc string) error {
	return cfnMessagingExec(ctx, h.commands, "sqs", "SetQueueAttributes", &api.SetQueueAttributesInput{QueueUrl: new(api.String(url)), Attributes: api.QueueAttributeMap{"Policy": api.String(doc)}})
}
func (h cfnSQSQueuePolicy) apply(ctx context.Context, r cloudformation.ResourceRequest, p cfnSQSQueuePolicyProperties) error {
	doc, err := cfnMessagingPolicy(p.PolicyDocument)
	if err != nil {
		return err
	}
	if !r.CloudControl {
		ctx = sqsservice.WithCloudFormationPolicyOwner(ctx, cfnSQSPolicyOwner(r))
	}
	for _, url := range p.Queues {
		if err := h.put(ctx, url, doc); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnSQSQueuePolicy) remove(ctx context.Context, r cloudformation.ResourceRequest, url, doc string) error {
	if !r.CloudControl {
		owner, err := h.privatePolicyOwner(ctx, url)
		if cfnMessagingMissing(err, "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue") {
			return nil
		}
		if err != nil {
			return err
		}
		if owner == "" {
			return nil
		}
		if owner != cfnSQSPolicyOwner(r) {
			return fmt.Errorf("refusing to delete another resource's queue policy")
		}
		ctx = sqsservice.WithCloudFormationPolicyOwner(ctx, owner)
	}
	return h.put(ctx, url, "")
}
func (h cfnSQSQueuePolicy) result(r cloudformation.ResourceRequest) cloudformation.ResourceResult {
	id := r.PhysicalID
	if id == "" {
		id = "queue-policy-" + cfnMessagingHash(r.StackID+r.LogicalID+r.Token)
	}
	out := cfnMessagingResult(id)
	out.Attributes = map[string]any{"Id": id}
	return out
}
func (h cfnSQSQueuePolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	var p cfnSQSQueuePolicyProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	err := h.apply(sqsservice.WithCloudFormationPolicyOwner(ctx, cfnSQSPolicyOwner(r)), r, p)
	if err == nil {
		return h.result(r), nil
	}
	if admitted, recoveryErr := h.RecoverCreation(ctx, r); admitted.PhysicalID != "" {
		return admitted, err
	} else if !cfnMessagingMissing(recoveryErr, "ResourceNotFoundException") {
		return cloudformation.ResourceResult{}, errors.Join(err, recoveryErr)
	}
	return cloudformation.ResourceResult{}, err
}
func (h cfnSQSQueuePolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return h.result(r), err
	}
	var old, next cfnSQSQueuePolicyProperties
	if err := cfnMessagingDecode(r.Previous, &old); err != nil {
		return h.result(r), err
	}
	if err := cfnMessagingDecode(r.Properties, &next); err != nil {
		return h.result(r), err
	}
	if err := h.apply(ctx, r, next); err != nil {
		return h.result(r), err
	}
	doc, err := cfnMessagingPolicy(old.PolicyDocument)
	if err != nil {
		return h.result(r), err
	}
	for _, url := range old.Queues {
		if !slices.Contains(next.Queues, url) {
			if err := h.remove(ctx, r, url, doc); err != nil {
				return h.result(r), err
			}
		}
	}
	return h.result(r), nil
}
func (h cfnSQSQueuePolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	var p cfnSQSQueuePolicyProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return err
	}
	doc, err := cfnMessagingPolicy(p.PolicyDocument)
	if err != nil {
		return err
	}
	for _, url := range p.Queues {
		if err := h.remove(ctx, r, url, doc); err != nil {
			return err
		}
	}
	return nil
}
