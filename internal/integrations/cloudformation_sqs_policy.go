package integrations

import (
	"context"
	"errors"
	"fmt"
	"slices"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/services/cloudformation"
)

type cfnSQSQueuePolicy struct{ commands StepFunctionsCommands }
type cfnSQSQueuePolicyProperties struct {
	Queues         []string
	PolicyDocument map[string]any
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
	queue := cfnSQSQueue(h)
	for _, url := range p.Queues {
		tags, err := queue.tags(ctx, url)
		if err != nil {
			return err
		}
		marker := tags[cfnMessagingPolicyTag]
		if marker != "" && marker != cfnMessagingMarker(r) {
			return fmt.Errorf("queue policy is owned by another resource")
		}
		current, err := h.policy(ctx, url)
		if err != nil {
			return err
		}
		if marker == "" && current != "" {
			return fmt.Errorf("queue already has an unrelated policy")
		}
		if marker == "" {
			if err := queue.tag(ctx, url, map[string]string{cfnMessagingPolicyTag: cfnMessagingMarker(r)}); err != nil {
				return err
			}
		}
		if err := h.put(ctx, url, doc); err != nil {
			if marker == "" {
				return errors.Join(err, queue.untag(ctx, url, []string{cfnMessagingPolicyTag}))
			}
			return err
		}
	}
	return nil
}
func (h cfnSQSQueuePolicy) remove(ctx context.Context, r cloudformation.ResourceRequest, url, doc string) error {
	queue := cfnSQSQueue(h)
	tags, err := queue.tags(ctx, url)
	if cfnMessagingMissing(err, "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue") {
		return nil
	}
	if err != nil {
		return err
	}
	if tags[cfnMessagingPolicyTag] == "" {
		return nil
	}
	if tags[cfnMessagingPolicyTag] != cfnMessagingMarker(r) {
		return fmt.Errorf("refusing to delete another resource's queue policy")
	}
	current, err := h.policy(ctx, url)
	if err != nil {
		return err
	}
	if current != "" && !cfnMessagingEqualJSON(current, doc) {
		return fmt.Errorf("queue policy changed outside this CloudFormation resource")
	}
	if current != "" {
		if err := h.put(ctx, url, ""); err != nil {
			return err
		}
	}
	return queue.untag(ctx, url, []string{cfnMessagingPolicyTag})
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
	return h.result(r), h.apply(ctx, r, p)
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
