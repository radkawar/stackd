package integrations

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/services/cloudformation"
)

type cfnSNSTopicPolicy struct{ commands StepFunctionsCommands }
type cfnSNSTopicPolicyProperties struct {
	Topics         []string
	PolicyDocument map[string]any
}

func (h cfnSNSTopicPolicy) Validate(raw cloudformation.Properties) error {
	var p cfnSNSTopicPolicyProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return err
	}
	if err := cfnMessagingUnique(p.Topics, "Topics"); err != nil {
		return err
	}
	_, err := cfnMessagingPolicy(p.PolicyDocument)
	return err
}
func (h cfnSNSTopicPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}

// Removing the managed policy restores SNS's native owner-only default policy;
// SNS does not expose DeleteTopicPolicy or accept an empty policy document.
func cfnSNSTopicDefaultPolicy(arn string) string {
	parts := strings.Split(arn, ":")
	account := parts[4]
	return `{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish"],"Resource":"` + arn + `","Condition":{"StringEquals":{"AWS:SourceOwner":"` + account + `"}}}]}`
}
func (h cfnSNSTopicPolicy) policy(ctx context.Context, arn string) (string, error) {
	out, err := cfnMessagingCall[api.GetTopicAttributesOutput](ctx, h.commands, "sns", "GetTopicAttributes", &api.GetTopicAttributesInput{TopicArn: new(api.TopicARN(arn))})
	if err != nil {
		return "", err
	}
	return string(out.Attributes["Policy"]), nil
}
func (h cfnSNSTopicPolicy) apply(ctx context.Context, r cloudformation.ResourceRequest, p cfnSNSTopicPolicyProperties) error {
	doc, err := cfnMessagingPolicy(p.PolicyDocument)
	if err != nil {
		return err
	}
	topic := cfnSNSTopic(h)
	for _, arn := range p.Topics {
		if err := cfnMessagingScopeARN(r, arn, "sns"); err != nil {
			return err
		}
		tags, err := topic.tags(ctx, arn)
		if err != nil {
			return err
		}
		marker := tags[cfnMessagingPolicyTag]
		if marker != "" && marker != cfnMessagingMarker(r) {
			return fmt.Errorf("topic policy is owned by another resource")
		}
		current, err := h.policy(ctx, arn)
		if err != nil {
			return err
		}
		if marker == "" && !cfnMessagingEqualJSON(current, cfnSNSTopicDefaultPolicy(arn)) {
			return fmt.Errorf("topic already has an unrelated policy")
		}
		if marker == "" {
			if err := topic.tag(ctx, arn, map[string]string{cfnMessagingPolicyTag: cfnMessagingMarker(r)}); err != nil {
				return err
			}
		}
		if err := topic.set(ctx, arn, "Policy", doc); err != nil {
			if marker == "" {
				return errors.Join(err, topic.untag(ctx, arn, []string{cfnMessagingPolicyTag}))
			}
			return err
		}
	}
	return nil
}
func (h cfnSNSTopicPolicy) remove(ctx context.Context, r cloudformation.ResourceRequest, arn, doc string) error {
	if err := cfnMessagingScopeARN(r, arn, "sns"); err != nil {
		return err
	}
	topic := cfnSNSTopic(h)
	tags, err := topic.tags(ctx, arn)
	if cfnMessagingMissing(err, "ResourceNotFound", "NotFound") {
		return nil
	}
	if err != nil {
		return err
	}
	if tags[cfnMessagingPolicyTag] == "" {
		return nil
	}
	if tags[cfnMessagingPolicyTag] != cfnMessagingMarker(r) {
		return fmt.Errorf("refusing to delete another resource's topic policy")
	}
	current, err := h.policy(ctx, arn)
	if err != nil {
		return err
	}
	baseline := cfnSNSTopicDefaultPolicy(arn)
	if !cfnMessagingEqualJSON(current, baseline) {
		if !cfnMessagingEqualJSON(current, doc) {
			return fmt.Errorf("topic policy changed outside this CloudFormation resource")
		}
		if err := topic.set(ctx, arn, "Policy", baseline); err != nil {
			return err
		}
	}
	return topic.untag(ctx, arn, []string{cfnMessagingPolicyTag})
}
func (h cfnSNSTopicPolicy) result(r cloudformation.ResourceRequest) cloudformation.ResourceResult {
	id := r.PhysicalID
	if id == "" {
		id = "topic-policy-" + cfnMessagingHash(r.StackID+r.LogicalID+r.Token)
	}
	out := cfnMessagingResult(id)
	out.Attributes = map[string]any{"Id": id}
	return out
}
func (h cfnSNSTopicPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	var p cfnSNSTopicPolicyProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(r), h.apply(ctx, r, p)
}
func (h cfnSNSTopicPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return h.result(r), err
	}
	var old, next cfnSNSTopicPolicyProperties
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
	for _, arn := range old.Topics {
		if !slices.Contains(next.Topics, arn) {
			if err := h.remove(ctx, r, arn, doc); err != nil {
				return h.result(r), err
			}
		}
	}
	return h.result(r), nil
}
func (h cfnSNSTopicPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	var p cfnSNSTopicPolicyProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return err
	}
	doc, err := cfnMessagingPolicy(p.PolicyDocument)
	if err != nil {
		return err
	}
	for _, arn := range p.Topics {
		if err := h.remove(ctx, r, arn, doc); err != nil {
			return err
		}
	}
	return nil
}
