package integrations

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sns"
)

type cfnSNSTopicPolicy struct{ commands StepFunctionsCommands }
type cfnSNSTopicPolicyProperties struct {
	Topics         []string
	Id             string
	PolicyDocument cfnStorageDocument
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
func cfnSNSPolicyMarker(r cloudformation.ResourceRequest) string {
	kind := r.Type
	if kind == "" {
		kind = "AWS::SNS::TopicPolicy"
	}
	return cfnMessagingMarker(r) + ":" + cfnMessagingHash(kind)
}

func (h cfnSNSTopicPolicy) apply(ctx context.Context, r cloudformation.ResourceRequest, p cfnSNSTopicPolicyProperties) (bool, error) {
	doc, err := cfnMessagingPolicy(p.PolicyDocument)
	if err != nil {
		return false, err
	}
	for _, arn := range p.Topics {
		if err := cfnMessagingScopeARN(r, arn, "sns"); err != nil {
			return false, err
		}
	}
	var previous cfnSNSTopicPolicyProperties
	if r.Type != "AWS::SNS::TopicInlinePolicy" {
		if err := cfnMessagingDecode(r.Previous, &previous); err != nil {
			return false, err
		}
	}
	admitted := false
	for _, arn := range p.Topics {
		kind, id := r.Type, h.result(r).PhysicalID
		if kind == "" {
			kind = "AWS::SNS::TopicPolicy"
		}
		requireOwned := slices.Contains(previous.Topics, arn)
		if kind == "AWS::SNS::TopicInlinePolicy" {
			id = arn
			requireOwned = r.PhysicalID != ""
		}
		_, observation, err := cfnSNSTopic(h).observe(ctx, arn)
		if err != nil {
			return admitted, err
		}
		callCtx := sns.WithCloudFormationPolicyClaim(ctx, sns.CloudFormationPolicyClaim{
			Owner: cfnSNSPolicyMarker(r), Identifier: id, Type: kind, RequireOwned: requireOwned, Direct: r.CloudControl && r.PhysicalID != "", Incarnation: observation.Incarnation,
		})
		if err := cfnSNSTopic(h).set(callCtx, arn, "Policy", doc); err != nil {
			return admitted, err
		}
		admitted = true
	}
	return admitted, nil
}
func (h cfnSNSTopicPolicy) remove(ctx context.Context, r cloudformation.ResourceRequest, arn string) error {
	if err := cfnMessagingScopeARN(r, arn, "sns"); err != nil {
		return err
	}
	topic := cfnSNSTopic(h)
	_, observation, err := topic.observe(ctx, arn)
	if cfnMessagingMissing(err, "ResourceNotFound", "NotFound") {
		if r.CloudControl {
			return cfnSNSPolicyNotFound(arn)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if r.CloudControl {
		return topic.set(ctx, arn, "Policy", cfnSNSTopicDefaultPolicy(arn))
	}
	if observation.PolicyOwnership.Owner == "" {
		return nil
	}
	if observation.PolicyOwnership.Owner != cfnSNSPolicyMarker(r) {
		return fmt.Errorf("refusing to delete another resource's topic policy")
	}
	callCtx := sns.WithCloudFormationPolicyClaim(ctx, sns.CloudFormationPolicyClaim{
		Owner: cfnSNSPolicyMarker(r), Remove: true, RequireOwned: true, Incarnation: observation.Incarnation,
	})
	return topic.set(callCtx, arn, "Policy", cfnSNSTopicDefaultPolicy(arn))
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
	r.CloudControl = false // CREATE must claim even through Cloud Control.
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	var p cfnSNSTopicPolicyProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if admitted, err := h.apply(ctx, r, p); err != nil {
		if admitted {
			return h.result(r), err
		}
		recovered, _ := h.RecoverCreation(ctx, r)
		return recovered, err
	}
	return h.result(r), nil
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
	if _, err := h.apply(ctx, r, next); err != nil {
		return h.result(r), err
	}
	for _, arn := range old.Topics {
		if !slices.Contains(next.Topics, arn) {
			if err := h.remove(ctx, r, arn); err != nil {
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
	for _, arn := range p.Topics {
		if err := h.remove(ctx, r, arn); err != nil {
			return err
		}
	}
	return nil
}
