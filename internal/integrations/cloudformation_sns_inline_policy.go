package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// Both SNS policy resource types claim the same real topic Policy attribute.
// TopicArn is the inline policy's official create-only primary identifier.
type cfnSNSTopicInlinePolicy struct{ commands StepFunctionsCommands }
type cfnSNSTopicInlinePolicyProperties struct {
	TopicArn       string
	PolicyDocument map[string]any
}

func (h cfnSNSTopicInlinePolicy) decode(raw cloudformation.Properties) (cfnSNSTopicInlinePolicyProperties, error) {
	var p cfnSNSTopicInlinePolicyProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return p, err
	}
	if p.TopicArn == "" {
		return p, fmt.Errorf("TopicArn is required")
	}
	_, err := cfnMessagingPolicy(p.PolicyDocument)
	return p, err
}
func (h cfnSNSTopicInlinePolicy) Validate(raw cloudformation.Properties) error {
	_, err := h.decode(raw)
	return err
}
func (h cfnSNSTopicInlinePolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnMessagingChanged(a, b, "TopicArn"), nil
}
func (h cfnSNSTopicInlinePolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false // CREATE never bypasses private native admission.
	p, err := h.decode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.Type = "AWS::SNS::TopicInlinePolicy"
	if _, err := cfnSNSTopicPolicy(h).apply(ctx, r, cfnSNSTopicPolicyProperties{Topics: []string{p.TopicArn}, PolicyDocument: p.PolicyDocument}); err != nil {
		recovered, _ := h.RecoverCreation(ctx, r)
		return recovered, err
	}
	return cfnMessagingResult(p.TopicArn), nil
}
func (h cfnSNSTopicInlinePolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cfnMessagingResult(r.PhysicalID)
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replace {
		return result, fmt.Errorf("topic inline policy update requires replacement")
	}
	p, err := h.decode(r.Properties)
	if err != nil {
		return result, err
	}
	if p.TopicArn != r.PhysicalID {
		return result, fmt.Errorf("TopicArn must match the physical identifier")
	}
	r.Type = "AWS::SNS::TopicInlinePolicy"
	_, err = cfnSNSTopicPolicy(h).apply(ctx, r, cfnSNSTopicPolicyProperties{Topics: []string{p.TopicArn}, PolicyDocument: p.PolicyDocument})
	return result, err
}
func (h cfnSNSTopicInlinePolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	arn := r.PhysicalID
	if arn == "" {
		arn, _ = r.Properties["TopicArn"].(string)
	}
	r.Type = "AWS::SNS::TopicInlinePolicy"
	return cfnSNSTopicPolicy(h).remove(ctx, r, arn)
}
func cfnSNSPolicyNotFound(identifier string) error {
	return &awswire.Error{Code: "NotFoundException", Message: "SNS policy not found: " + identifier, StatusCode: 404}
}
func (h cfnSNSTopicInlinePolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	arn := r.PhysicalID
	if arn == "" {
		arn, _ = r.Properties["TopicArn"].(string)
	}
	if err := cfnMessagingScopeARN(r, arn, "sns"); err != nil {
		return nil, err
	}
	out, observation, err := cfnSNSTopic(h).observe(ctx, arn)
	if cfnMessagingMissing(err, "NotFound", "ResourceNotFound") {
		return nil, cfnSNSPolicyNotFound(arn)
	}
	if err != nil {
		return nil, err
	}
	doc := string(out.Attributes["Policy"])
	if doc == "" || (observation.PolicyOwnership.Identifier == "" && cfnMessagingEqualJSON(doc, cfnSNSTopicDefaultPolicy(arn))) {
		return nil, cfnSNSPolicyNotFound(arn)
	}
	if !r.CloudControl {
		r.Type = "AWS::SNS::TopicInlinePolicy"
		if observation.PolicyOwnership.Owner != cfnSNSPolicyMarker(r) {
			return nil, fmt.Errorf("topic policy is not owned by this resource incarnation")
		}
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(doc), &document); err != nil {
		return nil, err
	}
	return cloudformation.Properties{"TopicArn": arn, "PolicyDocument": document}, nil
}
func cfnSNSListTopicARNs(ctx context.Context, commands StepFunctionsCommands, r cloudformation.ResourceRequest) ([]string, error) {
	var arns []string
	input := &api.ListTopicsInput{}
	seen := make(map[string]bool)
	for {
		out, err := cfnMessagingCall[api.ListTopicsOutput](ctx, commands, "sns", "ListTopics", input)
		if err != nil {
			return nil, err
		}
		for _, topic := range out.Topics {
			if topic.TopicArn == nil {
				continue
			}
			arn := string(*topic.TopicArn)
			if err := cfnMessagingScopeARN(r, arn, "sns"); err != nil {
				return nil, err
			}
			arns = append(arns, arn)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next := string(*out.NextToken)
		if seen[next] {
			return nil, fmt.Errorf("SNS topic pagination repeated a token")
		}
		seen[next] = true
		input.NextToken = out.NextToken
	}
	sort.Strings(arns)
	return arns, nil
}
func (h cfnSNSTopicInlinePolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	arns, err := cfnSNSListTopicARNs(ctx, h.commands, r)
	if err != nil {
		return nil, err
	}
	var resources []cloudformation.ResourceDescription
	for _, arn := range arns {
		request := r
		request.PhysicalID, request.CloudControl = arn, true
		properties, err := h.Read(ctx, request)
		if cfnMessagingMissing(err, "NotFoundException") {
			continue
		}
		if err != nil {
			return nil, err
		}
		resources = append(resources, cloudformation.ResourceDescription{Identifier: arn, Properties: properties})
	}
	return resources, nil
}
func (h cfnSNSTopicInlinePolicy) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnMessagingResult(r.PhysicalID), nil
}

var _ cloudformation.ResourceReader = cfnSNSTopicInlinePolicy{}
var _ cloudformation.ResourceResultReader = cfnSNSTopicInlinePolicy{}
