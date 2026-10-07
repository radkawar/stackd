package integrations

import (
	"context"
	"fmt"

	"stackd/internal/services/cloudformation"
)

func (h cfnSNSTopicPolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	var p cfnSNSTopicPolicyProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := h.result(r)
	admitted := false
	var observationError error
	for _, arn := range p.Topics {
		if err := cfnMessagingScopeARN(r, arn, "sns"); err != nil {
			return cloudformation.ResourceResult{}, err
		}
		out, observed, err := cfnSNSTopic(h).observe(ctx, arn)
		if cfnMessagingMissing(err, "NotFound", "ResourceNotFound") {
			continue
		}
		if err != nil {
			observationError = err
			continue
		}
		if observed.PolicyOwnership.Owner == cfnSNSPolicyMarker(r) && observed.PolicyOwnership.Identifier == result.PhysicalID && observed.PolicyOwnership.Type == "AWS::SNS::TopicPolicy" {
			admitted = true
		} else if observed.PolicyOwnership.Owner != "" || observed.PolicyOwnership.Identifier != "" || !cfnMessagingEqualJSON(string(out.Attributes["Policy"]), cfnSNSTopicDefaultPolicy(arn)) {
			observationError = fmt.Errorf("topic policy is not owned by this resource incarnation")
		}
	}
	if admitted {
		return result, observationError
	}
	if observationError != nil {
		return cloudformation.ResourceResult{}, observationError
	}
	return cloudformation.ResourceResult{}, cfnSNSPolicyNotFound(result.PhysicalID)
}
func (h cfnSNSTopicInlinePolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.decode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnMessagingScopeARN(r, p.TopicArn, "sns"); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, observed, err := cfnSNSTopic(h).observe(ctx, p.TopicArn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.Type = "AWS::SNS::TopicInlinePolicy"
	if observed.PolicyOwnership.Owner != cfnSNSPolicyMarker(r) || observed.PolicyOwnership.Identifier != p.TopicArn || observed.PolicyOwnership.Type != r.Type {
		if observed.PolicyOwnership.Identifier != "" || !cfnMessagingEqualJSON(string(out.Attributes["Policy"]), cfnSNSTopicDefaultPolicy(p.TopicArn)) {
			return cloudformation.ResourceResult{}, fmt.Errorf("topic policy is not owned by this resource incarnation")
		}
		return cloudformation.ResourceResult{}, cfnSNSPolicyNotFound(p.TopicArn)
	}
	return cfnMessagingResult(p.TopicArn), nil
}

var _ cloudformation.ResourceCreationRecoverer = cfnSNSTopicPolicy{}
var _ cloudformation.ResourceCreationRecoverer = cfnSNSTopicInlinePolicy{}
