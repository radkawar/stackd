package integrations

import (
	"context"
	"encoding/json"
	"fmt"

	"stackd/internal/services/cloudformation"
)

func (h cfnSNSTopicPolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	arns, err := cfnSNSListTopicARNs(ctx, h.commands, r)
	if err != nil {
		return nil, err
	}
	groups := make(map[string]cloudformation.ResourceDescription)
	for _, arn := range arns {
		out, observation, err := cfnSNSTopic(h).observe(ctx, arn)
		if err != nil {
			return nil, err
		}
		id := observation.PolicyOwnership.Identifier
		if id == "" || observation.PolicyOwnership.Type != "AWS::SNS::TopicPolicy" {
			continue
		}
		if !r.CloudControl && observation.PolicyOwnership.Owner != cfnSNSPolicyMarker(r) {
			continue
		}
		doc := string(out.Attributes["Policy"])
		var document map[string]any
		if err := json.Unmarshal([]byte(doc), &document); err != nil {
			return nil, err
		}
		group, exists := groups[id]
		if !exists {
			group = cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"Id": id, "PolicyDocument": document, "Topics": []string{}}}
		} else {
			first, err := cfnMessagingJSON(group.Properties["PolicyDocument"])
			if err != nil {
				return nil, err
			}
			if !cfnMessagingEqualJSON(first, doc) {
				return nil, fmt.Errorf("topic policy %s has divergent live topic policies", id)
			}
		}
		group.Properties["Topics"] = append(group.Properties["Topics"].([]string), arn)
		groups[id] = group
	}
	ids := cfnMessagingKeys(groups)
	resources := make([]cloudformation.ResourceDescription, 0, len(ids))
	for _, id := range ids {
		resources = append(resources, groups[id])
	}
	return resources, nil
}
func (h cfnSNSTopicPolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	resources, err := h.List(ctx, r)
	if err != nil {
		return nil, err
	}
	for _, resource := range resources {
		if resource.Identifier == r.PhysicalID {
			return resource.Properties, nil
		}
	}
	return nil, cfnSNSPolicyNotFound(r.PhysicalID)
}
func (h cfnSNSTopicPolicy) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	var p cfnSNSTopicPolicyProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := h.result(r)
	for _, arn := range p.Topics {
		if err := cfnMessagingScopeARN(r, arn, "sns"); err != nil {
			return cloudformation.ResourceResult{}, err
		}
		_, observation, err := cfnSNSTopic(h).observe(ctx, arn)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if observation.PolicyOwnership.Identifier != result.PhysicalID || (!r.CloudControl && observation.PolicyOwnership.Owner != cfnSNSPolicyMarker(r)) {
			return cloudformation.ResourceResult{}, cfnSNSPolicyNotFound(result.PhysicalID)
		}
	}
	return result, nil
}

var _ cloudformation.ResourceReader = cfnSNSTopicPolicy{}
var _ cloudformation.ResourceResultReader = cfnSNSTopicPolicy{}
