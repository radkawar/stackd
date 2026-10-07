package integrations

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	"stackd/internal/services/cloudformation"
	"stackd/internal/services/eks"
)

type cfnEKSOwner interface {
	CloudFormationCreation(context.Context, string, string) (string, error)
	CloudFormationOwned(context.Context, string, string, string) error
}

func cfnEKSAuthority(c StepFunctionsCommands) (cfnEKSOwner, error) {
	provider, ok := c.providers["eks"]
	if !ok {
		return nil, fmt.Errorf("EKS native incarnation authority unavailable")
	}
	owner, ok := provider.executor.(cfnEKSOwner)
	if !ok {
		return nil, fmt.Errorf("EKS native incarnation authority unavailable")
	}
	return owner, nil
}
func cfnEKSClaim(r cloudformation.ResourceRequest) (string, error) {
	if r.StackID == "" || r.LogicalID == "" || r.Token == "" {
		return "", fmt.Errorf("EKS deployment incarnation identity is incomplete")
	}
	return cfnNativeComputeClaim(r), nil
}
func cfnEKSRecoveryID(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest) (string, error) {
	claim, err := cfnEKSClaim(r)
	if err != nil {
		return "", err
	}
	owner, err := cfnEKSAuthority(c)
	if err != nil {
		return "", err
	}
	id, err := owner.CloudFormationCreation(ctx, r.Type, claim)
	if errors.Is(err, eks.ErrNotFound) {
		return "", cfnCSNotFound("This exact EKS deployment incarnation")
	}
	return id, err
}
func cfnEKSOwned(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, id string) error {
	if r.CloudControl {
		return nil
	}
	claim, err := cfnEKSClaim(r)
	if err != nil {
		return err
	}
	owner, err := cfnEKSAuthority(c)
	if err != nil {
		return err
	}
	return owner.CloudFormationOwned(ctx, r.Type, claim, id)
}
func cfnEKSContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return eks.WithCloudFormationMutation(ctx, r.Type, cfnNativeComputeClaim(r), r.PhysicalID)
}
func cfnEKSCreateContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return eks.WithCloudFormationCreation(ctx, r.Type, cfnNativeComputeClaim(r))
}
func cfnEKSTags(p map[string]any) (map[string]string, error) {
	out := map[string]string{}
	if p["Tags"] == nil {
		return out, nil
	}
	list, ok := p["Tags"].([]any)
	if !ok {
		return nil, fmt.Errorf("property Tags must be a list")
	}
	for _, item := range list {
		tag, ok := cfnComputeObject(item)
		if !ok {
			return nil, fmt.Errorf("property Tags entries must be objects")
		}
		key, keyOK := tag["Key"].(string)
		value, valueOK := tag["Value"].(string)
		if !keyOK || !valueOK || key == "" {
			return nil, fmt.Errorf("property Tags requires string Key and Value")
		}
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, fmt.Errorf("reserved tag key %s", key)
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate tag key %s", key)
		}
		out[key] = value
	}
	return out, nil
}
func cfnEKSValidate(resourceType string, p cloudformation.Properties) error {
	if err := cloudformation.ValidateResourceProperties(resourceType, p); err != nil {
		return err
	}
	_, err := cfnEKSTags(p)
	return err
}
func cfnEKSResourceTags(r cloudformation.ResourceRequest) map[string]string {
	tags, _ := cfnEKSTags(r.Properties)
	if len(r.Tags) == 0 {
		if len(tags) == 0 {
			return nil
		}
		return tags
	}
	out := maps.Clone(r.Tags)
	maps.Copy(out, tags)
	return out
}
func cfnEKSPublicTags(tags map[string]string) []any {
	out := make([]any, 0, len(tags))
	for _, key := range cfnMessagingKeys(tags) {
		out = append(out, map[string]any{"Key": key, "Value": tags[key]})
	}
	return out
}

func cfnEKSExpectedID(r cloudformation.ResourceRequest) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	cluster := cfnComputeString(r.Properties, "ClusterName")
	switch r.Type {
	case cfnEKSClusterType:
		return cfnComputeName(r, "Name", 100)
	case cfnEKSNodegroupType:
		return cluster + "/" + cfnComputeName(r, "NodegroupName", 63)
	case cfnEKSAddonType:
		return cluster + "|" + cfnComputeString(r.Properties, "AddonName")
	case cfnEKSFargateProfileType:
		return cluster + "|" + cfnComputeName(r, "FargateProfileName", 100)
	case cfnEKSAccessEntryType:
		return cfnComputeString(r.Properties, "PrincipalArn") + "|" + cluster
	}
	return ""
}

func (h cfnEKSCluster) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEKSRecoveryID(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = id
	v, err := h.get(cfnEKSContext(ctx, r), id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSClusterResult(v), nil
}
func (h cfnEKSNodegroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEKSRecoveryID(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = id
	cluster, name, err := cfnEKSNodegroupIdentity(id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(cfnEKSContext(ctx, r), cluster, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSNodegroupResult(v), nil
}
func (h cfnEKSAddon) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEKSRecoveryID(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = id
	cluster, name, err := h.locate(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(cfnEKSContext(ctx, r), cluster, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSAddonResult(v), nil
}
func (h cfnEKSFargateProfile) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEKSRecoveryID(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = id
	cluster, name, err := h.locate(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(cfnEKSContext(ctx, r), cluster, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSFargateResult(v), nil
}
func (h cfnEKSAccessEntry) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEKSRecoveryID(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = id
	cluster, name, err := h.locate(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(cfnEKSContext(ctx, r), cluster, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSAccessResult(v), nil
}
func (h cfnEKSPodIdentity) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEKSRecoveryID(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = id
	v, err := h.describeArn(cfnEKSContext(ctx, r), id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSPodIdentityResult(v), nil
}
