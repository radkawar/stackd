package integrations

import (
	"context"
	"errors"
	"fmt"
	"sort"

	api "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/kms"
)

// CloudFormationKMSHandlers delegates cryptographic resource effects to KMS.
func CloudFormationKMSHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{"AWS::KMS::Key": cfnKMSKey{commands}, "AWS::KMS::Alias": cfnKMSAlias{commands}, "AWS::KMS::ReplicaKey": cfnKMSReplicaKey{commands}}
}

type cfnKMSKey struct{ commands StepFunctionsCommands }
type cfnKMSAlias struct{ commands StepFunctionsCommands }

func cfnKMSAbsent(err error) error {
	var wire *awswire.Error
	if errors.As(err, &wire) && wire.Code == "NotFoundException" {
		return nil
	}
	return err
}

func (h cfnKMSKey) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "KeyPolicy", "Description", "Enabled", "EnableKeyRotation", "RotationPeriodInDays", "PendingWindowInDays", "KeySpec", "KeyUsage", "Origin", "MultiRegion", "BypassPolicyLockoutSafetyCheck", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Description", "KeySpec", "KeyUsage", "Origin"); err != nil {
		return err
	}
	if p["KeyPolicy"] != nil {
		if _, err := cfnKMSPolicy(p["KeyPolicy"]); err != nil {
			return err
		}
	}
	for _, key := range []string{"Enabled", "EnableKeyRotation", "MultiRegion", "BypassPolicyLockoutSafetyCheck"} {
		if v, ok := p[key]; ok {
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("%s must be a boolean", key)
			}
		}
	}
	if _, err := cfnKMSPendingWindow(p); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnKMSKey) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	if cfnComputeDefault(a, "KeySpec", "SYMMETRIC_DEFAULT") != cfnComputeDefault(b, "KeySpec", "SYMMETRIC_DEFAULT") ||
		cfnComputeDefault(a, "KeyUsage", "ENCRYPT_DECRYPT") != cfnComputeDefault(b, "KeyUsage", "ENCRYPT_DECRYPT") ||
		cfnComputeDefault(a, "Origin", "AWS_KMS") != cfnComputeDefault(b, "Origin", "AWS_KMS") ||
		cfnComputeDefault(a, "MultiRegion", false) != cfnComputeDefault(b, "MultiRegion", false) {
		return false, fmt.Errorf("KMS key specification, usage, origin and multi-region mode cannot be updated")
	}
	return false, nil
}
func (h cfnKMSKey) tags(ctx context.Context, id string) (map[string]string, error) {
	tags := map[string]string{}
	input := map[string]any{"KeyId": id}
	for {
		out, err := cfnComputeCall[api.ListResourceTagsOutput](ctx, h.commands, "kms", "ListResourceTags", input)
		if err != nil {
			return nil, err
		}
		for _, tag := range out.Tags {
			tags[cfnComputeValue(tag.TagKey)] = cfnComputeValue(tag.TagValue)
		}
		marker := cfnComputeValue(out.NextMarker)
		if marker == "" {
			return tags, nil
		}
		input["Marker"] = marker
	}
}
func cfnKMSTags(tags map[string]string) []map[string]string {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]map[string]string, 0, len(tags))
	for _, key := range keys {
		out = append(out, map[string]string{"TagKey": key, "TagValue": tags[key]})
	}
	return out
}
func (h cfnKMSKey) result(ctx context.Context, id string) (cloudformation.ResourceResult, error) {
	out, err := cfnComputeCall[api.DescribeKeyOutput](ctx, h.commands, "kms", "DescribeKey", map[string]any{"KeyId": id})
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: id, Ref: id}, err
	}
	if cfnKMSPendingDeletion(out.KeyMetadata) {
		return cloudformation.ResourceResult{PhysicalID: id, Ref: id}, &awswire.Error{Code: "NotFoundException", Message: "The KMS key is scheduled for deletion", StatusCode: 400}
	}
	return cfnKMSMetadataResult(out.KeyMetadata), nil
}
func (h cfnKMSKey) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnKMSKeyCreationContext(ctx, r)
	input := cfnComputeCopy(r.Properties, "Description", "KeySpec", "KeyUsage", "Origin", "MultiRegion", "BypassPolicyLockoutSafetyCheck")
	var err error
	if r.Properties["KeyPolicy"] != nil {
		input["Policy"], err = cfnComputeDocument(r.Properties["KeyPolicy"])
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	input["Tags"] = cfnKMSTags(cfnResourceTags(r))
	out, err := cfnComputeCall[api.CreateKeyOutput](ctx, h.commands, "kms", "CreateKey", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = cfnComputeValue(out.KeyMetadata.KeyId)
	result, err := h.result(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	r.Previous = nil
	return result, h.configure(ctx, r)
}
func (h cfnKMSKey) configure(ctx context.Context, r cloudformation.ResourceRequest) error {
	id := r.PhysicalID
	if r.Properties["KeyPolicy"] != nil {
		policy, err := cfnComputeDocument(r.Properties["KeyPolicy"])
		if err != nil {
			return err
		}
		input := map[string]any{"KeyId": id, "PolicyName": "default", "Policy": policy}
		if value, ok := r.Properties["BypassPolicyLockoutSafetyCheck"]; ok {
			input["BypassPolicyLockoutSafetyCheck"] = value
		}
		if err = cfnComputeRun(ctx, h.commands, "kms", "PutKeyPolicy", input); err != nil {
			return err
		}
	}
	if value := cfnComputeDefault(r.Properties, "Enabled", true); cfnComputeString(r.Properties, "Origin") != "EXTERNAL" && value != cfnComputeDefault(r.Previous, "Enabled", true) {
		action := "DisableKey"
		if value == true {
			action = "EnableKey"
		}
		if err := cfnComputeRun(ctx, h.commands, "kms", action, map[string]any{"KeyId": id}); err != nil {
			return err
		}
	}
	if value, ok := r.Properties["EnableKeyRotation"]; ok {
		action := "DisableKeyRotation"
		input := map[string]any{"KeyId": id}
		if value == true {
			action = "EnableKeyRotation"
			if period, ok := r.Properties["RotationPeriodInDays"]; ok {
				input["RotationPeriodInDays"] = period
			}
		}
		if err := cfnComputeRun(ctx, h.commands, "kms", action, input); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnKMSKey) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if _, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnKMSKeyContext(ctx, r)
	if _, err := cfnKMSIdentifier(ctx, r.PhysicalID); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	current, err := h.tags(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result, err := h.result(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	if err = h.configure(ctx, r); err != nil {
		return result, err
	}
	if err = cfnComputeRun(ctx, h.commands, "kms", "UpdateKeyDescription", map[string]any{"KeyId": r.PhysicalID, "Description": cfnComputeString(r.Properties, "Description")}); err != nil {
		return result, err
	}
	desired := cfnResourceTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err = cfnComputeRun(ctx, h.commands, "kms", "UntagResource", map[string]any{"KeyId": r.PhysicalID, "TagKeys": removed}); err != nil {
			return result, err
		}
	}
	return result, cfnComputeRun(ctx, h.commands, "kms", "TagResource", map[string]any{"KeyId": r.PhysicalID, "Tags": cfnKMSTags(desired)})
}
func (h cfnKMSKey) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := h.ValidateDeletionPolicy(r.DeletionPolicy); err != nil {
		return err
	}
	ctx = cfnKMSKeyContext(ctx, r)
	if _, err := cfnKMSIdentifier(ctx, r.PhysicalID); err != nil {
		return err
	}
	out, err := cfnComputeCall[api.DescribeKeyOutput](ctx, h.commands, "kms", "DescribeKey", map[string]any{"KeyId": r.PhysicalID})
	if err != nil {
		return cfnKMSAbsent(err)
	}
	if state := cfnComputeValue(out.KeyMetadata.KeyState); state == "PendingDeletion" || state == "PendingReplicaDeletion" {
		return nil
	}
	return cfnComputeRun(ctx, h.commands, "kms", "ScheduleKeyDeletion", map[string]any{"KeyId": r.PhysicalID, "PendingWindowInDays": cfnComputeDefault(r.Properties, "PendingWindowInDays", 30)})
}
func (h cfnKMSAlias) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "AliasName", "TargetKeyId"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "AliasName", "TargetKeyId"); err != nil {
		return err
	}
	return cfnComputeRequired(p, "AliasName", "TargetKeyId")
}
func (h cfnKMSAlias) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "AliasName"), h.Validate(b)
}
func (h cfnKMSAlias) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(r.Properties, "AliasName")
	ctx = kms.WithAliasOwner(ctx, kms.AliasOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
	err := cfnComputeRun(ctx, h.commands, "kms", "CreateAlias", cfnComputeCopy(r.Properties, "AliasName", "TargetKeyId"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name}, nil
}
func (h cfnKMSAlias) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnKMSAliasContext(ctx, r)
	err := cfnComputeRun(ctx, h.commands, "kms", "UpdateAlias", map[string]any{"AliasName": r.PhysicalID, "TargetKeyId": r.Properties["TargetKeyId"]})
	return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}, err
}
func (h cfnKMSAlias) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnKMSAliasContext(ctx, r)
	return cfnKMSAbsent(cfnComputeRun(ctx, h.commands, "kms", "DeleteAlias", map[string]any{"AliasName": r.PhysicalID}))
}

func cfnKMSAliasContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return kms.WithAliasOwner(ctx, kms.AliasOwner{
		StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token,
	})
}
