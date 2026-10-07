package integrations

import (
	"context"
	"errors"
	"fmt"

	api "stackd/internal/awsapi/iam"
	iamowner "stackd/internal/services/iam"

	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// An authorized native observer's private-owner mismatch proves that the live
// row is not this creation. It must never be returned as an admitted identity.
func cfnIAMRecoveryError(err error) error {
	var native *awswire.Error
	if errors.As(err, &native) && native.Code == "CloudFormationOwnershipConflict" {
		return cfnIAMNotFound()
	}
	return err
}

func cfnIAMCreationFailure(ctx context.Context, r cloudformation.ResourceRequest, h cloudformation.ResourceCreationRecoverer, cause error) (cloudformation.ResourceResult, error) {
	result, err := h.RecoverCreation(ctx, r)
	if err == nil {
		return result, cause
	}
	if cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, cause
	}
	return result, errors.Join(cause, err)
}

func (h cfnIAMRole) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	role, err := h.owned(ctx, r, cfnComputeName(r, "RoleName", 64))
	if err != nil {
		return cloudformation.ResourceResult{}, cfnIAMRecoveryError(err)
	}
	return cfnIAMRoleResult(role), nil
}
func (h cfnIAMUser) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	user, err := h.owned(ctx, r, cfnComputeName(r, "UserName", 64))
	if err != nil {
		return cloudformation.ResourceResult{}, cfnIAMRecoveryError(err)
	}
	return cfnIAMNamedResult(cfnComputeValue(user.UserName), cfnComputeValue(user.Arn)), nil
}
func (h cfnIAMGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	group, err := h.owned(ctx, r, cfnComputeName(r, "GroupName", 128))
	if err != nil {
		return cloudformation.ResourceResult{}, cfnIAMRecoveryError(err)
	}
	return cfnIAMNamedResult(cfnComputeValue(group.GroupName), cfnComputeValue(group.Arn)), nil
}
func (h cfnIAMManagedPolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	policy, err := h.owned(ctx, r, cfnIAMManagedARN(r))
	if err != nil {
		return cloudformation.ResourceResult{}, cfnIAMRecoveryError(err)
	}
	return cfnIAMManagedResult(policy), nil
}
func (h cfnIAMInstanceProfile) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	profile, err := h.owned(ctx, r, cfnComputeName(r, "InstanceProfileName", 128))
	if err != nil {
		return cloudformation.ResourceResult{}, cfnIAMRecoveryError(err)
	}
	return cfnIAMNamedResult(cfnComputeValue(profile.InstanceProfileName), cfnComputeValue(profile.Arn)), nil
}
func (h cfnIAMOIDC) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	arn, err := cfnIAMOIDCARN(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if _, err = h.owned(ctx, r, arn); err != nil {
		return cloudformation.ResourceResult{}, cfnIAMRecoveryError(err)
	}
	return cfnIAMOIDCResult(arn), nil
}
func (h cfnIAMSAML) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	arn := cfnIAMSAMLARN(r)
	provider, err := h.owned(ctx, r, arn)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnIAMRecoveryError(err)
	}
	return cfnIAMSAMLResult(arn, cfnComputeValue(provider.SAMLProviderUUID)), nil
}
func (h cfnIAMMFA) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	serial := cfnIAMMFASerial(r)
	if _, err := h.owned(ctx, r, serial); err != nil {
		return cloudformation.ResourceResult{}, cfnIAMRecoveryError(err)
	}
	return cfnIAMMFAResult(serial), nil
}
func (h cfnIAMServerCertificate) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	certificate, err := h.owned(ctx, r, cfnComputeName(r, "ServerCertificateName", 128))
	if err != nil {
		return cloudformation.ResourceResult{}, cfnIAMRecoveryError(err)
	}
	return cfnIAMServerCertificateResult(certificate), nil
}

func (h cfnIAMAccessKey) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	secret := ""
	owner := iamowner.CloudFormationContext{Owner: cfnIAMPolicyOwner(r), SecretResult: &secret}
	input := map[string]any{"UserName": cfnComputeString(r.Properties, "UserName")}
	var result cloudformation.ResourceResult
	for {
		out, err := cfnComputeCall[api.ListAccessKeysOutput](iamowner.WithCloudFormationContext(ctx, owner), h.commands, "iam", "ListAccessKeys", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		for _, key := range out.AccessKeyMetadata {
			id := cfnComputeValue(key.AccessKeyId)
			if r.PhysicalID != "" && r.PhysicalID != id {
				continue
			}
			if result.PhysicalID != "" {
				return cloudformation.ResourceResult{}, fmt.Errorf("ambiguous private access-key incarnation")
			}
			result = cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "SecretAccessKey": secret}}
		}
		marker := cfnComputeValue(out.Marker)
		if marker == "" {
			break
		}
		input["Marker"] = marker
	}
	if result.PhysicalID == "" {
		return result, cfnIAMNotFound()
	}
	return result, nil
}

func (h cfnIAMServiceLinked) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if r.PhysicalID != "" {
		role, err := h.owned(ctx, r, nil)
		if err != nil {
			return cloudformation.ResourceResult{}, cfnIAMRecoveryError(err)
		}
		return cfnIAMServiceLinkedResult(role), nil
	}
	input := map[string]any{"PathPrefix": "/aws-service-role/"}
	var result cloudformation.ResourceResult
	for {
		out, err := cfnComputeCall[api.ListRolesOutput](ctx, h.commands, "iam", "ListRoles", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		for _, candidate := range out.Roles {
			exact := r
			exact.PhysicalID = cfnComputeValue(candidate.RoleName)
			role, err := h.owned(ctx, exact, nil)
			if err != nil {
				if cfnComputeMissing(cfnIAMRecoveryError(err)) {
					continue
				}
				return cloudformation.ResourceResult{}, err
			}
			if result.PhysicalID != "" {
				return cloudformation.ResourceResult{}, fmt.Errorf("ambiguous private service-linked role incarnation")
			}
			result = cfnIAMServiceLinkedResult(role)
		}
		marker := cfnComputeValue(out.Marker)
		if marker == "" {
			break
		}
		input["Marker"] = marker
	}
	if result.PhysicalID == "" {
		return result, cfnIAMNotFound()
	}
	return result, nil
}

func (h cfnIAMInlineAttachment) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	name, target, err := h.identity(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, cfnIAMRecoveryError(err)
	}
	return h.result(name, target), nil
}

func (h cfnIAMPolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	name, id := cfnComputeString(r.Properties, "PolicyName"), cfnIAMPolicyID(r)
	found := false
	for key, kind := range map[string]string{"Roles": "Role", "Users": "User", "Groups": "Group"} {
		targets, _ := cfnComputeStringList(r.Properties, key)
		for _, target := range targets {
			_, err := cfnIAMGetInline(cfnIAMAggregateContext(ctx, r), h.commands, kind, cfnIAMPolicyInputs(kind, target, name, ""))
			if err != nil {
				if cfnComputeMissing(cfnIAMRecoveryError(err)) {
					continue
				}
				return cloudformation.ResourceResult{}, err
			}
			found = true
		}
	}
	if !found {
		return cloudformation.ResourceResult{}, cfnIAMNotFound()
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: name, Attributes: map[string]any{"Id": id}}, nil
}

func (h cfnIAMUserToGroupAddition) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	out, _, claims, err := h.group(ctx, r, cfnComputeString(r.Properties, "GroupName"), false, false)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnIAMAdditionID(r)
	for _, claim := range claims {
		if claim == id {
			return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": cfnComputeValue(out.Group.GroupId)}}, nil
		}
	}
	return cloudformation.ResourceResult{}, cfnIAMNotFound()
}
