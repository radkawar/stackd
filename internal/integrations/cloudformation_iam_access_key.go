package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
	iamowner "stackd/internal/services/iam"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-accesskey.html
// Secret material appears only in creation's GetAtt output, never the read model.
type cfnIAMAccessKey struct{ commands StepFunctionsCommands }

func (h cfnIAMAccessKey) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "UserName", "Status", "Serial"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "UserName"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "UserName", "Status"); err != nil {
		return err
	}
	if status := cfnComputeString(p, "Status"); status != "" && status != "Active" && status != "Inactive" && status != "Expired" {
		return fmt.Errorf("status must be Active, Inactive or Expired")
	}
	if p["Serial"] != nil {
		if _, err := cfnIAMInteger(p, "Serial", 0, 2147483647); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnIAMAccessKey) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	old, next := int64(0), int64(0)
	if a["Serial"] != nil {
		old, _ = cfnIAMInteger(a, "Serial", 0, 2147483647)
	}
	if b["Serial"] != nil {
		next, _ = cfnIAMInteger(b, "Serial", 0, 2147483647)
	}
	if next < old {
		return false, fmt.Errorf("serial can only be incremented")
	}
	return cfnComputeChanged(a, b, "UserName") || next != old, nil
}
func (h cfnIAMAccessKey) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[api.CreateAccessKeyOutput](cfnIAMContext(ctx, r), h.commands, "iam", "CreateAccessKey", map[string]any{"UserName": cfnComputeString(r.Properties, "UserName")})
	if err != nil {
		return cfnIAMCreationFailure(ctx, r, h, err)
	}
	if out.AccessKey == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("IAM returned no access key")
	}
	id := cfnComputeValue(out.AccessKey.AccessKeyId)
	result := cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "SecretAccessKey": cfnComputeValue(out.AccessKey.SecretAccessKey)}}
	// Native creation defaults to Active. Status convergence is a separately
	// authorized operation; failure must retain the admitted key and its secret.
	if status := cfnComputeString(r.Properties, "Status"); status != "" && status != cfnComputeValue(out.AccessKey.Status) {
		err = cfnComputeRun(cfnIAMContext(ctx, r), h.commands, "iam", "UpdateAccessKey", map[string]any{"UserName": cfnComputeString(r.Properties, "UserName"), "AccessKeyId": id, "Status": status})
	}
	return result, err
}
func (h cfnIAMAccessKey) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	secret := ""
	owner := iamowner.CloudFormationContext{Owner: cfnIAMPolicyOwner(r), Direct: r.CloudControl}
	if !r.CloudControl {
		owner.SecretResult = &secret
	}
	err := cfnComputeRun(iamowner.WithCloudFormationContext(ctx, owner), h.commands, "iam", "UpdateAccessKey", map[string]any{"UserName": cfnComputeString(r.Properties, "UserName"), "AccessKeyId": r.PhysicalID, "Status": cfnComputeDefault(r.Properties, "Status", "Active")})
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID, Attributes: map[string]any{"Id": r.PhysicalID}}
	if err == nil && !r.CloudControl {
		result.Attributes["SecretAccessKey"] = secret
	}
	return result, err
}
func (h cfnIAMAccessKey) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		rows, err := h.List(ctx, r)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		if len(rows) != 1 {
			return fmt.Errorf("ambiguous access-key incarnation")
		}
		r.PhysicalID = rows[0].Identifier
	}
	name := cfnComputeString(r.Properties, "UserName")
	if name == "" {
		out, err := cfnComputeCall[api.GetAccessKeyLastUsedOutput](ctx, h.commands, "iam", "GetAccessKeyLastUsed", map[string]any{"AccessKeyId": r.PhysicalID})
		if err != nil {
			return cfnComputeAbsent(err)
		}
		name = cfnComputeValue(out.UserName)
	}
	return cfnComputeAbsent(cfnComputeRun(cfnIAMContext(ctx, r), h.commands, "iam", "DeleteAccessKey", map[string]any{"UserName": name, "AccessKeyId": r.PhysicalID}))
}
func (h cfnIAMAccessKey) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name := cfnComputeString(r.Properties, "UserName")
	if name == "" {
		out, err := cfnComputeCall[api.GetAccessKeyLastUsedOutput](ctx, h.commands, "iam", "GetAccessKeyLastUsed", map[string]any{"AccessKeyId": r.PhysicalID})
		if err != nil {
			return nil, err
		}
		name = cfnComputeValue(out.UserName)
	}
	in := map[string]any{"UserName": name}
	for {
		out, err := cfnComputeCall[api.ListAccessKeysOutput](cfnIAMContext(ctx, r), h.commands, "iam", "ListAccessKeys", in)
		if err != nil {
			return nil, err
		}
		for _, key := range out.AccessKeyMetadata {
			if cfnComputeValue(key.AccessKeyId) == r.PhysicalID {
				return cloudformation.Properties{"Id": r.PhysicalID, "UserName": cfnComputeValue(key.UserName), "Status": cfnComputeValue(key.Status)}, nil
			}
		}
		marker := cfnComputeValue(out.Marker)
		if marker == "" {
			break
		}
		in["Marker"] = marker
	}
	return nil, cfnIAMNotFound()
}
func (h cfnIAMAccessKey) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	users := []string{}
	if name := cfnComputeString(r.Properties, "UserName"); name != "" {
		users = append(users, name)
	} else {
		in := map[string]any{}
		for {
			out, err := cfnComputeCall[api.ListUsersOutput](ctx, h.commands, "iam", "ListUsers", in)
			if err != nil {
				return nil, err
			}
			for _, u := range out.Users {
				users = append(users, cfnComputeValue(u.UserName))
			}
			marker := cfnComputeValue(out.Marker)
			if marker == "" {
				break
			}
			in["Marker"] = marker
		}
	}
	for _, name := range users {
		in := map[string]any{"UserName": name}
		for {
			out, err := cfnComputeCall[api.ListAccessKeysOutput](cfnIAMContext(ctx, r), h.commands, "iam", "ListAccessKeys", in)
			if err != nil {
				return nil, err
			}
			for _, key := range out.AccessKeyMetadata {
				id := cfnComputeValue(key.AccessKeyId)
				result = append(result, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"Id": id, "UserName": name, "Status": cfnComputeValue(key.Status)}})
			}
			marker := cfnComputeValue(out.Marker)
			if marker == "" {
				break
			}
			in["Marker"] = marker
		}
	}
	return result, nil
}
