package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
	iamowner "stackd/internal/services/iam"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-servicelinkedrole.html
// IAM's service-owned deletion job is observed, never replaced by ordinary DeleteRole.
type cfnIAMServiceLinked struct{ commands StepFunctionsCommands }

func (h cfnIAMServiceLinked) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "AWSServiceName", "CustomSuffix", "Description"); err != nil {
		return err
	}
	return cfnComputeStrings(p, "AWSServiceName", "CustomSuffix", "Description")
}
func (h cfnIAMServiceLinked) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "AWSServiceName", "CustomSuffix"), h.Validate(b)
}
func cfnIAMServiceLinkedResult(role *api.Role) cloudformation.ResourceResult {
	name := cfnComputeValue(role.RoleName)
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"RoleName": name}}
}
func (h cfnIAMServiceLinked) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnComputeRequired(r.Properties, "AWSServiceName"); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[api.CreateServiceLinkedRoleOutput](cfnIAMContext(ctx, r), h.commands, "iam", "CreateServiceLinkedRole", cfnComputeCopy(r.Properties, "AWSServiceName", "CustomSuffix", "Description"))
	if err != nil {
		return cfnIAMCreationFailure(ctx, r, h, err)
	}
	if out.Role == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("IAM returned no service-linked role")
	}
	return cfnIAMServiceLinkedResult(out.Role), nil
}
func (h cfnIAMServiceLinked) owned(ctx context.Context, r cloudformation.ResourceRequest, task *string) (*api.Role, error) {
	owner := iamowner.CloudFormationContext{Owner: cfnIAMPolicyOwner(r), Direct: r.CloudControl, DeletionTask: task}
	out, err := cfnComputeCall[api.GetRoleOutput](iamowner.WithCloudFormationContext(ctx, owner), h.commands, "iam", "GetRole", map[string]any{"RoleName": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	if out.Role == nil || !strings.HasPrefix(cfnComputeValue(out.Role.Path), "/aws-service-role/") {
		return nil, cfnIAMNotFound()
	}
	return out.Role, nil
}
func (h cfnIAMServiceLinked) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	role, err := h.owned(ctx, r, nil)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnIAMServiceLinkedResult(role)
	err = cfnComputeRun(cfnIAMContext(ctx, r), h.commands, "iam", "UpdateRoleDescription", map[string]any{"RoleName": r.PhysicalID, "Description": cfnComputeDefault(r.Properties, "Description", "")})
	return result, err
}
func (h cfnIAMServiceLinked) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		rows, err := h.List(ctx, r)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		if len(rows) != 1 {
			return fmt.Errorf("ambiguous service-linked incarnation")
		}
		r.PhysicalID = rows[0].Identifier
	}
	if _, err := h.owned(ctx, r, nil); err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(cfnIAMContext(ctx, r), h.commands, "iam", "DeleteServiceLinkedRole", map[string]any{"RoleName": r.PhysicalID}))
}
func (h cfnIAMServiceLinked) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	if r.PhysicalID == "" {
		rows, err := h.List(ctx, r)
		if err != nil {
			return false, err
		}
		if len(rows) == 0 {
			return true, nil
		}
		r.PhysicalID = rows[0].Identifier
	}
	task := ""
	_, err := h.owned(ctx, r, &task)
	if cfnComputeMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if task == "" {
		return false, fmt.Errorf("IAM role has no deletion task")
	}
	out, err := cfnComputeCall[api.GetServiceLinkedRoleDeletionStatusOutput](ctx, h.commands, "iam", "GetServiceLinkedRoleDeletionStatus", map[string]any{"DeletionTaskId": task})
	if err != nil {
		return false, err
	}
	status := cfnComputeValue(out.Status)
	if status == "FAILED" {
		reason := ""
		if out.Reason != nil {
			reason = cfnComputeValue(out.Reason.Reason)
		}
		return false, fmt.Errorf("service-linked role deletion failed: %s", reason)
	}
	return status == "SUCCEEDED", nil
}
func (h cfnIAMServiceLinked) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	role, err := h.owned(ctx, r, nil)
	if err != nil {
		return nil, err
	}
	return cloudformation.Properties{"RoleName": cfnComputeValue(role.RoleName), "Description": cfnComputeValue(role.Description)}, nil
}
func (h cfnIAMServiceLinked) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{"PathPrefix": "/aws-service-role/"}
	for {
		out, err := cfnComputeCall[api.ListRolesOutput](ctx, h.commands, "iam", "ListRoles", in)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Roles {
			rr := r
			rr.PhysicalID = cfnComputeValue(v.RoleName)
			p, e := h.Read(ctx, rr)
			if e != nil {
				if !r.CloudControl {
					continue
				}
				return nil, e
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
		}
		marker := cfnComputeValue(out.Marker)
		if marker == "" {
			return result, nil
		}
		in["Marker"] = marker
	}
}
