package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
	iamowner "stackd/internal/services/iam"
)

// Native embedded IAM policy lifecycle, using authoritative parent policy records:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-userpolicy.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-grouppolicy.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-rolepolicy.html
type cfnIAMInlineAttachment struct {
	commands StepFunctionsCommands
	kind     string
}

func (h cfnIAMInlineAttachment) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "PolicyName", "PolicyDocument", h.kind+"Name"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "PolicyName", h.kind+"Name", "PolicyDocument"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "PolicyName", h.kind+"Name"); err != nil {
		return err
	}
	_, err := cfnComputeDocument(p["PolicyDocument"])
	return err
}
func (h cfnIAMInlineAttachment) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "PolicyName", h.kind+"Name"), h.Validate(b)
}
func (h cfnIAMInlineAttachment) identity(r cloudformation.ResourceRequest) (string, string, error) {
	name, target := cfnComputeString(r.Properties, "PolicyName"), cfnComputeString(r.Properties, h.kind+"Name")
	if r.PhysicalID != "" {
		var p map[string]string
		if err := json.Unmarshal([]byte(r.PhysicalID), &p); err != nil {
			return "", "", fmt.Errorf("invalid inline IAM policy identifier")
		}
		name, target = p["PolicyName"], p[h.kind+"Name"]
	}
	if name == "" || target == "" {
		return "", "", fmt.Errorf("PolicyName and %sName are required", h.kind)
	}
	return name, target, nil
}
func (h cfnIAMInlineAttachment) result(name, target string) cloudformation.ResourceResult {
	raw, _ := json.Marshal(map[string]string{"PolicyName": name, h.kind + "Name": target})
	return cloudformation.ResourceResult{PhysicalID: string(raw), Ref: name}
}
func (h cfnIAMInlineAttachment) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.put(ctx, r, true)
}
func (h cfnIAMInlineAttachment) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.put(ctx, r, false)
}
func (h cfnIAMInlineAttachment) put(ctx context.Context, r cloudformation.ResourceRequest, creating bool) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name, target, err := h.identity(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	doc, _ := cfnComputeDocument(r.Properties["PolicyDocument"])
	owner := iamowner.CloudFormationContext{Owner: cfnIAMPolicyOwner(r), Direct: r.CloudControl && !creating, Creating: creating, RequireExisting: !creating}
	if err := cfnComputeRun(iamowner.WithCloudFormationContext(ctx, owner), h.commands, "iam", "Put"+h.kind+"Policy", cfnIAMPolicyInputs(h.kind, target, name, doc)); err != nil {
		if creating {
			return cfnIAMCreationFailure(ctx, r, h, err)
		}
		return cloudformation.ResourceResult{}, err
	}
	return h.result(name, target), nil
}
func (h cfnIAMInlineAttachment) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name, target, err := h.identity(r)
	if err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(cfnIAMContext(ctx, r), h.commands, "iam", "Delete"+h.kind+"Policy", cfnIAMPolicyInputs(h.kind, target, name, "")))
}
func (h cfnIAMInlineAttachment) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, target, err := h.identity(r)
	if err != nil {
		return nil, err
	}
	doc, err := cfnIAMGetInline(cfnIAMContext(ctx, r), h.commands, h.kind, cfnIAMPolicyInputs(h.kind, target, name, ""))
	if err != nil {
		return nil, err
	}
	return cloudformation.Properties{"PolicyName": name, h.kind + "Name": target, "PolicyDocument": cfnIAMDocument(doc)}, nil
}
func (h cfnIAMInlineAttachment) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	names, err := cfnIAMIdentityNames(ctx, h.commands, h.kind)
	if err != nil {
		return nil, err
	}
	if name := cfnComputeString(r.Properties, h.kind+"Name"); name != "" {
		names = []string{name}
	}
	var result []cloudformation.ResourceDescription
	for _, target := range names {
		in := map[string]any{h.kind + "Name": target}
		for {
			listed, marker, err := cfnIAMListInline(ctx, h.commands, h.kind, in)
			if err != nil {
				return nil, err
			}
			for _, policy := range listed {
				name := string(policy)
				rr := r
				rr.PhysicalID = h.result(name, target).PhysicalID
				p, e := h.Read(ctx, rr)
				if e != nil {
					if !r.CloudControl {
						continue
					}
					return nil, e
				}
				result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
			}
			if marker == "" {
				break
			}
			in["Marker"] = marker
		}
	}
	return result, nil
}
func cfnIAMIdentityNames(ctx context.Context, c StepFunctionsCommands, kind string) ([]string, error) {
	var names []string
	in := map[string]any{}
	for {
		marker := ""
		switch kind {
		case "User":
			out, err := cfnComputeCall[api.ListUsersOutput](ctx, c, "iam", "ListUsers", in)
			if err != nil {
				return nil, err
			}
			for _, v := range out.Users {
				names = append(names, cfnComputeValue(v.UserName))
			}
			marker = cfnComputeValue(out.Marker)
		case "Group":
			out, err := cfnComputeCall[api.ListGroupsOutput](ctx, c, "iam", "ListGroups", in)
			if err != nil {
				return nil, err
			}
			for _, v := range out.Groups {
				names = append(names, cfnComputeValue(v.GroupName))
			}
			marker = cfnComputeValue(out.Marker)
		case "Role":
			out, err := cfnComputeCall[api.ListRolesOutput](ctx, c, "iam", "ListRoles", in)
			if err != nil {
				return nil, err
			}
			for _, v := range out.Roles {
				names = append(names, cfnComputeValue(v.RoleName))
			}
			marker = cfnComputeValue(out.Marker)
		}
		if marker == "" {
			return names, nil
		}
		in["Marker"] = marker
	}
}
