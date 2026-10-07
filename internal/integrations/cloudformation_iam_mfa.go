package integrations

import (
	"context"
	"reflect"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
	iamowner "stackd/internal/services/iam"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-virtualmfadevice.html
// Seed and QR material are consumed inside IAM, never returned as CFN attributes.
type cfnIAMMFA struct{ commands StepFunctionsCommands }

func (h cfnIAMMFA) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "VirtualMfaDeviceName", "Path", "Users", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "VirtualMfaDeviceName", "Path"); err != nil {
		return err
	}
	if err := cfnIAMRequireList(p, "Users", 1); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnIAMMFA) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "VirtualMfaDeviceName") || !reflect.DeepEqual(cfnComputeDefault(a, "Path", "/"), cfnComputeDefault(b, "Path", "/")), h.Validate(b)
}
func cfnIAMMFASerial(r cloudformation.ResourceRequest) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	return cfnIAMARN(r, "mfa", cfnComputeDefault(r.Properties, "Path", "/").(string), cfnComputeName(r, "VirtualMfaDeviceName", 128))
}
func (h cfnIAMMFA) tags(ctx context.Context, serial string) (api.TagListType, error) {
	var tags api.TagListType
	in := map[string]any{"SerialNumber": serial}
	for {
		out, err := cfnComputeCall[api.ListMFADeviceTagsOutput](ctx, h.commands, "iam", "ListMFADeviceTags", in)
		if err != nil {
			return nil, err
		}
		tags = append(tags, out.Tags...)
		marker := cfnComputeValue(out.Marker)
		if marker == "" {
			return tags, nil
		}
		in["Marker"] = marker
	}
}
func (h cfnIAMMFA) owned(ctx context.Context, r cloudformation.ResourceRequest, serial string) (*api.VirtualMFADevice, error) {
	ctx = cfnIAMContext(ctx, r)
	in := map[string]any{"AssignmentStatus": "Any"}
	for {
		out, err := cfnComputeCall[api.ListVirtualMFADevicesOutput](ctx, h.commands, "iam", "ListVirtualMFADevices", in)
		if err != nil {
			return nil, err
		}
		for _, d := range out.VirtualMFADevices {
			if cfnComputeValue(d.SerialNumber) == serial {
				tags, e := h.tags(ctx, serial)
				if e != nil {
					return nil, e
				}
				d.Tags = tags
				return &d, nil
			}
		}
		marker := cfnComputeValue(out.Marker)
		if marker == "" {
			return nil, cfnIAMNotFound()
		}
		in["Marker"] = marker
	}
}
func cfnIAMMFAResult(serial string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: serial, Ref: serial, Attributes: map[string]any{"SerialNumber": serial}}
}
func (h cfnIAMMFA) users(ctx context.Context, r cloudformation.ResourceRequest, d *api.VirtualMFADevice) error {
	desired, _ := cfnComputeStringList(r.Properties, "Users")
	current := ""
	if d.User != nil {
		current = cfnComputeValue(d.User.UserName)
	}
	serial := cfnComputeValue(d.SerialNumber)
	if current != "" && (len(desired) == 0 || !strings.EqualFold(desired[0], current)) {
		if err := cfnComputeRun(ctx, h.commands, "iam", "DeactivateMFADevice", map[string]any{"UserName": current, "SerialNumber": serial}); err != nil {
			return err
		}
		current = ""
	}
	if len(desired) == 1 && current == "" {
		return cfnComputeRun(cfnIAMContext(ctx, r), h.commands, "iam", "EnableMFADevice", map[string]any{"UserName": desired[0], "SerialNumber": serial, "AuthenticationCode1": "000000", "AuthenticationCode2": "000000"})
	}
	return nil
}
func (h cfnIAMMFA) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	serial := cfnIAMMFASerial(r)
	d, err := h.owned(ctx, r, serial)
	if err != nil && !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if cfnComputeMissing(err) {
		out, e := cfnComputeCall[api.CreateVirtualMFADeviceOutput](ctx, h.commands, "iam", "CreateVirtualMFADevice", map[string]any{"VirtualMFADeviceName": cfnComputeName(r, "VirtualMfaDeviceName", 128), "Path": cfnComputeDefault(r.Properties, "Path", "/"), "Tags": cfnComputeTagList(cfnIAMCustomerTags(r))})
		if e != nil {
			return cfnIAMCreationFailure(ctx, r, h, e)
		}
		d = out.VirtualMFADevice
		serial = cfnComputeValue(d.SerialNumber)
	}
	return cfnIAMMFAResult(serial), h.users(ctx, r, d)
}
func (h cfnIAMMFA) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	d, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnIAMMFAResult(r.PhysicalID)
	if err := h.users(ctx, r, d); err != nil {
		return result, err
	}
	return result, cfnIAMUpdateTags(ctx, h.commands, r, "MFADevice", "SerialNumber", r.PhysicalID, cfnIAMTags(d.Tags))
}
func (h cfnIAMMFA) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnIAMContext(ctx, r)
	serial := cfnIAMMFASerial(r)
	d, err := h.owned(ctx, r, serial)
	if err != nil {
		return cfnComputeAbsent(err)
	}
	r.Properties = cloudformation.Properties{"Users": []any{}}
	if err := h.users(ctx, r, d); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "iam", "DeleteVirtualMFADevice", map[string]any{"SerialNumber": serial}))
}
func (h cfnIAMMFA) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	d, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	users := []string{}
	if d.User != nil {
		users = append(users, cfnComputeValue(d.User.UserName))
	}
	pathName := strings.SplitN(r.PhysicalID, ":mfa", 2)
	path, name := "/", ""
	if len(pathName) == 2 {
		i := strings.LastIndex(pathName[1], "/")
		if i >= 0 {
			path = pathName[1][:i+1]
			name = pathName[1][i+1:]
		}
	}
	return cloudformation.Properties{"SerialNumber": r.PhysicalID, "VirtualMfaDeviceName": name, "Path": path, "Users": users, "Tags": cfnIAMUserTags(d.Tags)}, nil
}
func (h cfnIAMMFA) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{"AssignmentStatus": "Any"}
	for {
		out, err := cfnComputeCall[api.ListVirtualMFADevicesOutput](ctx, h.commands, "iam", "ListVirtualMFADevices", in)
		if err != nil {
			return nil, err
		}
		for _, d := range out.VirtualMFADevices {
			rr := r
			rr.PhysicalID = cfnComputeValue(d.SerialNumber)
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
func (h cfnIAMMFA) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	if _, err := h.owned(ctx, r, r.PhysicalID); err != nil {
		if cfnComputeMissing(err) {
			return false, nil
		}
		return false, err
	}
	ready := false
	owner := iamowner.CloudFormationContext{Owner: cfnIAMPolicyOwner(r), Direct: r.CloudControl, MFASerial: r.PhysicalID, MFAReady: &ready}
	_, err := cfnComputeCall[api.ListVirtualMFADevicesOutput](iamowner.WithCloudFormationContext(ctx, owner), h.commands, "iam", "ListVirtualMFADevices", map[string]any{"AssignmentStatus": "Any", "MaxItems": 1})
	return ready, err
}
