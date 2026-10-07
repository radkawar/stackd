package integrations

import (
	"context"
	"fmt"
	"path"
	"strings"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

type cfnEC2Instance struct{ commands StepFunctionsCommands }

func (h cfnEC2Instance) Validate(p cloudformation.Properties) error {
	if err := cfnEC2ComputeValidate(p, "AdditionalInfo", "Affinity", "AvailabilityZone", "BlockDeviceMappings", "CpuOptions", "CreditSpecification", "DisableApiTermination", "EbsOptimized", "ElasticGpuSpecifications", "ElasticInferenceAccelerators", "EnclaveOptions", "HibernationOptions", "HostId", "HostResourceGroupArn", "IamInstanceProfile", "ImageId", "InstanceInitiatedShutdownBehavior", "InstanceType", "Ipv6AddressCount", "Ipv6Addresses", "KernelId", "KeyName", "LaunchTemplate", "LicenseSpecifications", "MetadataOptions", "Monitoring", "NetworkInterfaces", "PlacementGroupName", "PrivateDnsNameOptions", "PrivateIpAddress", "PropagateTagsToVolumeOnCreation", "RamdiskId", "SecurityGroupIds", "SecurityGroups", "SourceDestCheck", "SsmAssociations", "SubnetId", "Tags", "Tenancy", "UserData", "Volumes"); err != nil {
		return err
	}
	if p["ImageId"] == nil && p["LaunchTemplate"] == nil {
		return fmt.Errorf("ImageId or LaunchTemplate is required")
	}
	if p["SsmAssociations"] != nil {
		return fmt.Errorf("SSM instance associations require an association owner that is not implemented")
	}
	if err := cfnEC2Booleans(p, "DisableApiTermination", "EbsOptimized", "Monitoring", "PropagateTagsToVolumeOnCreation", "SourceDestCheck"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "AdditionalInfo", "Affinity", "AvailabilityZone", "HostId", "HostResourceGroupArn", "IamInstanceProfile", "ImageId", "InstanceInitiatedShutdownBehavior", "InstanceType", "KernelId", "KeyName", "PlacementGroupName", "PrivateIpAddress", "RamdiskId", "SubnetId", "Tenancy", "UserData"); err != nil {
		return err
	}
	if raw, found := p["Volumes"]; found {
		list, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("volumes must be a list")
		}
		seen := map[string]bool{}
		for _, item := range list {
			v, ok := cfnComputeObject(item)
			if !ok {
				return fmt.Errorf("volumes entries must be objects")
			}
			if err := cfnComputeProperties(v, "VolumeId", "Device"); err != nil {
				return err
			}
			if err := cfnComputeRequired(v, "VolumeId", "Device"); err != nil {
				return err
			}
			if err := cfnComputeStrings(v, "VolumeId", "Device"); err != nil {
				return err
			}
			id := cfnComputeString(v, "VolumeId")
			if id == "" || cfnComputeString(v, "Device") == "" || seen[id] {
				return fmt.Errorf("volumes requires distinct nonempty volume IDs and devices")
			}
			seen[id] = true
		}
	}
	_, err := cfnEC2InstanceLaunch(cloudformation.ResourceRequest{Properties: p})
	return err
}
func (h cfnEC2Instance) Replacement(a, b cloudformation.Properties) (bool, error) {
	if cfnComputeChanged(a, b, "AvailabilityZone", "CpuOptions", "ElasticGpuSpecifications", "ElasticInferenceAccelerators", "EnclaveOptions", "HibernationOptions", "HostResourceGroupArn", "ImageId", "Ipv6AddressCount", "Ipv6Addresses", "KeyName", "LaunchTemplate", "LicenseSpecifications", "NetworkInterfaces", "PlacementGroupName", "PrivateIpAddress", "SubnetId", "SecurityGroups") {
		return true, nil
	}
	return cfnEC2InstanceMappingsReplace(a["BlockDeviceMappings"], b["BlockDeviceMappings"]), nil
}
func (h cfnEC2Instance) instances(ctx context.Context, in map[string]any) ([]api.Instance, error) {
	rows := []api.Instance{}
	for {
		out, err := cfnComputeCall[api.DescribeInstancesResult](ctx, h.commands, "ec2", "DescribeInstances", in)
		if err != nil {
			return nil, err
		}
		for _, reservation := range out.Reservations {
			rows = append(rows, reservation.Instances...)
		}
		if cfnComputeValue(out.NextToken) == "" {
			return rows, nil
		}
		in["NextToken"] = *out.NextToken
	}
}
func (h cfnEC2Instance) get(ctx context.Context, id string) (api.Instance, error) {
	rows, err := h.instances(ctx, map[string]any{"InstanceIds": []string{id}})
	if err != nil {
		return api.Instance{}, err
	}
	if len(rows) != 1 {
		return api.Instance{}, cfnEC2ComputeMissing("instance", id)
	}
	return rows[0], nil
}
func cfnEC2InstanceResult(v api.Instance) cloudformation.ResourceResult {
	id := cfnComputeValue(v.InstanceId)
	attrs := map[string]any{"InstanceId": id, "VpcId": cfnComputeValue(v.VpcId), "PrivateDnsName": cfnComputeValue(v.PrivateDnsName), "PrivateIp": cfnComputeValue(v.PrivateIpAddress), "PublicDnsName": cfnComputeValue(v.PublicDnsName), "PublicIp": cfnComputeValue(v.PublicIpAddress)}
	if v.Placement != nil {
		attrs["AvailabilityZone"] = cfnComputeValue(v.Placement.AvailabilityZone)
	}
	if v.State != nil {
		state := map[string]any{"Name": cfnComputeValue(v.State.Name)}
		if v.State.Code != nil {
			state["Code"] = fmt.Sprint(*v.State.Code)
		}
		attrs["State"] = state
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: attrs}
}
func cfnEC2InstanceState(v api.Instance) string {
	if v.State == nil {
		return ""
	}
	return cfnComputeValue(v.State.Name)
}
func cfnEC2InstanceLaunch(r cloudformation.ResourceRequest) (map[string]any, error) {
	in := cfnComputeCopy(r.Properties, "AdditionalInfo", "BlockDeviceMappings", "CpuOptions", "CreditSpecification", "DisableApiTermination", "EbsOptimized", "ElasticInferenceAccelerators", "EnclaveOptions", "HibernationOptions", "ImageId", "InstanceInitiatedShutdownBehavior", "InstanceType", "Ipv6AddressCount", "Ipv6Addresses", "KernelId", "KeyName", "LaunchTemplate", "LicenseSpecifications", "MetadataOptions", "NetworkInterfaces", "PrivateDnsNameOptions", "PrivateIpAddress", "RamdiskId", "SecurityGroupIds", "SecurityGroups", "SubnetId", "UserData")
	if in["InstanceType"] == nil && in["LaunchTemplate"] == nil {
		in["InstanceType"] = "m1.small"
	}
	if value, found := r.Properties["ElasticGpuSpecifications"]; found {
		in["ElasticGpuSpecification"] = value
	}
	placement := cfnComputeCopy(r.Properties, "Affinity", "AvailabilityZone", "HostId", "HostResourceGroupArn", "Tenancy")
	if value, found := r.Properties["PlacementGroupName"]; found {
		placement["GroupName"] = value
	}
	if len(placement) > 0 {
		in["Placement"] = placement
	}
	if value, found := r.Properties["Monitoring"]; found {
		in["Monitoring"] = map[string]any{"Enabled": value}
	}
	if value, found := r.Properties["IamInstanceProfile"]; found {
		in["IamInstanceProfile"] = map[string]any{"Name": value}
	}
	if err := cfnEC2InstanceLaunchProperties(r.Properties, in); err != nil {
		return nil, err
	}
	in["MinCount"], in["MaxCount"] = 1, 1
	in["ClientToken"] = cfnComputeHash(r.Token)
	specs := cfnEC2NetworkTagSpecifications(r, "instance")
	if propagate, _ := r.Properties["PropagateTagsToVolumeOnCreation"].(bool); propagate {
		specs = append(specs, cfnEC2NetworkTagSpecifications(r, "volume")...)
	}
	in["TagSpecifications"] = specs
	return in, nil
}
func (h cfnEC2Instance) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if id != "" {
		r.PhysicalID = id
		return h.Result(ctx, r)
	}
	in, err := cfnEC2InstanceLaunch(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[api.Reservation](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "RunInstances", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if len(out.Instances) != 1 || cfnComputeValue(out.Instances[0].InstanceId) == "" {
		return cloudformation.ResourceResult{}, fmt.Errorf("RunInstances did not return exactly one instance")
	}
	v := out.Instances[0]
	return cfnEC2InstanceResult(v), cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InstanceId))
}
func (h cfnEC2Instance) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if replacement, _ := h.Replacement(r.Previous, r.Properties); replacement {
		return cloudformation.ResourceResult{}, fmt.Errorf("instance update requires replacement")
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEC2InstanceResult(v)
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InstanceId)); err != nil {
		return result, err
	}
	_, err = h.converge(ctx, r, v)
	return result, err
}
func (h cfnEC2Instance) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, err := h.get(ctx, r.PhysicalID)
	if cfnEC2Missing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InstanceId)); err != nil {
		return err
	}
	if state := cfnEC2InstanceState(v); state == "terminated" || state == "shutting-down" {
		return nil
	}
	// Termination protection is user-owned service state. Never silently bypass
	// it: the authoritative EC2 termination command determines admission.
	return cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "TerminateInstances", map[string]any{"InstanceIds": []string{r.PhysicalID}})
}
func (h cfnEC2Instance) attribute(ctx context.Context, id, attribute string) (*api.InstanceAttribute, error) {
	return cfnComputeCall[api.InstanceAttribute](ctx, h.commands, "ec2", "DescribeInstanceAttribute", map[string]any{"InstanceId": id, "Attribute": attribute})
}
func (h cfnEC2Instance) modify(ctx context.Context, id, key string, value any) error {
	return cfnComputeRun(ctx, h.commands, "ec2", "ModifyInstanceAttribute", map[string]any{"InstanceId": id, key: map[string]any{"Value": value}})
}

// converge runs real EC2 commands under the instance mutation fence.
// Stop/modify/start remains pending until the shared scheduler drives QEMU.
func (h cfnEC2Instance) converge(ctx context.Context, r cloudformation.ResourceRequest, v api.Instance) (bool, error) {
	ctx = cfnEC2NativeContext(ctx, r, "mutate")
	state := cfnEC2InstanceState(v)
	if state == "terminated" || state == "shutting-down" {
		reason := ""
		if v.StateReason != nil {
			reason = cfnComputeValue(v.StateReason.Message)
		}
		return false, fmt.Errorf("EC2 instance is %s: %s", state, reason)
	}
	if state == "pending" || state == "stopping" {
		return false, nil
	}
	if state != "running" && state != "stopped" {
		return false, fmt.Errorf("EC2 instance reported unknown state %q", state)
	}
	for _, key := range []string{"AdditionalInfo", "Affinity", "HostId", "PlacementGroupName", "KernelId", "RamdiskId", "PrivateDnsNameOptions"} {
		if len(r.Previous) > 0 && cfnComputeChanged(r.Previous, r.Properties, key) {
			return false, fmt.Errorf("native EC2 owner cannot update %s", key)
		}
	}
	if optimized, _ := r.Properties["EbsOptimized"].(bool); optimized {
		return false, fmt.Errorf("native EC2 owner does not provide EBS optimization guarantees")
	}
	if tenancy := cfnComputeString(r.Properties, "Tenancy"); tenancy != "" && tenancy != "default" {
		return false, fmt.Errorf("native EC2 owner supports only default tenancy")
	}
	resize := false
	if desired := cfnEC2InstanceDesiredType(r); desired != "" && desired != cfnComputeValue(v.InstanceType) {
		resize = true
	}
	var user *api.InstanceAttribute
	if _, found := r.Properties["UserData"]; found || r.Previous["UserData"] != nil {
		var err error
		user, err = h.attribute(ctx, r.PhysicalID, "userData")
		if err != nil {
			return false, err
		}
		actual := ""
		if user.UserData != nil {
			actual = cfnComputeValue(user.UserData.Value)
		}
		if actual != cfnComputeString(r.Properties, "UserData") {
			resize = true
		}
	}
	if resize && state == "running" {
		return false, cfnComputeRun(ctx, h.commands, "ec2", "StopInstances", map[string]any{"InstanceIds": []string{r.PhysicalID}})
	}
	if resize && state == "stopped" {
		if desired := cfnEC2InstanceDesiredType(r); desired != "" && desired != cfnComputeValue(v.InstanceType) {
			if err := h.modify(ctx, r.PhysicalID, "InstanceType", desired); err != nil {
				return false, err
			}
		}
		if user != nil {
			actual := ""
			if user.UserData != nil {
				actual = cfnComputeValue(user.UserData.Value)
			}
			desired := cfnComputeString(r.Properties, "UserData")
			if actual != desired {
				if err := h.modify(ctx, r.PhysicalID, "UserData", desired); err != nil {
					return false, err
				}
			}
		}
	}
	if err := h.liveAttributes(ctx, r, v); err != nil {
		return false, err
	}
	if err := h.mappings(ctx, r, v); err != nil {
		return false, err
	}
	if state == "stopped" {
		return false, cfnComputeRun(ctx, h.commands, "ec2", "StartInstances", map[string]any{"InstanceIds": []string{r.PhysicalID}})
	}
	if ready, err := h.profile(ctx, r, v); !ready || err != nil {
		return false, err
	}
	if ready, err := h.volumes(ctx, r, v); !ready || err != nil {
		return ready, err
	}
	if err := cfnEC2NetworkUpdateTags(ctx, h.commands, r, r.PhysicalID, cfnEC2Tags(v.Tags)); err != nil {
		return false, err
	}
	fresh, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if fresh.MetadataOptions != nil && cfnComputeValue(fresh.MetadataOptions.State) == "pending" {
		return false, nil
	}
	return true, nil
}
func (h cfnEC2Instance) liveAttributes(ctx context.Context, r cloudformation.ResourceRequest, v api.Instance) error {
	for _, row := range []struct {
		key, attribute string
		fallback       any
	}{{"DisableApiTermination", "disableApiTermination", false}, {"InstanceInitiatedShutdownBehavior", "instanceInitiatedShutdownBehavior", "stop"}, {"SourceDestCheck", "sourceDestCheck", true}} {
		desired, found := r.Properties[row.key]
		if !found {
			if r.Previous[row.key] == nil {
				continue
			}
			desired = row.fallback
		}
		out, err := h.attribute(ctx, r.PhysicalID, row.attribute)
		if err != nil {
			return err
		}
		var actual any
		switch row.key {
		case "DisableApiTermination":
			if out.DisableApiTermination != nil {
				actual = cfnEC2ComputeBool(out.DisableApiTermination.Value)
			}
		case "InstanceInitiatedShutdownBehavior":
			if out.InstanceInitiatedShutdownBehavior != nil {
				actual = cfnComputeValue(out.InstanceInitiatedShutdownBehavior.Value)
			}
		case "SourceDestCheck":
			if out.SourceDestCheck != nil {
				actual = cfnEC2ComputeBool(out.SourceDestCheck.Value)
			}
		}
		if actual != desired {
			if err := h.modify(ctx, r.PhysicalID, row.key, desired); err != nil {
				return err
			}
		}
	}
	if err := h.groups(ctx, r, v); err != nil {
		return err
	}
	if desired, found := r.Properties["Monitoring"]; found || r.Previous["Monitoring"] != nil {
		if !found {
			desired = false
		}
		actual := v.Monitoring != nil && cfnComputeValue(v.Monitoring.State) == "enabled"
		if desired != actual {
			operation := "UnmonitorInstances"
			if desired == true {
				operation = "MonitorInstances"
			}
			if err := cfnComputeRun(ctx, h.commands, "ec2", operation, map[string]any{"InstanceIds": []string{r.PhysicalID}}); err != nil {
				return err
			}
		}
	}
	if err := h.metadata(ctx, r, v); err != nil {
		return err
	}
	if desired, found := r.Properties["CreditSpecification"]; found || r.Previous["CreditSpecification"] != nil {
		family := ""
		if !found {
			typ := cfnEC2InstanceDesiredType(r)
			if typ == "" {
				typ = cfnComputeValue(v.InstanceType)
			}
			family, _, _ = strings.Cut(typ, ".")
			// Resizing out of a burstable family removes CPU credits entirely;
			// EC2 has no default credit setting to apply to an ordinary type.
			switch family {
			case "t2", "t3", "t3a", "t4g", "t8i":
			default:
				return nil
			}
		}
		out, err := cfnComputeCall[api.DescribeInstanceCreditSpecificationsResult](ctx, h.commands, "ec2", "DescribeInstanceCreditSpecifications", map[string]any{"InstanceIds": []string{r.PhysicalID}})
		if err != nil {
			return err
		}
		want := ""
		if found {
			credits, ok := cfnComputeObject(desired)
			if !ok {
				return fmt.Errorf("CreditSpecification must be an object")
			}
			want = cfnComputeString(credits, "CPUCredits")
		} else {
			defaults, err := cfnComputeCall[api.GetDefaultCreditSpecificationResult](ctx, h.commands, "ec2", "GetDefaultCreditSpecification", map[string]any{"InstanceFamily": family})
			if err != nil {
				return err
			}
			if defaults.InstanceFamilyCreditSpecification == nil {
				return fmt.Errorf("EC2 did not return the default credit specification")
			}
			want = cfnComputeValue(defaults.InstanceFamilyCreditSpecification.CpuCredits)
		}
		actual := ""
		if len(out.InstanceCreditSpecifications) == 1 {
			actual = cfnComputeValue(out.InstanceCreditSpecifications[0].CpuCredits)
		}
		if actual != want {
			out, err := cfnComputeCall[api.ModifyInstanceCreditSpecificationResult](ctx, h.commands, "ec2", "ModifyInstanceCreditSpecification", map[string]any{"InstanceCreditSpecifications": []any{map[string]any{"InstanceId": r.PhysicalID, "CpuCredits": want}}})
			if err != nil {
				return err
			}
			if len(out.UnsuccessfulInstanceCreditSpecifications) > 0 {
				return fmt.Errorf("EC2 rejected instance CPU credit modification")
			}
		}
	}
	return nil
}
func (h cfnEC2Instance) profile(ctx context.Context, r cloudformation.ResourceRequest, v api.Instance) (bool, error) {
	wanted := cfnComputeString(r.Properties, "IamInstanceProfile")
	if wanted == "" && r.Previous["IamInstanceProfile"] == nil {
		return true, nil
	}
	in := map[string]any{"Filters": []any{map[string]any{"Name": "instance-id", "Values": []string{r.PhysicalID}}}}
	association := ""
	for {
		out, err := cfnComputeCall[api.DescribeIamInstanceProfileAssociationsResult](ctx, h.commands, "ec2", "DescribeIamInstanceProfileAssociations", in)
		if err != nil {
			return false, err
		}
		for _, a := range out.IamInstanceProfileAssociations {
			switch cfnComputeValue(a.State) {
			case "associating", "disassociating":
				return false, nil
			case "associated":
				association = cfnComputeValue(a.AssociationId)
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			break
		}
		in["NextToken"] = *out.NextToken
	}
	current := ""
	if v.IamInstanceProfile != nil {
		current = path.Base(cfnComputeValue(v.IamInstanceProfile.Arn))
	}
	if wanted == current {
		return true, nil
	}
	if wanted == "" {
		if association == "" {
			return true, nil
		}
		return false, cfnComputeRun(ctx, h.commands, "ec2", "DisassociateIamInstanceProfile", map[string]any{"AssociationId": association})
	}
	request := map[string]any{"IamInstanceProfile": map[string]any{"Name": wanted}}
	operation := "AssociateIamInstanceProfile"
	if association != "" {
		operation = "ReplaceIamInstanceProfileAssociation"
		request["AssociationId"] = association
	} else {
		request["InstanceId"] = r.PhysicalID
	}
	return false, cfnComputeRun(ctx, h.commands, "ec2", operation, request)
}
func (h cfnEC2Instance) volumes(ctx context.Context, r cloudformation.ResourceRequest, v api.Instance) (bool, error) {
	wanted := map[string]string{}
	if list, ok := r.Properties["Volumes"].([]any); ok {
		for _, raw := range list {
			volume, _ := cfnComputeObject(raw)
			wanted[cfnComputeString(volume, "VolumeId")] = cfnComputeString(volume, "Device")
		}
	}
	previous := map[string]string{}
	if list, ok := r.Previous["Volumes"].([]any); ok {
		for _, raw := range list {
			volume, _ := cfnComputeObject(raw)
			previous[cfnComputeString(volume, "VolumeId")] = cfnComputeString(volume, "Device")
		}
	}
	pending := false
	for id, device := range previous {
		if desired, found := wanted[id]; found && desired == device {
			continue
		}
		for _, m := range v.BlockDeviceMappings {
			if m.Ebs != nil && cfnComputeValue(m.Ebs.VolumeId) == id {
				pending = true
				if cfnComputeValue(m.Ebs.Status) != "detaching" {
					if err := cfnComputeRun(ctx, h.commands, "ec2", "DetachVolume", map[string]any{"InstanceId": r.PhysicalID, "VolumeId": id, "Device": cfnComputeValue(m.DeviceName)}); err != nil {
						return false, err
					}
				}
			}
		}
	}
	if pending {
		return false, nil
	}
	for id, device := range wanted {
		found := false
		for _, m := range v.BlockDeviceMappings {
			if m.Ebs == nil || cfnComputeValue(m.Ebs.VolumeId) != id {
				continue
			}
			found = true
			if cfnComputeValue(m.DeviceName) != device {
				return false, fmt.Errorf("volume %s is attached at a different device", id)
			}
			if cfnComputeValue(m.Ebs.Status) != "attached" {
				pending = true
			}
		}
		if !found {
			if err := cfnComputeRun(ctx, h.commands, "ec2", "AttachVolume", map[string]any{"InstanceId": r.PhysicalID, "VolumeId": id, "Device": device}); err != nil {
				return false, err
			}
			pending = true
		}
	}
	return !pending, nil
}
func (h cfnEC2Instance) projection(ctx context.Context, v api.Instance) (cloudformation.Properties, error) {
	p, err := cfnEC2ComputeProjection(v)
	if err != nil {
		return nil, err
	}
	p = cloudformation.Properties(cfnComputeCopy(p, "ImageId", "InstanceType", "KeyName", "SubnetId", "PrivateIpAddress", "CpuOptions", "EbsOptimized", "HibernationOptions", "EnclaveOptions"))
	p["Tags"] = cfnEC2ComputePublicTags(v.Tags)
	for key, value := range cfnEC2InstanceResult(v).Attributes {
		p[key] = value
	}
	if v.Placement != nil {
		p["AvailabilityZone"] = cfnComputeValue(v.Placement.AvailabilityZone)
		p["Tenancy"] = cfnComputeValue(v.Placement.Tenancy)
	}
	if v.IamInstanceProfile != nil {
		p["IamInstanceProfile"] = path.Base(cfnComputeValue(v.IamInstanceProfile.Arn))
	}
	groups := []any{}
	for _, g := range v.SecurityGroups {
		groups = append(groups, cfnComputeValue(g.GroupId))
	}
	p["SecurityGroupIds"] = groups
	p["Monitoring"] = v.Monitoring != nil && cfnComputeValue(v.Monitoring.State) == "enabled"
	if v.MetadataOptions != nil {
		metadata, err := cfnEC2ComputeProjection(v.MetadataOptions)
		if err != nil {
			return nil, err
		}
		delete(metadata, "State")
		p["MetadataOptions"] = metadata
	}
	for _, row := range []struct{ key, attribute string }{{"UserData", "userData"}, {"DisableApiTermination", "disableApiTermination"}, {"InstanceInitiatedShutdownBehavior", "instanceInitiatedShutdownBehavior"}, {"SourceDestCheck", "sourceDestCheck"}} {
		out, err := h.attribute(ctx, cfnComputeValue(v.InstanceId), row.attribute)
		if err != nil {
			return nil, err
		}
		switch row.key {
		case "UserData":
			if out.UserData != nil {
				p[row.key] = cfnComputeValue(out.UserData.Value)
			}
		case "DisableApiTermination":
			if out.DisableApiTermination != nil {
				p[row.key] = cfnEC2ComputeBool(out.DisableApiTermination.Value)
			}
		case "InstanceInitiatedShutdownBehavior":
			if out.InstanceInitiatedShutdownBehavior != nil {
				p[row.key] = cfnComputeValue(out.InstanceInitiatedShutdownBehavior.Value)
			}
		case "SourceDestCheck":
			if out.SourceDestCheck != nil {
				p[row.key] = cfnEC2ComputeBool(out.SourceDestCheck.Value)
			}
		}
	}
	switch family, _, _ := strings.Cut(cfnComputeValue(v.InstanceType), "."); family {
	case "t2", "t3", "t3a", "t4g", "t8i":
		out, err := cfnComputeCall[api.DescribeInstanceCreditSpecificationsResult](ctx, h.commands, "ec2", "DescribeInstanceCreditSpecifications", map[string]any{"InstanceIds": []string{cfnComputeValue(v.InstanceId)}})
		if err != nil {
			return nil, err
		}
		if len(out.InstanceCreditSpecifications) == 1 {
			p["CreditSpecification"] = map[string]any{"CPUCredits": cfnComputeValue(out.InstanceCreditSpecifications[0].CpuCredits)}
		}
	}
	if err := h.topology(ctx, v, p); err != nil {
		return nil, err
	}
	return p, nil
}
func (h cfnEC2Instance) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InstanceId)); err != nil {
		return nil, err
	}
	if cfnEC2InstanceState(v) == "terminated" {
		return nil, cfnEC2ComputeMissing("instance", r.PhysicalID)
	}
	return h.projection(ctx, v)
}
func (h cfnEC2Instance) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := h.instances(ctx, map[string]any{})
	if err != nil {
		return nil, err
	}
	out := []cloudformation.ResourceDescription{}
	for _, v := range rows {
		if cfnEC2InstanceState(v) == "terminated" {
			continue
		}
		if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InstanceId)); err != nil {
			continue
		}
		p, err := h.projection(ctx, v)
		if err != nil {
			return nil, err
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: cfnComputeValue(v.InstanceId), Properties: p})
	}
	return out, nil
}
func (h cfnEC2Instance) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InstanceId)); err != nil {
		return false, err
	}
	return h.converge(ctx, r, v)
}
func (h cfnEC2Instance) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if cfnEC2Missing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InstanceId)); err != nil {
		return false, err
	}
	return cfnEC2InstanceState(v) == "terminated", nil
}
func (h cfnEC2Instance) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEC2InstanceResult(v), cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InstanceId))
}
func (h cfnEC2Instance) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if id == "" {
		return cloudformation.ResourceResult{}, cfnEC2NotFound(r.Type)
	}
	r.PhysicalID = id
	return h.Result(ctx, r)
}
