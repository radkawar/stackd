package ec2

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"

	api "stackd/internal/awsapi/ec2"
)

func (s *Service) describeInstanceAttribute(ctx context.Context, tx Transaction, in *api.DescribeInstanceAttributeRequest) (*api.InstanceAttribute, error) {
	records, err := s.instanceCommandTargetsWith(ctx, tx, "DescribeInstanceAttribute", api.InstanceIdStringList{api.InstanceId(str(in.InstanceId))}, in.DryRun, map[string][]string{"ec2:Attribute": {str(in.Attribute)}})
	if err != nil {
		return nil, err
	}
	r := records[0]
	d, err := instanceProjection(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	out := &api.InstanceAttribute{InstanceId: d.InstanceId}
	switch str(in.Attribute) {
	case "instanceType":
		out.InstanceType = &api.AttributeValue{Value: new(api.String(str(d.InstanceType)))}
	case "rootDeviceName":
		out.RootDeviceName = &api.AttributeValue{Value: d.RootDeviceName}
	case "blockDeviceMapping":
		out.BlockDeviceMappings = d.BlockDeviceMappings
	case "groupSet":
		out.Groups = d.SecurityGroups
	case "sourceDestCheck":
		out.SourceDestCheck = &api.AttributeBooleanValue{Value: d.SourceDestCheck}
	case "disableApiTermination":
		out.DisableApiTermination = &api.AttributeBooleanValue{Value: new(api.Boolean(r.DisableAPITermination))}
	case "disableApiStop":
		out.DisableApiStop = &api.AttributeBooleanValue{Value: new(api.Boolean(r.DisableAPIStop))}
	case "instanceInitiatedShutdownBehavior":
		out.InstanceInitiatedShutdownBehavior = &api.AttributeValue{Value: new(api.String(r.ShutdownBehavior))}
	case "userData":
		out.UserData = &api.AttributeValue{}
		if len(r.UserData) > 0 {
			out.UserData.Value = new(api.String(base64.StdEncoding.EncodeToString(r.UserData)))
		}
	case "ebsOptimized":
		out.EbsOptimized = &api.AttributeBooleanValue{Value: d.EbsOptimized}
	case "enaSupport":
		out.EnaSupport = &api.AttributeBooleanValue{Value: d.EnaSupport}
	case "kernel":
		out.KernelId = &api.AttributeValue{Value: d.KernelId}
	case "ramdisk":
		out.RamdiskId = &api.AttributeValue{Value: d.RamdiskId}
	case "sriovNetSupport":
		out.SriovNetSupport = &api.AttributeValue{Value: d.SriovNetSupport}
	case "productCodes":
		out.ProductCodes = d.ProductCodes
	default:
		return nil, failure("InvalidParameterValue", "Value ("+str(in.Attribute)+") for parameter attribute is invalid. Unknown attribute.")
	}
	return out, nil
}

func normalizeInstanceAttribute(in *api.ModifyInstanceAttributeRequest) (*api.ModifyInstanceAttributeRequest, error) {
	out := api.CloneModifyInstanceAttributeRequest(*in)
	count := 0
	for _, present := range []bool{len(in.BlockDeviceMappings) > 0, in.DisableApiStop != nil, in.DisableApiTermination != nil, in.EbsOptimized != nil, in.EnaSupport != nil, in.EnclaveOptions != nil, len(in.Groups) > 0, in.InstanceInitiatedShutdownBehavior != nil, in.InstanceType != nil, in.Kernel != nil, in.Ramdisk != nil, in.SourceDestCheck != nil, in.SriovNetSupport != nil, in.UserData != nil} {
		if present {
			count++
		}
	}
	if in.Attribute != nil {
		if count > 0 || in.Value == nil {
			return nil, failure("InvalidParameterCombination", "Specify exactly one instance attribute and value.")
		}
		value := api.String(str(in.Value))
		boolAttr := func() (*api.AttributeBooleanValue, error) {
			v, err := strconv.ParseBool(string(value))
			if err != nil {
				return nil, failure("InvalidParameterValue", "The attribute value must be true or false.")
			}
			return &api.AttributeBooleanValue{Value: new(api.Boolean(v))}, nil
		}
		var err error
		switch str(in.Attribute) {
		case "disableApiStop":
			out.DisableApiStop, err = boolAttr()
		case "disableApiTermination":
			out.DisableApiTermination, err = boolAttr()
		case "sourceDestCheck":
			out.SourceDestCheck, err = boolAttr()
		case "instanceType":
			out.InstanceType = &api.AttributeValue{Value: &value}
		case "instanceInitiatedShutdownBehavior":
			out.InstanceInitiatedShutdownBehavior = &api.AttributeValue{Value: &value}
		case "userData":
			bytes, e := base64.StdEncoding.DecodeString(string(value))
			if e != nil {
				return nil, failure("InvalidParameterValue", "Invalid BASE64 encoding of user data.")
			}
			out.UserData = &api.SecureBlobAttributeValue{Value: api.SecureBlob(bytes)}
		default:
			return nil, unsupported("The requested instance attribute cannot be modified.")
		}
		if err != nil {
			return nil, err
		}
	} else if count != 1 || in.Value != nil {
		return nil, failure("InvalidParameterCombination", "Specify exactly one instance attribute.")
	}
	return &out, nil
}

func instanceAttributeConditions(in *api.ModifyInstanceAttributeRequest) map[string][]string {
	name, value := str(in.Attribute), ""
	switch {
	case in.DisableApiStop != nil:
		name = "disableApiStop"
		value = strconv.FormatBool(boolValue(in.DisableApiStop.Value))
	case in.DisableApiTermination != nil:
		name = "disableApiTermination"
		value = strconv.FormatBool(boolValue(in.DisableApiTermination.Value))
	case in.SourceDestCheck != nil:
		name = "sourceDestCheck"
		value = strconv.FormatBool(boolValue(in.SourceDestCheck.Value))
	case in.InstanceType != nil:
		name = "instanceType"
		value = str(in.InstanceType.Value)
	case in.InstanceInitiatedShutdownBehavior != nil:
		name = "instanceInitiatedShutdownBehavior"
		value = str(in.InstanceInitiatedShutdownBehavior.Value)
	case in.UserData != nil:
		name = "userData"
	case len(in.BlockDeviceMappings) > 0:
		name = "blockDeviceMapping"
	case len(in.Groups) > 0:
		name = "groupSet"
	case in.EbsOptimized != nil:
		name = "ebsOptimized"
	case in.EnaSupport != nil:
		name = "enaSupport"
	case in.EnclaveOptions != nil:
		name = "enclaveOptions"
	case in.Kernel != nil:
		name = "kernel"
	case in.Ramdisk != nil:
		name = "ramdisk"
	case in.SriovNetSupport != nil:
		name = "sriovNetSupport"
	}
	out := map[string][]string{"ec2:Attribute": {name}}
	if value != "" {
		out["ec2:Attribute/"+name] = []string{value}
	}
	return out
}

func (s *Service) modifyInstanceAttribute(ctx context.Context, tx Transaction, in *api.ModifyInstanceAttributeRequest) (*emptyResult, error) {
	request, err := normalizeInstanceAttribute(in)
	if err != nil {
		return nil, err
	}
	records, err := s.instanceCommandTargetsWith(ctx, tx, "ModifyInstanceAttribute", api.InstanceIdStringList{api.InstanceId(str(in.InstanceId))}, in.DryRun, instanceAttributeConditions(request))
	if err != nil {
		return nil, err
	}
	record := records[0]
	if state := instanceState(record); state == "terminated" || state == "shutting-down" {
		return nil, failure("IncorrectInstanceState", "The instance cannot be modified in its current state.")
	}
	if request.EbsOptimized != nil || request.EnaSupport != nil || request.EnclaveOptions != nil || request.Kernel != nil || request.Ramdisk != nil || request.SriovNetSupport != nil {
		return nil, unsupported("Changing the requested guest hardware attribute is not implemented.")
	}
	if request.InstanceType != nil || request.UserData != nil {
		if instanceState(record) != "stopped" {
			return nil, failure("IncorrectInstanceState", "The instance must be stopped to modify this attribute.")
		}
	}
	if v := request.DisableApiStop; v != nil {
		if v.Value == nil {
			return nil, failure("MissingParameter", "Attribute value is required.")
		}
		record.DisableAPIStop = boolValue(v.Value)
	}
	if v := request.DisableApiTermination; v != nil {
		if v.Value == nil {
			return nil, failure("MissingParameter", "Attribute value is required.")
		}
		record.DisableAPITermination = boolValue(v.Value)
	}
	if v := request.InstanceInitiatedShutdownBehavior; v != nil {
		if str(v.Value) != "stop" && str(v.Value) != "terminate" {
			return nil, failure("InvalidParameterValue", "Shutdown behavior must be stop or terminate.")
		}
		record.ShutdownBehavior = str(v.Value)
	}
	if request.UserData != nil {
		if len(request.UserData.Value) > 16384 {
			return nil, failure("InvalidParameterValue", "User data exceeds 16384 bytes.")
		}
		record.UserData = slices.Clone([]byte(request.UserData.Value))
	}
	if request.InstanceType != nil {
		// AWS reports a hibernated instance as stopped, but rejects resizing
		// until it has resumed and completed an ordinary stop.
		if record.Data.StateReason != nil && str(record.Data.StateReason.Code) == "Client.UserInitiatedHibernate" {
			return nil, failure("IncorrectInstanceState", "The instance '"+record.Key.ID+"' is not in the 'stopped' state.")
		}
		if s.instanceTypes == nil {
			return nil, unsupported("No instance-type catalog is configured.")
		}
		typ, err := s.instanceTypes.ResolveInstanceType(ctx, api.InstanceType(str(request.InstanceType.Value)))
		if err != nil {
			return nil, err
		}
		if typ.ProcessorInfo == nil || !slices.Contains(typ.ProcessorInfo.SupportedArchitectures, api.ArchitectureType(str(record.Data.Architecture))) {
			return nil, failure("InvalidParameterValue", "The instance type does not support this image architecture.")
		}
		cpu, err := instanceCPU(typ, nil)
		if err != nil {
			return nil, err
		}
		if err := s.admitInstanceCreditTypeChange(ctx, &record, api.InstanceType(str(typ.InstanceType))); err != nil {
			return nil, err
		}
		record.Data.CpuOptions = cpu
		record.Data.InstanceType = typ.InstanceType
	}
	if len(request.BlockDeviceMappings) > 0 {
		seen := map[string]bool{}
		for _, mapping := range request.BlockDeviceMappings {
			device := str(mapping.DeviceName)
			if seen[device] {
				return nil, failure("InvalidParameterValue", "Duplicate block device mapping.")
			}
			seen[device] = true
			if mapping.Ebs == nil || mapping.Ebs.DeleteOnTermination == nil || mapping.NoDevice != nil || mapping.VirtualName != nil {
				return nil, unsupported("Only DeleteOnTermination can be changed for attached EBS mappings.")
			}
			found := false
			for i := range record.Data.BlockDeviceMappings {
				retained := &record.Data.BlockDeviceMappings[i]
				if str(retained.DeviceName) != device || retained.Ebs == nil {
					continue
				}
				if mapping.Ebs.VolumeId != nil && str(mapping.Ebs.VolumeId) != str(retained.Ebs.VolumeId) {
					return nil, failure("InvalidParameterValue", "The volume does not match the attached device.")
				}
				retained.Ebs.DeleteOnTermination = mapping.Ebs.DeleteOnTermination
				found = true
				break
			}
			if !found {
				return nil, failure("InvalidParameterValue", "The specified block device is not attached.")
			}
		}
	}
	if request.SourceDestCheck != nil || len(request.Groups) > 0 {
		if len(record.Data.NetworkInterfaces) != 1 {
			return nil, unsupported("ModifyInstanceAttribute requires exactly one primary interface.")
		}
		eni, err := tx.NetworkInterface(key(ctx, str(record.Data.NetworkInterfaces[0].NetworkInterfaceId)))
		if err != nil {
			return nil, err
		}
		if request.SourceDestCheck != nil {
			if request.SourceDestCheck.Value == nil {
				return nil, failure("MissingParameter", "Attribute value is required.")
			}
			// TODO: Comeback support VPC forwarding appliances before admitting disabled checks.
			if !boolValue(request.SourceDestCheck.Value) {
				return nil, unsupported("Disabling source/destination checks requires native forwarding support.")
			}
			eni.Data.SourceDestCheck = request.SourceDestCheck.Value
			record.Data.SourceDestCheck = request.SourceDestCheck.Value
		}
		if len(request.Groups) > 0 {
			groups := []SecurityGroupRecord{}
			for _, id := range request.Groups {
				group, err := tx.SecurityGroup(key(ctx, string(id)))
				if errors.Is(err, ErrNotFound) {
					return nil, missing("security-group", string(id))
				}
				if err != nil {
					return nil, err
				}
				groups = append(groups, group)
			}
			subnet, err := interfaceSubnet(tx, eni)
			if err != nil {
				return nil, err
			}
			if err := validateNetworkInterfaceGroups(groups, subnet, true); err != nil {
				return nil, err
			}
			eni.Data.Groups = networkInterfaceGroupIdentifiers(groups)
			record.Data.SecurityGroups = eni.Data.Groups
		}
		if err := tx.PutNetworkInterface(eni); err != nil {
			return nil, err
		}
		record.Data.NetworkInterfaces[0] = instanceNetworkData(eni.Data)
		if instanceState(record) == "running" {
			scheduleInstanceObservation(&record, s.clock.Now())
		}
	}
	record.Generation++
	setInstanceCommand(ctx, &record)
	if err := tx.PutInstance(record); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func (s *Service) resetInstanceAttribute(ctx context.Context, tx Transaction, in *api.ResetInstanceAttributeRequest) (*emptyResult, error) {
	records, err := s.instanceCommandTargetsWith(ctx, tx, "ResetInstanceAttribute", api.InstanceIdStringList{api.InstanceId(str(in.InstanceId))}, in.DryRun, map[string][]string{"ec2:Attribute": {str(in.Attribute)}})
	if err != nil {
		return nil, err
	}
	if str(in.Attribute) != "sourceDestCheck" {
		return nil, unsupported("Only sourceDestCheck reset is supported for ordinary EBS-backed instances.")
	}
	record := records[0]
	if state := instanceState(record); state == "terminated" || state == "shutting-down" {
		return nil, failure("IncorrectInstanceState", "The instance cannot be modified in its current state.")
	}
	record.Data.SourceDestCheck = new(api.Boolean(true))
	for i, n := range record.Data.NetworkInterfaces {
		eni, err := tx.NetworkInterface(key(ctx, str(n.NetworkInterfaceId)))
		if err != nil {
			return nil, err
		}
		eni.Data.SourceDestCheck = new(api.Boolean(true))
		if err := tx.PutNetworkInterface(eni); err != nil {
			return nil, err
		}
		record.Data.NetworkInterfaces[i] = instanceNetworkData(eni.Data)
	}
	record.Generation++
	setInstanceCommand(ctx, &record)
	if err := tx.PutInstance(record); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}
