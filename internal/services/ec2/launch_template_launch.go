package ec2

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

type launchTemplateAuthorizationKey struct{}
type launchTemplateAuthorization struct {
	ARN       string
	Resources map[string]bool
}

func addLaunchTemplateConditions(ctx context.Context, action, kind, id string, conditions map[string][]string) {
	if action != "RunInstances" {
		return
	}
	origin, ok := ctx.Value(launchTemplateAuthorizationKey{}).(launchTemplateAuthorization)
	if !ok {
		return
	}
	conditions["ec2:LaunchTemplate"] = []string{origin.ARN}
	conditions["ec2:IsLaunchTemplateResource"] = []string{strconv.FormatBool(origin.Resources[kind+"/"+id])}
}

func (s *Service) resolveLaunchTemplate(ctx context.Context, tx Reader, in *api.RunInstancesRequest) (context.Context, *api.RunInstancesRequest, error) {
	if in.LaunchTemplate == nil {
		return ctx, in, nil
	}
	spec := in.LaunchTemplate
	template, err := selectLaunchTemplate(ctx, tx, str(spec.LaunchTemplateId), str(spec.LaunchTemplateName))
	if err != nil {
		return ctx, nil, err
	}
	version, err := selectLaunchTemplateVersion(tx, template, str(spec.Version))
	if err != nil {
		return ctx, nil, err
	}
	if version.Data.InstanceRequirements != nil {
		return ctx, nil, unsupported("Attribute-based instance selection requires an EC2 Fleet or Auto Scaling consumer, not RunInstances.")
	}
	if strings.HasPrefix(str(version.Data.ImageId), "resolve:ssm:") && in.ImageId == nil {
		// TODO: Comeback resolve launch-template SSM image aliases through the
		// current Parameter Store owner; managed operators need their own owner.
		return ctx, nil, unsupported("Resolving SSM image aliases in launch templates is not implemented.")
	}
	out := api.LaunchTemplateConvertRequestLaunchTemplateDataToRunInstancesRequest(version.Data)
	if _, err := instanceLaunchTags(in.TagSpecifications); err != nil {
		return ctx, nil, err
	}
	overrides := api.CloneRunInstancesRequest(*in)
	out.TagSpecifications = mergeLaunchTags(out.TagSpecifications, overrides.TagSpecifications)
	overrides.TagSpecifications = nil
	out.BlockDeviceMappings = mergeLaunchMappings(out.BlockDeviceMappings, overrides.BlockDeviceMappings)
	overrides.BlockDeviceMappings = nil
	out.NetworkInterfaces = mergeLaunchNetworks(out.NetworkInterfaces, overrides.NetworkInterfaces)
	overrides.NetworkInterfaces = nil
	api.MergeRunInstancesRequest(&out, overrides)
	out.LaunchTemplate = &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.LaunchTemplateId(template.Key.ID)), Version: new(api.String(strconv.FormatInt(version.Key.Number, 10)))}
	origin := launchTemplateAuthorization{ARN: resourceARN(scopeFor(ctx), "launch-template", template.Key.ID), Resources: map[string]bool{}}
	origin.Resources["launch-template/"+template.Key.ID] = true
	origin.Resources["instance/*"] = true
	origin.Resources["volume/*"] = true
	origin.Resources["network-interface/*"] = len(in.NetworkInterfaces) == 0 && in.SubnetId == nil && len(in.SecurityGroupIds) == 0 && in.PrivateIpAddress == nil
	if in.ImageId == nil && version.Data.ImageId != nil {
		origin.Resources["image/"+str(version.Data.ImageId)] = true
	}
	if in.KeyName == nil && version.Data.KeyName != nil {
		pair, err := keyPairByName(ctx, tx, str(version.Data.KeyName))
		if err == nil {
			origin.Resources["key-pair/"+pair.Key.ID] = true
		}
	}
	if len(in.SecurityGroupIds) == 0 && len(in.SecurityGroups) == 0 && len(in.NetworkInterfaces) == 0 {
		for _, id := range version.Data.SecurityGroupIds {
			origin.Resources["security-group/"+string(id)] = true
		}
	}
	for _, network := range version.Data.NetworkInterfaces {
		if in.SubnetId == nil && len(in.NetworkInterfaces) == 0 && network.SubnetId != nil {
			origin.Resources["subnet/"+str(network.SubnetId)] = true
		}
		if len(in.NetworkInterfaces) == 0 {
			if network.NetworkInterfaceId != nil {
				origin.Resources["network-interface/"+str(network.NetworkInterfaceId)] = true
			}
			if len(in.SecurityGroupIds) == 0 && len(in.SecurityGroups) == 0 {
				for _, id := range network.Groups {
					origin.Resources["security-group/"+string(id)] = true
				}
			}
		}
	}
	ctx = context.WithValue(ctx, launchTemplateAuthorizationKey{}, origin)
	if err := s.authorize(ctx, "RunInstances", "launch-template", template.Key.ID, template.Data.Tags); err != nil {
		return ctx, nil, err
	}
	return ctx, &out, nil
}
func mergeLaunchTags(base, overrides api.TagSpecificationList) api.TagSpecificationList {
	for _, spec := range overrides {
		index := -1
		for i, v := range base {
			if str(v.ResourceType) == str(spec.ResourceType) {
				index = i
				break
			}
		}
		if index < 0 {
			base = append(base, spec)
			continue
		}
		for _, tag := range spec.Tags {
			found := false
			for i, old := range base[index].Tags {
				if str(old.Key) == str(tag.Key) {
					base[index].Tags[i] = tag
					found = true
					break
				}
			}
			if !found {
				base[index].Tags = append(base[index].Tags, tag)
			}
		}
	}
	return base
}
func mergeLaunchMappings(base, overrides api.BlockDeviceMappingRequestList) api.BlockDeviceMappingRequestList {
	for n, mapping := range overrides {
		duplicate := false
		for _, earlier := range overrides[:n] {
			if str(earlier.DeviceName) == str(mapping.DeviceName) {
				duplicate = true
				break
			}
		}
		if duplicate {
			base = append(base, mapping)
			continue
		}
		index := -1
		for i, v := range base {
			if str(v.DeviceName) == str(mapping.DeviceName) {
				index = i
				break
			}
		}
		if index < 0 {
			base = append(base, mapping)
			continue
		}
		if mapping.NoDevice != nil {
			base[index] = mapping
		} else {
			api.MergeBlockDeviceMapping(&base[index], mapping)
		}
	}
	return base
}
func mergeLaunchNetworks(base, overrides api.InstanceNetworkInterfaceSpecificationList) api.InstanceNetworkInterfaceSpecificationList {
	for n, network := range overrides {
		duplicate := false
		for _, earlier := range overrides[:n] {
			if earlier.DeviceIndex != nil && network.DeviceIndex != nil && *earlier.DeviceIndex == *network.DeviceIndex {
				duplicate = true
				break
			}
		}
		if duplicate {
			base = append(base, network)
			continue
		}
		index := -1
		for i, v := range base {
			if v.DeviceIndex != nil && network.DeviceIndex != nil && *v.DeviceIndex == *network.DeviceIndex {
				index = i
				break
			}
		}
		if index < 0 {
			base = append(base, network)
			continue
		}
		api.MergeInstanceNetworkInterfaceSpecification(&base[index], network)
	}
	return base
}
func templateInstanceTags(spec *api.LaunchTemplateSpecification, tags api.TagList) api.TagList {
	if spec == nil {
		return tags
	}
	return append(tags, api.Tag{Key: new(api.String("aws:ec2launchtemplate:id")), Value: new(api.String(str(spec.LaunchTemplateId)))}, api.Tag{Key: new(api.String("aws:ec2launchtemplate:version")), Value: new(api.String(str(spec.Version)))})
}

func (s *Service) getLaunchTemplateData(ctx context.Context, tx Transaction, in *api.GetLaunchTemplateDataRequest) (*api.GetLaunchTemplateDataResult, error) {
	records, err := s.instanceCommandTargets(ctx, tx, "GetLaunchTemplateData", api.InstanceIdStringList{api.InstanceId(str(in.InstanceId))}, in.DryRun)
	if err != nil {
		return nil, err
	}
	record := records[0]
	if instanceState(record) == "terminated" {
		return nil, failure("IncorrectInstanceState", "The instance is terminated.")
	}
	conditions := map[string][]string{"ec2:InstanceType": {str(record.Data.InstanceType)}, "ec2:InstanceID": {record.Key.ID}, "ec2:Attribute": {""}}
	if record.Data.Placement != nil {
		conditions["ec2:AvailabilityZone"] = []string{str(record.Data.Placement.AvailabilityZone)}
	}
	for _, attribute := range []string{"userData", "disableApiStop", "disableApiTermination", "instanceInitiatedShutdownBehavior"} {
		conditions["ec2:Attribute"][0] = attribute
		if err := s.authorizeWith(ctx, "DescribeInstanceAttribute", "instance", record.Key.ID, record.Data.Tags, conditions); err != nil {
			return nil, err
		}
	}
	if record.Credits.Mode != "" {
		if err := s.authorize(ctx, "DescribeInstanceCreditSpecifications", "", "*", nil); err != nil {
			return nil, err
		}
	}
	if s.instanceVolumes == nil {
		return nil, unsupported("The instance volume owner is required to retrieve launch data.")
	}
	mappings, err := s.instanceVolumes.InstanceLaunchMappings(ctx, record.Data)
	if err != nil {
		return nil, err
	}
	d := api.LaunchTemplateConvertInstanceToRequestLaunchTemplateData(record.Data)
	// Read current attachments, protection flags, user data and credit controls;
	// the reservation's original input is not authoritative after modification.
	launch := api.RunInstancesRequest{BlockDeviceMappings: mappings}
	d.BlockDeviceMappings = api.LaunchTemplateConvertRunInstancesRequestToRequestLaunchTemplateData(launch).BlockDeviceMappings
	d.DisableApiStop = new(api.Boolean(record.DisableAPIStop))
	d.DisableApiTermination = new(api.Boolean(record.DisableAPITermination))
	d.InstanceInitiatedShutdownBehavior = new(api.ShutdownBehavior(record.ShutdownBehavior))
	if len(record.UserData) > 0 {
		d.UserData = new(api.SensitiveUserData(base64.StdEncoding.EncodeToString(record.UserData)))
	}
	d.Monitoring = &api.LaunchTemplatesMonitoringRequest{Enabled: new(api.Boolean(record.Data.Monitoring != nil && str(record.Data.Monitoring.State) == "enabled"))}
	if record.Credits.Mode != "" {
		d.CreditSpecification = &api.CreditSpecificationRequest{CpuCredits: new(api.String(record.Credits.Mode))}
	}
	tags := api.TagList{}
	for _, tag := range record.Data.Tags {
		if !strings.HasPrefix(str(tag.Key), "aws:") {
			tags = append(tags, tag)
		}
	}
	if len(tags) > 0 {
		d.TagSpecifications = api.LaunchTemplateTagSpecificationRequestList{{ResourceType: new(api.ResourceType("instance")), Tags: api.CloneTagList(tags)}}
	}
	for _, network := range record.Data.NetworkInterfaces {
		spec := api.LaunchTemplateInstanceNetworkInterfaceSpecificationRequest{Description: copyPointer(network.Description), InterfaceType: copyPointer(network.InterfaceType), AssociatePublicIpAddress: new(api.Boolean(network.Association != nil))}
		if network.SubnetId != nil {
			spec.SubnetId = new(api.SubnetId(*network.SubnetId))
		}
		if network.Attachment != nil {
			spec.DeviceIndex = copyPointer(network.Attachment.DeviceIndex)
			spec.NetworkCardIndex = copyPointer(network.Attachment.NetworkCardIndex)
			spec.DeleteOnTermination = copyPointer(network.Attachment.DeleteOnTermination)
		}
		for _, group := range network.Groups {
			spec.Groups = append(spec.Groups, api.SecurityGroupId(str(group.GroupId)))
		}
		for _, address := range network.PrivateIpAddresses {
			spec.PrivateIpAddresses = append(spec.PrivateIpAddresses, api.PrivateIpAddressSpecification{Primary: copyPointer(address.Primary), PrivateIpAddress: copyPointer(address.PrivateIpAddress)})
		}
		d.NetworkInterfaces = append(d.NetworkInterfaces, spec)
	}
	data := api.LaunchTemplateConvertRequestLaunchTemplateDataToResponseLaunchTemplateData(d)
	return &api.GetLaunchTemplateDataResult{LaunchTemplateData: &data}, nil
}
