package ec2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"maps"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

func registerInstances(s *Service) {
	register(s, "RunInstances", s.runInstances)
	register(s, "DescribeInstances", s.describeInstances)
	register(s, "DescribeInstanceStatus", s.describeInstanceStatus)
	register(s, "DescribeInstanceAttribute", s.describeInstanceAttribute)
	register(s, "ModifyInstanceAttribute", s.modifyInstanceAttribute)
	register(s, "ResetInstanceAttribute", s.resetInstanceAttribute)
	register(s, "StartInstances", s.startInstances)
	register(s, "StopInstances", s.stopInstances)
	register(s, "RebootInstances", s.rebootInstances)
	register(s, "TerminateInstances", s.terminateInstances)
	register(s, "MonitorInstances", s.monitorInstances)
	register(s, "UnmonitorInstances", s.unmonitorInstances)
	register(s, "GetConsoleOutput", s.getConsoleOutput)
	registerExternalOwnedCommand(s, "GetConsoleScreenshot", s.getConsoleScreenshot)
	register(s, "ModifyInstanceMetadataOptions", s.modifyInstanceMetadataOptions)
	register(s, "AttachVolume", s.attachVolume)
	register(s, "DetachVolume", s.detachVolume)
}

func validateInstanceLaunch(in *api.RunInstancesRequest) error {
	if str(in.ImageId) == "" {
		return failure("MissingParameter", "The request must contain the parameter ImageId")
	}
	if in.MinCount == nil || *in.MinCount <= 0 {
		return failure("InvalidParameterValue", "Minimum instance count must be greater than zero")
	}
	if in.MaxCount == nil || *in.MaxCount <= 0 {
		return failure("InvalidParameterValue", "Maximum instance count must be greater than zero")
	}
	if *in.MaxCount < *in.MinCount {
		return failure("InvalidParameterValue", "Maximum instance count must not be smaller than minimum instance count")
	}
	if len(str(in.ClientToken)) > 64 {
		return failure("InvalidParameterValue", "Client token must be less than or equal to 64 characters")
	}
	for _, c := range str(in.ClientToken) {
		if c < 32 || c > 126 {
			return failure("InvalidParameterValue", "Client token must contain only ASCII printable characters")
		}
	}
	if in.AdditionalInfo != nil || in.CapacityReservationSpecification != nil || len(in.ElasticGpuSpecification) > 0 || len(in.ElasticInferenceAccelerators) > 0 || in.EnablePrimaryIpv6 != nil || in.EnclaveOptions != nil || in.InstanceMarketOptions != nil || in.Ipv6AddressCount != nil || len(in.Ipv6Addresses) > 0 || in.KernelId != nil || len(in.LicenseSpecifications) > 0 || in.MaintenanceOptions != nil || in.NetworkPerformanceOptions != nil || in.Operator != nil || in.PrivateDnsNameOptions != nil || in.RamdiskId != nil || len(in.SecondaryInterfaces) > 0 || len(in.SecurityGroups) > 0 {
		// TODO: Comeback implement fleet/market/capacity placement, IPv6 and
		// specialty guest hardware with real backends.
		return unsupported("The request contains unsupported launch, placement or guest hardware options.")
	}
	if boolValue(in.EbsOptimized) {
		return unsupported("EBS performance guarantees are not implemented.")
	}
	if p := in.Placement; p != nil {
		if p.Affinity != nil || p.GroupId != nil || p.GroupName != nil || p.HostId != nil || p.HostResourceGroupArn != nil || p.PartitionNumber != nil || p.SpreadDomain != nil || (p.Tenancy != nil && str(p.Tenancy) != "default") {
			return unsupported("Only ordinary shared-tenancy placement is supported.")
		}
	}
	if c := in.CpuOptions; c != nil && (c.AmdSevSnp != nil || c.NestedVirtualization != nil) {
		return unsupported("SEV-SNP and nested virtualization are not implemented.")
	}
	if in.InstanceInitiatedShutdownBehavior != nil && str(in.InstanceInitiatedShutdownBehavior) != "stop" && str(in.InstanceInitiatedShutdownBehavior) != "terminate" {
		return failure("InvalidParameterValue", "Invalid instance initiated shutdown behavior.")
	}
	return nil
}

func instanceLaunchTags(specs api.TagSpecificationList) (map[string]api.TagList, error) {
	out := map[string]api.TagList{}
	for _, spec := range specs {
		kind := str(spec.ResourceType)
		if kind != "instance" && kind != "volume" && kind != "network-interface" {
			return nil, failure("InvalidParameterValue", "Unsupported RunInstances tag resource type.")
		}
		if _, ok := out[kind]; ok {
			return nil, failure("InvalidParameterValue", "Duplicate tag specification.")
		}
		tags, err := CreationTags(api.TagSpecificationList{spec}, kind)
		if err != nil {
			return nil, err
		}
		out[kind] = tags
	}
	return out, nil
}

func (s *Service) runInstances(ctx context.Context, tx Transaction, in *api.RunInstancesRequest) (*api.Reservation, error) {
	var err error
	ctx, in, err = s.resolveLaunchTemplate(ctx, tx, in)
	if err != nil {
		return nil, err
	}
	if _, managed := ctx.Value(lambdaManagedLaunchKey{}).(string); managed {
		for _, attachment := range in.NetworkInterfaces {
			if attachment.NetworkInterfaceId != nil {
				return nil, unsupported("Lambda managed launches require newly allocated network interfaces.")
			}
		}
	}
	if err := validateInstanceLaunch(in); err != nil {
		return nil, err
	}
	image, err := resolveLaunchImage(ctx, tx, str(in.ImageId))
	if err != nil {
		return nil, err
	}
	if str(image.Data.RootDeviceType) != "ebs" || str(image.Data.VirtualizationType) != "hvm" || (str(image.Data.Platform) != "" && str(image.Data.Platform) != "linux") {
		return nil, unsupported("Only Linux HVM EBS-backed images are supported.")
	}
	metadata, err := launchMetadataOptions(image.Data, in.MetadataOptions)
	if err != nil {
		return nil, err
	}
	tags, err := instanceLaunchTags(in.TagSpecifications)
	if err != nil {
		return nil, err
	}
	if str(metadata.InstanceMetadataTags) == "enabled" {
		if err := validateMetadataTags(tags["instance"]); err != nil {
			return nil, err
		}
	}
	if s.instanceVolumes == nil || s.instanceTypes == nil {
		return nil, unsupported("An EBS owner and instance-type catalog are required.")
	}
	instanceType := api.InstanceType(str(in.InstanceType))
	if instanceType == "" {
		return nil, failure("MissingParameter", "An instance type is required by the configured native backend.")
	}
	typ, err := s.instanceTypes.ResolveInstanceType(ctx, instanceType)
	if err != nil {
		return nil, err
	}
	cpu, err := instanceCPU(typ, in.CpuOptions)
	if err != nil {
		return nil, err
	}
	credits, err := s.admitInstanceCredits(ctx, instanceType, in.CreditSpecification)
	if err != nil {
		return nil, err
	}
	if typ.ProcessorInfo == nil || !slices.Contains(typ.ProcessorInfo.SupportedArchitectures, api.ArchitectureType(str(image.Data.Architecture))) {
		return nil, failure("InvalidParameterValue", "The image architecture does not match the instance type.")
	}
	networkPlan, err := s.planInstanceNetwork(ctx, tx, in, tags["network-interface"])
	if err != nil {
		return nil, err
	}
	zone := str(networkPlan.subnet.Data.AvailabilityZone)
	volumeZone := AvailabilityZone{Name: zone, ID: str(networkPlan.subnet.Data.AvailabilityZoneId)}
	if in.Placement != nil && in.Placement.AvailabilityZoneId != nil && str(in.Placement.AvailabilityZoneId) != str(networkPlan.subnet.Data.AvailabilityZoneId) {
		return nil, failure("InvalidParameterValue", "The subnet and availability zone ID do not match.")
	}
	plan, err := s.instanceVolumes.PlanInstanceVolumes(ctx, image.Data, in.BlockDeviceMappings, volumeZone)
	if err != nil {
		return nil, err
	}
	hibernation := in.HibernationOptions != nil && boolValue(in.HibernationOptions.Configured)
	if hibernation {
		if err := admitInstanceHibernation(image.Data, typ, plan); err != nil {
			return nil, err
		}
	}
	var profile *api.IamInstanceProfile
	if in.IamInstanceProfile != nil {
		if s.instanceProfiles == nil {
			return nil, unsupported("IAM instance-profile credentials are not configured.")
		}
		resolved, err := s.instanceProfiles.ResolveInstanceProfile(ctx, *in.IamInstanceProfile)
		if err != nil {
			return nil, err
		}
		if len(resolved.Roles) != 1 {
			return nil, failure("InvalidParameterValue", "The instance profile must contain exactly one role.")
		}
		now := s.clock.Now()
		if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: str(resolved.Roles[0].Arn), ResourceAccountID: scopeFor(ctx).AccountID, Context: map[string][]string{"iam:PassedToService": {"ec2.amazonaws.com"}}, EvaluationTime: &now}); denied != nil {
			return nil, denied
		}
		profile = &api.IamInstanceProfile{Arn: new(api.String(str(resolved.Arn))), Id: new(api.String(str(resolved.InstanceProfileId)))}
	}
	conditions := map[string][]string{"ec2:InstanceType": {string(instanceType)}, "ec2:AvailabilityZone": {zone}, "ec2:Tenancy": {"default"}, "ec2:MetadataHttpTokens": {str(metadata.HttpTokens)}, "ec2:MetadataHttpEndpoint": {str(metadata.HttpEndpoint)}, "ec2:MetadataHttpPutResponseHopLimit": {strconv.Itoa(int(*metadata.HttpPutResponseHopLimit))}, "ec2:InstanceMetadataTags": {str(metadata.InstanceMetadataTags)}, "ec2:RootDeviceType": {"ebs"}, "ec2:ImageID": {image.Key.ID}}
	conditions["ec2:Vpc"] = []string{resourceARN(networkPlan.subnet.Key.Scope, "vpc", str(networkPlan.subnet.Data.VpcId))}
	conditions["ec2:Subnet"] = []string{resourceARN(networkPlan.subnet.Key.Scope, "subnet", networkPlan.subnet.Key.ID)}
	conditions["ec2:AvailabilityZoneId"] = []string{str(networkPlan.subnet.Data.AvailabilityZoneId)}
	if in.KeyName != nil {
		conditions["ec2:KeyPairName"] = []string{str(in.KeyName)}
	}
	if profile != nil {
		conditions["ec2:InstanceProfile"] = []string{str(profile.Arn)}
	}
	if err := s.authorizeImage(ctx, "RunInstances", image, nil); err != nil {
		return nil, err
	}
	if err := s.authorizeCreateWith(ctx, "RunInstances", "instance", "*", tags["instance"], maps.Clone(conditions)); err != nil {
		return nil, err
	}
	for _, mapping := range plan {
		if mapping.Ebs == nil {
			return nil, unsupported("Only EBS block device mappings are supported.")
		}
		c := maps.Clone(conditions)
		c["ec2:Encrypted"] = []string{strconv.FormatBool(boolValue(mapping.Ebs.Encrypted))}
		c["ec2:VolumeType"] = []string{str(mapping.Ebs.VolumeType)}
		if mapping.Ebs.VolumeSize != nil {
			c["ec2:VolumeSize"] = []string{strconv.Itoa(int(*mapping.Ebs.VolumeSize))}
		}
		if str(mapping.Ebs.SnapshotId) != "" {
			c["ec2:ParentSnapshot"] = []string{resourceARN(scopeFor(ctx), "snapshot", str(mapping.Ebs.SnapshotId))}
		}
		if err := s.authorizeCreateWith(ctx, "RunInstances", "volume", "*", tags["volume"], c); err != nil {
			return nil, err
		}
	}
	publicKey := ""
	if in.KeyName != nil {
		pair, err := keyPairByName(ctx, tx, str(in.KeyName))
		if err != nil {
			return nil, err
		}
		if err := s.authorizeWith(ctx, "RunInstances", "key-pair", pair.Key.ID, pair.Data.Tags, keyPairConditions(pair.Data)); err != nil {
			return nil, err
		}
		publicKey = str(pair.Data.PublicKey)
	}
	userData, err := base64.StdEncoding.DecodeString(str(in.UserData))
	if err != nil {
		return nil, failure("InvalidParameterValue", "Invalid BASE64 encoding of user data.")
	}
	if len(userData) > 16*1024 {
		return nil, failure("InvalidParameterValue", "User data exceeds 16384 bytes.")
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	// DryRun validates authoritative control-plane state without executing a
	// guest. Real launches still require an explicit backend before any effects.
	if s.instanceRuntime == nil {
		return nil, unsupported("An explicit native instance backend is required.")
	}
	tokenZone := ""
	if in.SubnetId != nil || len(in.NetworkInterfaces) > 0 || (in.Placement != nil && (in.Placement.AvailabilityZone != nil || in.Placement.AvailabilityZoneId != nil)) {
		tokenZone = zone
	}
	if previous, err := retainedReservation(ctx, tx, in, tokenZone); err != nil || previous != nil {
		return previous, err
	}
	count := int(*in.MaxCount)
	if networkPlan.existing == nil && networkPlan.subnet.Data.AvailableIpAddressCount != nil {
		count = min(count, int(*networkPlan.subnet.Data.AvailableIpAddressCount))
	}
	if count < int(*in.MinCount) {
		return nil, failure("InsufficientFreeAddressesInSubnet", "The subnet has insufficient free addresses.")
	}
	if count > 1 && networkPlan.spec.PrivateIpAddress != nil {
		return nil, failure("InvalidParameterCombination", "A private IP address may be specified for only one instance.")
	}
	reservationID, err := tx.NextID(scopeFor(ctx), "r")
	if err != nil {
		return nil, err
	}
	reservation := ReservationRecord{Key: key(ctx, reservationID), Input: reservationInput(in), ClientToken: str(in.ClientToken), TokenZone: tokenZone}
	actor := awsctx.FromContext(ctx)
	reservation.LaunchPrincipalARN, reservation.LaunchPrincipalID = actor.PrincipalARN, actor.PrincipalID
	monitoringState := api.MonitoringState("disabled")
	if in.Monitoring != nil && boolValue(in.Monitoring.Enabled) {
		monitoringState = "enabled"
	}
	for index := range count {
		id, err := tx.NextID(scopeFor(ctx), "i")
		if err != nil {
			return nil, err
		}
		eni, err := s.admitInstanceNetwork(ctx, tx, id, networkPlan, tags["network-interface"])
		if err != nil {
			return nil, err
		}
		mappings, err := s.instanceVolumes.AdmitInstanceVolumes(ctx, id, volumeZone, plan, tags["volume"])
		if err != nil {
			return nil, err
		}
		behavior := str(in.InstanceInitiatedShutdownBehavior)
		if behavior == "" {
			behavior = "stop"
		}
		launchedAt := s.clock.Now()
		record := InstanceRecord{Key: key(ctx, id), ReservationID: reservationID, UserData: slices.Clone(userData), PublicKey: publicKey, ShutdownBehavior: behavior, DisableAPIStop: boolValue(in.DisableApiStop), DisableAPITermination: boolValue(in.DisableApiTermination), Generation: 1, Intent: InstanceIntentStart, NextActionAt: launchedAt, IdentityInfoLastUpdated: launchedAt}
		if providerARN, managed := ctx.Value(lambdaManagedLaunchKey{}).(string); managed {
			record.LambdaCapacityProviderARN, record.LambdaManagedGeneration = providerARN, str(in.ClientToken)
		}
		record.Credits = credits
		record.MetadataTokenKey = make([]byte, 32)
		if _, err := rand.Read(record.MetadataTokenKey); err != nil {
			return nil, err
		}
		instanceTags, err := s.autoScalingInstanceTags(ctx, id, templateInstanceTags(in.LaunchTemplate, api.CloneTagList(tags["instance"])))
		if err != nil {
			return nil, err
		}
		record.Data = api.Instance{
			InstanceId: new(api.String(id)), ImageId: new(api.String(image.Key.ID)), InstanceType: new(instanceType),
			AmiLaunchIndex: new(api.Integer(index)), LaunchTime: new(api.DateTime(launchedAt)),
			Architecture: image.Data.Architecture, RootDeviceType: image.Data.RootDeviceType, RootDeviceName: image.Data.RootDeviceName,
			VirtualizationType: image.Data.VirtualizationType, BootMode: image.Data.BootMode, EnaSupport: image.Data.EnaSupport,
			BlockDeviceMappings: mappings, MetadataOptions: metadata, IamInstanceProfile: profile,
			KeyName: new(api.String(str(in.KeyName))), ClientToken: new(api.String(str(in.ClientToken))), CpuOptions: cpu,
			Placement: &api.Placement{AvailabilityZone: new(api.String(zone)), AvailabilityZoneId: new(api.AvailabilityZoneId(str(networkPlan.subnet.Data.AvailabilityZoneId))), Tenancy: new(api.Tenancy("default"))},
			SubnetId:  eni.SubnetId, VpcId: eni.VpcId, PrivateIpAddress: eni.PrivateIpAddress, PrivateDnsName: new(api.String(privateDNSName(scopeFor(ctx), str(eni.PrivateIpAddress)))),
			NetworkInterfaces: api.InstanceNetworkInterfaceList{eni}, SecurityGroups: eni.Groups, SourceDestCheck: new(api.Boolean(true)),
			Tags: instanceTags, Monitoring: &api.Monitoring{State: new(monitoringState)}, EbsOptimized: new(api.Boolean(false)),
			HibernationOptions: &api.HibernationOptions{Configured: new(api.Boolean(hibernation))},
		}
		record.Data.Operator = lambdaInstanceOperator(record)
		captureMetadataBlockDevices(&record)
		setInstanceCommand(ctx, &record)
		if err := s.changeInstanceState(ctx, tx, &record, "pending"); err != nil {
			return nil, err
		}
		if profile != nil {
			if _, err := s.admitInstanceProfileAssociation(ctx, tx, &record, profile); err != nil {
				return nil, err
			}
		}
		reservation.InstanceIDs = append(reservation.InstanceIDs, id)
	}
	if err := tx.PutReservation(reservation); err != nil {
		return nil, err
	}
	return reservationResult(ctx, tx, reservation)
}

func instanceCPU(typ api.InstanceTypeInfo, options *api.CpuOptionsRequest) (*api.CpuOptions, error) {
	if typ.VCpuInfo == nil || typ.VCpuInfo.DefaultCores == nil || typ.VCpuInfo.DefaultThreadsPerCore == nil || typ.MemoryInfo == nil || typ.MemoryInfo.SizeInMiB == nil {
		return nil, unsupported("The instance type lacks retained CPU and memory facts.")
	}
	cores, threads := int32(*typ.VCpuInfo.DefaultCores), int32(*typ.VCpuInfo.DefaultThreadsPerCore)
	if options != nil {
		if options.CoreCount != nil {
			cores = int32(*options.CoreCount)
			if !slices.Contains(typ.VCpuInfo.ValidCores, api.CoreCount(cores)) {
				return nil, failure("InvalidParameterValue", "Unsupported CPU core count.")
			}
		}
		if options.ThreadsPerCore != nil {
			threads = int32(*options.ThreadsPerCore)
			if !slices.Contains(typ.VCpuInfo.ValidThreadsPerCore, api.ThreadsPerCore(threads)) {
				return nil, failure("InvalidParameterValue", "Unsupported threads per core.")
			}
		}
	}
	if cores <= 0 || threads <= 0 || *typ.MemoryInfo.SizeInMiB <= 0 {
		return nil, unsupported("The instance type has invalid retained runtime dimensions.")
	}
	return &api.CpuOptions{CoreCount: new(api.Integer(cores)), ThreadsPerCore: new(api.Integer(threads))}, nil
}

func validateMetadataTags(tags api.TagList) error {
	for _, tag := range tags {
		k := str(tag.Key)
		if k == "." || k == ".." || k == "_index" {
			return failure("InvalidParameterValue", "Tag key is not valid for instance metadata.")
		}
		for _, r := range k {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("+-=.,_:@", r)) {
				return failure("InvalidParameterValue", "Tag key is not valid for instance metadata.")
			}
		}
	}
	return nil
}
