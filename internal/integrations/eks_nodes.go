package integrations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	native "stackd/compute/eks"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	asgapi "stackd/internal/awsapi/autoscaling"
	ec2api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	asg "stackd/internal/services/autoscaling"
	eks "stackd/internal/services/eks"
)

const eksNodePrincipal = "eks-nodegroup.amazonaws.com"
const eksNodeRoleName = "AWSServiceRoleForAmazonEKSNodegroup"
const eksDrainHook = "eks-managed-drain"

type EKSNodeCommands interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}
type EKSNodeIAM interface {
	EKSNodeCommands
	EnsureServiceLinkedRole(context.Context, string) error
	ResolvePrincipal(context.Context, string) (authorization.Principal, error)
}

type EKSNodeAutoScaling interface {
	EKSNodeCommands
	ManagedScaling(context.Context, string, string) (asg.ManagedScalingState, error)
	UpdateManagedScaling(context.Context, string, string, uint64, int32, int32) error
}

// EKSNodes owns no EC2/ASG inventory or IAM sessions. Those remain with the
// existing owners; every effect enters their ordinary current-authority APIs.
type EKSNodes struct {
	EC2         EKSNodeCommands
	AutoScaling EKSNodeAutoScaling
	IAM         EKSNodeIAM
	Roles       ServiceRoles
	Images      map[string]native.NodeImage
	sessions    serviceRoleSessions
}

func (a *EKSNodes) nodeContext(ctx context.Context, n eks.Nodegroup) (context.Context, error) {
	m := awsctx.FromContext(ctx)
	m.Partition = n.Key.Cluster.Partition
	m.AccountID = n.Key.Cluster.AccountID
	m.Region = n.Key.Cluster.Region
	ctx = awsctx.WithMetadata(ctx, m)
	role := "arn:" + m.Partition + ":iam::" + m.AccountID + ":role/aws-service-role/" + eksNodePrincipal + "/" + eksNodeRoleName
	return a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: eksNodePrincipal, SourceARN: n.Key.ARN(n.ID), Type: "AWSService"}, role, "EKSNodegroup", "")
}
func eksNodeCommandContext(ctx context.Context) context.Context {
	m := awsctx.FromContext(ctx)
	m.RequestID = uuid.NewString()
	m.InvokedBy = eksNodePrincipal
	return awsctx.WithViaService(awsctx.WithMetadata(ctx, m), eksNodePrincipal)
}

func eksNodeCall[T any](ctx context.Context, owner EKSNodeCommands, service, action string, in any) (*T, error) {
	if owner == nil {
		return nil, errors.New("eks: " + service + " owner is not configured")
	}
	ctx = eksNodeCommandContext(ctx)
	model, ok := awscatalog.LookupService(service)
	if !ok {
		return nil, errors.New("eks: generated service contract unavailable")
	}
	op, ok := model.Operation(action)
	if !ok {
		return nil, errors.New("eks: generated operation contract unavailable")
	}
	out, rejected := owner.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: in})
	if rejected != nil {
		return nil, rejected
	}
	result, ok := out.(*T)
	if !ok {
		return nil, fmt.Errorf("eks: invalid %s %s response", service, action)
	}
	return result, nil
}
func nodeValue[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func nodeErrorCode(err error, code string) bool {
	var wire *awswire.Error
	return errors.As(err, &wire) && wire.Code == code
}
func nodeInvalid(message string) error {
	return &awswire.Error{Code: "InvalidParameterException", StatusCode: 400, Message: message}
}
func (a *EKSNodes) Admit(ctx context.Context, c eks.Cluster, n *eks.Nodegroup) (bool, error) {
	if a.IAM == nil || a.EC2 == nil || a.AutoScaling == nil {
		return false, errors.New("eks: IAM, EC2 and Auto Scaling owners are required")
	}
	if err := a.IAM.EnsureServiceLinkedRole(ctx, eksNodePrincipal); err != nil {
		return false, err
	}
	current, err := a.IAM.ResolvePrincipal(ctx, n.NodeRoleARN)
	if err != nil {
		return false, err
	}
	if current.ID != n.NodeRoleID {
		return false, nodeInvalid("The node IAM role incarnation changed.")
	}
	service, err := a.nodeContext(ctx, *n)
	if err != nil {
		return false, err
	}
	subnets := make(ec2api.SubnetIdStringList, len(n.Subnets))
	for i, v := range n.Subnets {
		subnets[i] = ec2api.SubnetId(v)
	}
	placement, err := eksNodeCall[ec2api.DescribeSubnetsResult](service, a.EC2, "ec2", "DescribeSubnets", &ec2api.DescribeSubnetsRequest{SubnetIds: subnets})
	if err != nil {
		return false, err
	}
	if len(placement.Subnets) != len(n.Subnets) {
		return false, nodeInvalid("A nodegroup subnet does not exist.")
	}
	for _, subnet := range placement.Subnets {
		if nodeValue(subnet.VpcId) != c.VPCID {
			return false, nodeInvalid("Nodegroup subnets must belong to the cluster VPC.")
		}
	}
	customImage := false
	if n.LaunchTemplateID != "" || n.LaunchTemplateName != "" {
		v, err := a.sourceTemplate(service, *n)
		if err != nil {
			return false, err
		}
		d := v.LaunchTemplateData
		if d == nil {
			return false, nodeInvalid("Launch template contains no launch data.")
		}
		if d.IamInstanceProfile != nil {
			return false, nodeInvalid("An instance profile cannot be specified in a nodegroup launch template.")
		}
		for _, network := range d.NetworkInterfaces {
			if network.SubnetId != nil || network.NetworkInterfaceId != nil {
				return false, nodeInvalid("A nodegroup launch template cannot specify subnet or existing network-interface IDs.")
			}
		}
		if n.TemplateGeneration == 1 && len(n.InstanceTypes) > 0 && d.InstanceType != nil {
			return false, nodeInvalid("Instance type cannot be specified both in the nodegroup and launch template.")
		}
		if d.ImageId != nil {
			customImage = true
			n.ImageID = nodeValue(d.ImageId)
			n.AmiType = "CUSTOM"
		}
		if d.InstanceType != nil {
			n.InstanceTypes = []string{nodeValue(d.InstanceType)}
		}
		n.LaunchTemplateID = nodeValue(v.LaunchTemplateId)
		n.LaunchTemplateName = nodeValue(v.LaunchTemplateName)
		if v.VersionNumber == nil {
			return false, errors.New("eks: launch-template version is absent")
		}
		n.LaunchTemplateVersion = strconv.FormatInt(int64(*v.VersionNumber), 10)
	}
	if !customImage {
		image, ok := a.Images[n.Version]
		if !ok || image.ImageID == "" {
			return false, nodeInvalid("No imported firmware worker image is configured for Kubernetes " + n.Version + "; supply a compatible custom launch template.")
		}
		if n.ReleaseVersion != "" && n.ReleaseVersion != image.ReleaseVersion {
			return false, nodeInvalid("The requested worker image release is not configured.")
		}
		n.ImageID = image.ImageID
		n.ReleaseVersion = image.ReleaseVersion
		n.AmiType = image.AmiType
	}
	if len(n.InstanceTypes) == 0 {
		n.InstanceTypes = []string{"t3.medium"}
	}
	if n.GroupARN != "" {
		group, _, err := a.group(service, *n)
		if err != nil {
			return false, err
		}
		if group != nil && group.MinSize != nil && group.MaxSize != nil && group.DesiredCapacity != nil {
			n.MinSize, n.MaxSize, n.DesiredSize = int32(*group.MinSize), int32(*group.MaxSize), int32(*group.DesiredCapacity)
		}
	}
	return customImage, nil
}
func (a *EKSNodes) sourceTemplate(ctx context.Context, n eks.Nodegroup) (ec2api.LaunchTemplateVersion, error) {
	in := &ec2api.DescribeLaunchTemplateVersionsRequest{}
	if n.LaunchTemplateID != "" {
		in.LaunchTemplateId = new(ec2api.LaunchTemplateId(n.LaunchTemplateID))
	} else {
		in.LaunchTemplateName = new(ec2api.LaunchTemplateName(n.LaunchTemplateName))
	}
	version := n.LaunchTemplateVersion
	if version == "" {
		version = "$Default"
	}
	in.Versions = ec2api.VersionStringList{ec2api.String(version)}
	out, e := eksNodeCall[ec2api.DescribeLaunchTemplateVersionsResult](ctx, a.EC2, "ec2", "DescribeLaunchTemplateVersions", in)
	if e != nil {
		return ec2api.LaunchTemplateVersion{}, e
	}
	if len(out.LaunchTemplateVersions) != 1 {
		return ec2api.LaunchTemplateVersion{}, errors.New("eks: selected launch-template version is absent")
	}
	return out.LaunchTemplateVersions[0], nil
}
func (a *EKSNodes) ensureProfile(ctx context.Context, n eks.Nodegroup) error {
	out, e := eksNodeCall[iamapi.GetInstanceProfileResponse](ctx, a.IAM, "iam", "GetInstanceProfile", &iamapi.GetInstanceProfileRequest{InstanceProfileName: new(iamapi.InstanceProfileNameType(n.ProfileName))})
	if nodeErrorCode(e, "NoSuchEntity") {
		_, e = eksNodeCall[iamapi.CreateInstanceProfileResponse](ctx, a.IAM, "iam", "CreateInstanceProfile", &iamapi.CreateInstanceProfileRequest{InstanceProfileName: new(iamapi.InstanceProfileNameType(n.ProfileName))})
		if e != nil {
			return e
		}
		out, e = eksNodeCall[iamapi.GetInstanceProfileResponse](ctx, a.IAM, "iam", "GetInstanceProfile", &iamapi.GetInstanceProfileRequest{InstanceProfileName: new(iamapi.InstanceProfileNameType(n.ProfileName))})
	}
	if e != nil {
		return e
	}
	if out.InstanceProfile == nil {
		return errors.New("eks: instance profile response is absent")
	}
	expected := "arn:" + n.Key.Cluster.Partition + ":iam::" + n.Key.Cluster.AccountID + ":instance-profile/" + n.ProfileName
	if nodeValue(out.InstanceProfile.Arn) != expected {
		return errors.New("eks: instance profile ownership mismatch")
	}
	if len(out.InstanceProfile.Roles) > 0 {
		if len(out.InstanceProfile.Roles) != 1 || nodeValue(out.InstanceProfile.Roles[0].Arn) != n.NodeRoleARN || nodeValue(out.InstanceProfile.Roles[0].RoleId) != n.NodeRoleID {
			return errors.New("eks: instance profile role incarnation mismatch")
		}
		return nil
	}
	role := n.NodeRoleARN[strings.LastIndex(n.NodeRoleARN, "/")+1:]
	_, e = eksNodeCall[iamapi.AddRoleToInstanceProfileOutput](ctx, a.IAM, "iam", "AddRoleToInstanceProfile", &iamapi.AddRoleToInstanceProfileRequest{InstanceProfileName: new(iamapi.InstanceProfileNameType(n.ProfileName)), RoleName: new(iamapi.RoleNameType(role))})
	return e
}
func (a *EKSNodes) managedTemplate(ctx context.Context, c eks.Cluster, n eks.Nodegroup, b native.WorkerBootstrap) (string, string, error) {
	// Stable incarnation names and generation descriptions recover an accepted
	// owner command when the EKS completion transaction did not commit.
	marker := n.ID + ":" + strconv.FormatInt(n.TemplateGeneration, 10)
	existing, e := eksNodeCall[ec2api.DescribeLaunchTemplatesResult](ctx, a.EC2, "ec2", "DescribeLaunchTemplates", &ec2api.DescribeLaunchTemplatesRequest{LaunchTemplateNames: ec2api.LaunchTemplateNameStringList{ec2api.LaunchTemplateName(n.GroupName)}})
	templateID := ""
	if e == nil {
		if len(existing.LaunchTemplates) != 1 {
			return "", "", errors.New("eks: ambiguous managed launch template")
		}
		t := existing.LaunchTemplates[0]
		if !slices.ContainsFunc(t.Tags, func(t ec2api.Tag) bool {
			return nodeValue(t.Key) == "eks:nodegroup-name" && nodeValue(t.Value) == n.Key.Name
		}) || !slices.ContainsFunc(t.Tags, func(t ec2api.Tag) bool { return nodeValue(t.Key) == "eks" && nodeValue(t.Value) == n.ID }) {
			return "", "", errors.New("eks: refusing unowned launch template")
		}
		templateID = nodeValue(t.LaunchTemplateId)
		query := &ec2api.DescribeLaunchTemplateVersionsRequest{LaunchTemplateId: new(ec2api.LaunchTemplateId(templateID))}
		for {
			versions, err := eksNodeCall[ec2api.DescribeLaunchTemplateVersionsResult](ctx, a.EC2, "ec2", "DescribeLaunchTemplateVersions", query)
			if err != nil {
				return "", "", err
			}
			for _, v := range versions.LaunchTemplateVersions {
				if nodeValue(v.VersionDescription) == marker && v.VersionNumber != nil {
					return templateID, strconv.FormatInt(int64(*v.VersionNumber), 10), nil
				}
			}
			if versions.NextToken == nil {
				break
			}
			query.NextToken = versions.NextToken
		}
	} else if !nodeErrorCode(e, "InvalidLaunchTemplateName.NotFoundException") && !nodeErrorCode(e, "InvalidLaunchTemplateName.NotFound") {
		return "", "", e
	}
	data := ec2api.RequestLaunchTemplateData{}
	if n.LaunchTemplateID != "" {
		source, e := a.sourceTemplate(ctx, n)
		if e != nil {
			return "", "", e
		}
		raw, e := json.Marshal(source.LaunchTemplateData)
		if e != nil {
			return "", "", e
		}
		if e = json.Unmarshal(raw, &data); e != nil {
			return "", "", e
		}
	}
	data.ImageId = new(ec2api.ImageId(n.ImageID))
	if data.InstanceType == nil {
		data.InstanceType = new(ec2api.InstanceType(n.InstanceTypes[0]))
	}
	data.IamInstanceProfile = &ec2api.LaunchTemplateIamInstanceProfileSpecificationRequest{Name: new(ec2api.String(n.ProfileName))}
	if len(data.SecurityGroupIds) == 0 && len(data.NetworkInterfaces) == 0 {
		for _, g := range c.SecurityGroups {
			data.SecurityGroupIds = append(data.SecurityGroupIds, ec2api.SecurityGroupId(g))
		}
	}
	if n.DiskSize > 0 {
		data.BlockDeviceMappings = ec2api.LaunchTemplateBlockDeviceMappingRequestList{{DeviceName: new(ec2api.String("/dev/sda1")), Ebs: &ec2api.LaunchTemplateEbsBlockDeviceRequest{VolumeSize: new(ec2api.Integer(n.DiskSize)), DeleteOnTermination: new(ec2api.Boolean(true)), VolumeType: new(ec2api.VolumeType("gp3"))}}}
	}
	if data.MetadataOptions == nil {
		data.MetadataOptions = &ec2api.LaunchTemplateInstanceMetadataOptionsRequest{HttpTokens: new(ec2api.LaunchTemplateHttpTokensState("required")), HttpPutResponseHopLimit: new(ec2api.Integer(2))}
	}
	userdata, e := eksWorkerUserData(n, b, nodeValue(data.UserData))
	if e != nil {
		return "", "", e
	}
	data.UserData = new(ec2api.SensitiveUserData(userdata))
	if templateID == "" {
		out, e := eksNodeCall[ec2api.CreateLaunchTemplateResult](ctx, a.EC2, "ec2", "CreateLaunchTemplate", &ec2api.CreateLaunchTemplateRequest{LaunchTemplateName: new(ec2api.String(n.GroupName)), ClientToken: new(ec2api.String(marker)), LaunchTemplateData: &data, VersionDescription: new(ec2api.VersionDescription(marker)), TagSpecifications: ec2api.TagSpecificationList{{ResourceType: new(ec2api.ResourceType("launch-template")), Tags: ec2api.TagList{{Key: new(ec2api.String("eks")), Value: new(ec2api.String(n.ID))}, {Key: new(ec2api.String("eks:nodegroup-name")), Value: new(ec2api.String(n.Key.Name))}, {Key: new(ec2api.String("eks:cluster-name")), Value: new(ec2api.String(n.Key.Cluster.Name))}}}}})
		if e != nil {
			return "", "", e
		}
		if out.LaunchTemplate == nil {
			return "", "", errors.New("eks: created launch template is absent")
		}
		return nodeValue(out.LaunchTemplate.LaunchTemplateId), "1", nil
	}
	out, e := eksNodeCall[ec2api.CreateLaunchTemplateVersionResult](ctx, a.EC2, "ec2", "CreateLaunchTemplateVersion", &ec2api.CreateLaunchTemplateVersionRequest{LaunchTemplateId: new(ec2api.LaunchTemplateId(templateID)), ClientToken: new(ec2api.String(marker)), LaunchTemplateData: &data, VersionDescription: new(ec2api.VersionDescription(marker))})
	if e != nil {
		return "", "", e
	}
	if out.LaunchTemplateVersion == nil || out.LaunchTemplateVersion.VersionNumber == nil {
		return "", "", errors.New("eks: created launch-template version is absent")
	}
	return templateID, strconv.FormatInt(int64(*out.LaunchTemplateVersion.VersionNumber), 10), nil
}
func (a *EKSNodes) Reconcile(ctx context.Context, c eks.Cluster, n eks.Nodegroup, b native.WorkerBootstrap, capacity int32) (eks.NodegroupObservation, error) {
	ctx, e := a.nodeContext(ctx, n)
	if e != nil {
		return eks.NodegroupObservation{}, e
	}
	if n.Operation == "VersionUpdate" && n.UpdateStrategy != "MINIMAL" && n.ScaleDownStarted {
		maximum := n.MaxSize + max(capacity-n.DesiredSize, 0)
		err := a.AutoScaling.UpdateManagedScaling(eksNodeCommandContext(ctx), n.GroupName, n.GroupARN, n.ScaleDownScaleUpVersion, capacity, maximum)
		if err != nil && !errors.Is(err, asg.ErrManagedScaleUp) {
			return eks.NodegroupObservation{}, err
		}
		return a.observe(ctx, n)
	}
	if e = a.ensureProfile(ctx, n); e != nil {
		return eks.NodegroupObservation{}, e
	}
	id, version, e := a.managedTemplate(ctx, c, n, b)
	if e != nil {
		return eks.NodegroupObservation{}, e
	}
	group, _, e := a.group(ctx, n)
	if e != nil {
		return eks.NodegroupObservation{}, e
	}
	if group != nil && n.Operation == "" && group.MinSize != nil && group.MaxSize != nil && group.DesiredCapacity != nil {
		n.MinSize, n.MaxSize, n.DesiredSize = int32(*group.MinSize), int32(*group.MaxSize), int32(*group.DesiredCapacity)
		capacity = n.DesiredSize
	}
	lt := &asgapi.LaunchTemplateSpecification{LaunchTemplateId: new(asgapi.XmlStringMaxLen255(id)), Version: new(asgapi.XmlStringMaxLen255(version))}
	maximum := n.MaxSize + max(capacity-n.DesiredSize, 0)
	if group == nil {
		_, e = eksNodeCall[asgapi.CreateAutoScalingGroupOutput](ctx, a.AutoScaling, "autoscaling", "CreateAutoScalingGroup", &asgapi.CreateAutoScalingGroupInput{AutoScalingGroupName: new(asgapi.XmlStringMaxLen255(n.GroupName)), LaunchTemplate: lt, MinSize: new(asgapi.AutoScalingGroupMinSize(n.MinSize)), MaxSize: new(asgapi.AutoScalingGroupMaxSize(maximum)), DesiredCapacity: new(asgapi.AutoScalingGroupDesiredCapacity(capacity)), VPCZoneIdentifier: new(asgapi.XmlStringMaxLen5000(strings.Join(n.Subnets, ","))), HealthCheckGracePeriod: new(asgapi.HealthCheckGracePeriod(900)), Tags: asgapi.Tags{{Key: new(asgapi.TagKey("eks")), Value: new(asgapi.TagValue(n.ID)), PropagateAtLaunch: new(asgapi.PropagateAtLaunch(true))}, {Key: new(asgapi.TagKey("eks:cluster-name")), Value: new(asgapi.TagValue(n.Key.Cluster.Name)), PropagateAtLaunch: new(asgapi.PropagateAtLaunch(true))}, {Key: new(asgapi.TagKey("eks:nodegroup-name")), Value: new(asgapi.TagValue(n.Key.Name)), PropagateAtLaunch: new(asgapi.PropagateAtLaunch(true))}}, LifecycleHookSpecificationList: asgapi.LifecycleHookSpecifications{{LifecycleHookName: new(asgapi.AsciiStringMaxLen255(eksDrainHook)), LifecycleTransition: new(asgapi.LifecycleTransition("autoscaling:EC2_INSTANCE_TERMINATING")), HeartbeatTimeout: new(asgapi.HeartbeatTimeout(1800)), DefaultResult: new(asgapi.LifecycleActionResult("CONTINUE"))}}})
	} else if group.DesiredCapacity == nil || int32(*group.DesiredCapacity) != capacity || group.MinSize == nil || int32(*group.MinSize) != n.MinSize || group.MaxSize == nil || int32(*group.MaxSize) != maximum || group.LaunchTemplate == nil || nodeValue(group.LaunchTemplate.Version) != version || nodeValue(group.LaunchTemplate.LaunchTemplateId) != id {
		_, e = eksNodeCall[asgapi.UpdateAutoScalingGroupOutput](ctx, a.AutoScaling, "autoscaling", "UpdateAutoScalingGroup", &asgapi.UpdateAutoScalingGroupInput{AutoScalingGroupName: new(asgapi.XmlStringMaxLen255(n.GroupName)), LaunchTemplate: lt, MinSize: new(asgapi.AutoScalingGroupMinSize(n.MinSize)), MaxSize: new(asgapi.AutoScalingGroupMaxSize(maximum)), DesiredCapacity: new(asgapi.AutoScalingGroupDesiredCapacity(capacity))})
	}
	if e != nil {
		return eks.NodegroupObservation{}, e
	}
	out, e := a.observe(ctx, n)
	out.ManagedTemplateID = id
	out.ManagedTemplateVersion = version
	return out, e
}
func (a *EKSNodes) group(ctx context.Context, n eks.Nodegroup) (*asgapi.AutoScalingGroup, uint64, error) {
	out, err := a.AutoScaling.ManagedScaling(eksNodeCommandContext(ctx), n.GroupName, n.GroupARN)
	if errors.Is(err, asg.ErrNotFound) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	g := &out.Group
	if !slices.ContainsFunc(g.Tags, func(t asgapi.TagDescription) bool { return nodeValue(t.Key) == "eks" && nodeValue(t.Value) == n.ID }) {
		return nil, 0, errors.New("eks: refusing an unowned Auto Scaling group")
	}
	return g, out.ScaleUpVersion, nil
}
func (a *EKSNodes) Observe(ctx context.Context, n eks.Nodegroup) (eks.NodegroupObservation, error) {
	ctx, e := a.nodeContext(ctx, n)
	if e != nil {
		return eks.NodegroupObservation{}, e
	}
	return a.observe(ctx, n)
}
func (a *EKSNodes) observe(ctx context.Context, n eks.Nodegroup) (eks.NodegroupObservation, error) {
	result := eks.NodegroupObservation{}
	group, scaleUpVersion, e := a.group(ctx, n)
	if e != nil || group == nil {
		return result, e
	}
	result.GroupARN = nodeValue(group.AutoScalingGroupARN)
	result.ScaleUpVersion = scaleUpVersion
	result.AvailabilityZoneCount = int32(len(group.AvailabilityZones))
	if group.MinSize != nil {
		result.MinSize = int32(*group.MinSize)
	}
	if group.MaxSize != nil {
		result.MaxSize = int32(*group.MaxSize)
	}
	if group.DesiredCapacity != nil {
		result.DesiredSize = int32(*group.DesiredCapacity)
	}
	if group.LaunchTemplate != nil {
		result.ManagedTemplateID = nodeValue(group.LaunchTemplate.LaunchTemplateId)
		result.ManagedTemplateVersion = nodeValue(group.LaunchTemplate.Version)
	}
	if len(group.Instances) == 0 {
		return result, nil
	}
	ids := make(ec2api.InstanceIdStringList, 0, len(group.Instances))
	for _, v := range group.Instances {
		ids = append(ids, ec2api.InstanceId(nodeValue(v.InstanceId)))
	}
	instances, e := eksNodeCall[ec2api.DescribeInstancesResult](ctx, a.EC2, "ec2", "DescribeInstances", &ec2api.DescribeInstancesRequest{InstanceIds: ids})
	if e != nil {
		return result, e
	}
	for _, member := range group.Instances {
		for _, reservation := range instances.Reservations {
			for _, instance := range reservation.Instances {
				if nodeValue(member.InstanceId) != nodeValue(instance.InstanceId) {
					continue
				}
				if instance.State != nil && nodeValue(instance.State.Name) == "terminated" {
					continue
				}
				w := eks.NodegroupWorker{InstanceID: nodeValue(instance.InstanceId), PrivateIP: nodeValue(instance.PrivateIpAddress), AvailabilityZone: nodeValue(member.AvailabilityZone), LifecycleState: nodeValue(member.LifecycleState)}
				if instance.LaunchTime != nil {
					w.BootstrapStarted = *instance.LaunchTime
				}
				for _, tag := range instance.Tags {
					switch nodeValue(tag.Key) {
					case "aws:ec2launchtemplate:id":
						w.TemplateID = nodeValue(tag.Value)
					case "aws:ec2launchtemplate:version":
						w.TemplateVersion = nodeValue(tag.Value)
					}
				}
				result.Workers = append(result.Workers, w)
			}
		}
	}
	slices.SortFunc(result.Workers, func(a, b eks.NodegroupWorker) int { return strings.Compare(a.InstanceID, b.InstanceID) })
	return result, nil
}
func (a *EKSNodes) Terminate(ctx context.Context, n eks.Nodegroup, id string, decrement bool) error {
	ctx, e := a.nodeContext(ctx, n)
	if e != nil {
		return e
	}
	g, _, e := a.group(ctx, n)
	if e != nil {
		return e
	}
	if g == nil {
		return nil
	}
	member := slices.IndexFunc(g.Instances, func(v asgapi.Instance) bool { return nodeValue(v.InstanceId) == id })
	if member < 0 || strings.HasPrefix(nodeValue(g.Instances[member].LifecycleState), "Terminating") {
		// A previous command may have committed even when its response was lost.
		return nil
	}
	_, e = eksNodeCall[asgapi.TerminateInstanceInAutoScalingGroupOutput](ctx, a.AutoScaling, "autoscaling", "TerminateInstanceInAutoScalingGroup", &asgapi.TerminateInstanceInAutoScalingGroupInput{AutoScalingGroupName: new(asgapi.XmlStringMaxLen255(n.GroupName)), InstanceId: new(asgapi.XmlStringMaxLen19(id)), ShouldDecrementDesiredCapacity: new(asgapi.ShouldDecrementDesiredCapacity(decrement))})
	return e
}
func (a *EKSNodes) CompleteTermination(ctx context.Context, n eks.Nodegroup, id string) error {
	ctx, e := a.nodeContext(ctx, n)
	if e != nil {
		return e
	}
	g, _, e := a.group(ctx, n)
	if e != nil {
		return e
	}
	if g == nil || !slices.ContainsFunc(g.Instances, func(v asgapi.Instance) bool {
		return nodeValue(v.InstanceId) == id && nodeValue(v.LifecycleState) == "Terminating:Wait"
	}) {
		// Never act on a member that left this exact-owned group or a lifecycle
		// action that already completed during an earlier attempt.
		return nil
	}
	_, e = eksNodeCall[asgapi.CompleteLifecycleActionOutput](ctx, a.AutoScaling, "autoscaling", "CompleteLifecycleAction", &asgapi.CompleteLifecycleActionInput{AutoScalingGroupName: new(asgapi.ResourceName(n.GroupName)), LifecycleHookName: new(asgapi.AsciiStringMaxLen255(eksDrainHook)), InstanceId: new(asgapi.XmlStringMaxLen19(id)), LifecycleActionResult: new(asgapi.LifecycleActionResult("CONTINUE"))})
	return e
}
func (a *EKSNodes) Delete(ctx context.Context, n eks.Nodegroup) (bool, error) {
	ctx, e := a.nodeContext(ctx, n)
	if e != nil {
		return false, e
	}
	group, _, e := a.group(ctx, n)
	if e != nil {
		return false, e
	}
	if group != nil {
		if nodeValue(group.Status) == "Delete in progress" {
			return false, nil
		}
		_, e = eksNodeCall[asgapi.DeleteAutoScalingGroupOutput](ctx, a.AutoScaling, "autoscaling", "DeleteAutoScalingGroup", &asgapi.DeleteAutoScalingGroupInput{AutoScalingGroupName: new(asgapi.XmlStringMaxLen255(n.GroupName)), ForceDelete: new(asgapi.ForceDelete(true))})
		return false, e
	}
	// Delete only the unique owned managed template; never the customer's source.
	templates, e := eksNodeCall[ec2api.DescribeLaunchTemplatesResult](ctx, a.EC2, "ec2", "DescribeLaunchTemplates", &ec2api.DescribeLaunchTemplatesRequest{LaunchTemplateNames: ec2api.LaunchTemplateNameStringList{ec2api.LaunchTemplateName(n.GroupName)}})
	if e == nil {
		for _, t := range templates.LaunchTemplates {
			if !slices.ContainsFunc(t.Tags, func(v ec2api.Tag) bool { return nodeValue(v.Key) == "eks" && nodeValue(v.Value) == n.ID }) {
				return false, errors.New("eks: refusing unowned managed launch-template cleanup")
			}
			_, e = eksNodeCall[ec2api.DeleteLaunchTemplateResult](ctx, a.EC2, "ec2", "DeleteLaunchTemplate", &ec2api.DeleteLaunchTemplateRequest{LaunchTemplateId: new(ec2api.LaunchTemplateId(nodeValue(t.LaunchTemplateId)))})
			if e != nil {
				return false, e
			}
		}
	} else if !nodeErrorCode(e, "InvalidLaunchTemplateName.NotFoundException") && !nodeErrorCode(e, "InvalidLaunchTemplateName.NotFound") {
		return false, e
	}
	profile, e := eksNodeCall[iamapi.GetInstanceProfileResponse](ctx, a.IAM, "iam", "GetInstanceProfile", &iamapi.GetInstanceProfileRequest{InstanceProfileName: new(iamapi.InstanceProfileNameType(n.ProfileName))})
	if nodeErrorCode(e, "NoSuchEntity") {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	if profile.InstanceProfile == nil {
		return false, errors.New("eks: profile cleanup response is absent")
	}
	for _, role := range profile.InstanceProfile.Roles {
		if nodeValue(role.Arn) != n.NodeRoleARN || nodeValue(role.RoleId) != n.NodeRoleID {
			return false, errors.New("eks: refusing replaced profile role cleanup")
		}
		_, e = eksNodeCall[iamapi.RemoveRoleFromInstanceProfileOutput](ctx, a.IAM, "iam", "RemoveRoleFromInstanceProfile", &iamapi.RemoveRoleFromInstanceProfileRequest{InstanceProfileName: new(iamapi.InstanceProfileNameType(n.ProfileName)), RoleName: role.RoleName})
		if e != nil {
			return false, e
		}
	}
	_, e = eksNodeCall[iamapi.DeleteInstanceProfileOutput](ctx, a.IAM, "iam", "DeleteInstanceProfile", &iamapi.DeleteInstanceProfileRequest{InstanceProfileName: new(iamapi.InstanceProfileNameType(n.ProfileName))})
	return e == nil, e
}
func eksWorkerUserData(n eks.Nodegroup, b native.WorkerBootstrap, previous string) (string, error) {
	script := `#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
command -v k3s >/dev/null
mkdir -p /etc/rancher/k3s /var/lib/rancher/k3s/agent/images
TOKEN=$(curl -fsS --retry 10 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token)
meta() { curl -fsS --retry 10 -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/$1"; }
INSTANCE=$(meta instance-id)
ADDRESS=$(meta local-ipv4)
ZONE=$(meta placement/availability-zone)
`
	labels := make([]string, 0, len(n.Labels)+2)
	for key, value := range n.Labels {
		labels = append(labels, key+"="+value)
	}
	slices.Sort(labels)
	labels = append(labels, "eks.amazonaws.com/nodegroup="+n.Key.Name, "eks.amazonaws.com/capacityType="+n.CapacityType)
	taints := make([]string, 0, len(n.Taints))
	for _, t := range n.Taints {
		taints = append(taints, t.Key+"="+t.Value+":"+t.Effect)
	}
	config := map[string]any{"server": b.ServerURL, "token": b.Token, "node-label": labels, "node-taint": taints, "flannel-conf": "/etc/rancher/k3s/stackd-flannel.json"}
	// JSON is a YAML subset; shell-substituted instance identity is always taken
	// from the real EC2 owner's IMDSv2, never from fabricated control-plane rows.
	raw, e := json.Marshal(config)
	if e != nil {
		return "", e
	}
	script += "printf '%s' '" + base64.StdEncoding.EncodeToString(raw) + "' | base64 -d > /etc/rancher/k3s/config.json\n"
	overlay, e := json.Marshal(map[string]any{"Network": "10.42.0.0/16", "EnableIPv4": true, "EnableIPv6": false, "Backend": map[string]any{"Type": "vxlan", "Port": b.FlannelPort, "VNI": b.FlannelPort}})
	if e != nil {
		return "", e
	}
	script += "printf '%s' '" + base64.StdEncoding.EncodeToString(overlay) + "' | base64 -d > /etc/rancher/k3s/stackd-flannel.json\n"
	script += `python3 - "$INSTANCE" "$ADDRESS" "$ZONE" <<'PY'
import json,sys
p='/etc/rancher/k3s/config.json'
v=json.load(open(p)); v['node-name']=sys.argv[1]; v['node-ip']=sys.argv[2]; v['node-external-ip']=sys.argv[2]
v['kubelet-arg']=['provider-id=aws:///'+sys.argv[3]+'/'+sys.argv[1]]
with open('/etc/rancher/k3s/config.yaml','w') as f: json.dump(v,f)
PY
cat >/etc/systemd/system/k3s-agent.service <<'UNIT'
[Unit]
Description=EKS managed EC2 Kubernetes worker
Wants=network-online.target
After=network-online.target
[Service]
Type=notify
ExecStart=/usr/local/bin/k3s agent --config /etc/rancher/k3s/config.yaml
KillMode=process
Delegate=yes
Restart=always
RestartSec=5
LimitNOFILE=1048576
TasksMax=infinity
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now k3s-agent.service
`
	if previous == "" {
		return base64.StdEncoding.EncodeToString([]byte(script)), nil
	}
	custom, e := base64.StdEncoding.DecodeString(previous)
	if e != nil {
		return "", nodeInvalid("Launch-template user data is not valid base64.")
	}
	// Retain custom cloud-init MIME parts, then execute the native agent bootstrap.
	boundary := "eks-" + n.ID
	body := "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"" + boundary + "\"\n\n--" + boundary + "\n"
	if strings.HasPrefix(string(custom), "MIME-Version:") || strings.HasPrefix(string(custom), "Content-Type:") {
		body += string(custom)
	} else if strings.HasPrefix(string(custom), "#!") {
		body += "Content-Type: text/x-shellscript\n\n" + string(custom)
	} else if strings.HasPrefix(string(custom), "#cloud-config") {
		body += "Content-Type: text/cloud-config\n\n" + string(custom)
	} else {
		return "", nodeInvalid("Worker launch-template user data must be shell, cloud-config, or MIME multipart.")
	}
	body += "\n--" + boundary + "\nContent-Type: text/x-shellscript\n\n" + script + "\n--" + boundary + "--\n"
	return base64.StdEncoding.EncodeToString([]byte(body)), nil
}

var _ eks.NodegroupCompute = (*EKSNodes)(nil)
