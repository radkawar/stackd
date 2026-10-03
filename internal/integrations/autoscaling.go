package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/autoscaling"
	ec2api "stackd/internal/awsapi/ec2"
	elbapi "stackd/internal/awsapi/elbv2"
	snsapi "stackd/internal/awsapi/sns"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	asg "stackd/internal/services/autoscaling"
	ec2svc "stackd/internal/services/ec2"
	"stackd/internal/services/elbv2"
	"stackd/internal/services/eventbridge"
)

// AutoScalingEC2 leaves admission, execution, networking and audit with EC2.
// The membership seam is trusted service-only authority, not public CreateTags.
type AutoScalingEC2 interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	RecordRequestError(context.Context, awsapi.DecodedRequest, *awswire.Error) error
	SetAutoScalingGroup(context.Context, string, string, string) error
	RunAutoScalingInstance(context.Context, string, *ec2api.RunInstancesRequest) (*ec2api.Reservation, *awswire.Error)
	TerminateAutoScalingInstance(context.Context, string, *ec2api.TerminateInstancesRequest) (*ec2api.TerminateInstancesResult, *awswire.Error)
	ValidateAutoScalingWarmPool(context.Context, *ec2api.LaunchTemplateSpecification) *awswire.Error
}

// AutoScaling supplies instance commands and fresh linked-role execution identity.
// IAM's Service directly supplies asg.ServiceRoles; ApplicationScaling's existing
// CloudWatch methods supply asg.Alarms without a second alarm implementation.
type AutoScaling struct {
	EC2   AutoScalingEC2
	Roles ServiceRoles
}

var _ asg.Instances = (*AutoScaling)(nil)
var _ asg.ExecutionIdentity = (*AutoScaling)(nil)
var _ asg.Alarms = (*ApplicationScaling)(nil)

type autoScalingSourceKey struct{}

func (a *AutoScaling) Context(ctx context.Context, group asg.GroupRecord) (context.Context, error) {
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = group.Key.Partition, group.Key.AccountID, group.Key.Region
	if parent := apievents.EventID(ctx); parent != "" {
		m.ParentEventID = parent
	}
	ctx = awsctx.WithMetadata(ctx, m)
	source := awsctx.ServicePrincipal{Name: asg.ServicePrincipal, SourceARN: group.Key.ARN(group.ID), Type: "AWSService"}
	credential, rejected := a.Roles.assume(ctx, source, autoScalingString(group.Data.ServiceLinkedRoleARN), identity.RoleSessionSpec{SessionName: "AutoScaling"}, "")
	if rejected != nil {
		return nil, rejected
	}
	service, rejected := serviceRoleRequestContext(ctx, credential, group.Key.Region, asg.ServicePrincipal)
	if rejected != nil {
		return nil, rejected
	}
	// Native commands authorize the issued role, not ServicePrincipal. Internal
	// membership and termination commands also consume the immutable group source.
	return context.WithValue(service, autoScalingSourceKey{}, source), nil
}

func autoScalingCommandContext(ctx context.Context) context.Context {
	m := awsctx.FromContext(ctx)
	if parent := apievents.EventID(ctx); parent != "" {
		m.ParentEventID = parent
	}
	m.RequestID = uuid.NewString()
	m.InvokedBy = asg.ServicePrincipal
	return awsctx.WithViaService(awsctx.WithMetadata(ctx, m), asg.ServicePrincipal)
}

type autoScalingAPIRecorder interface {
	RecordRequestError(context.Context, awsapi.DecodedRequest, *awswire.Error) error
}

// Keep the dependency's native rejection after an enclosing ASG savepoint fails.
// Like IAM's service-linked-role failure, this retains no transaction context.
type autoScalingDependencyRejection struct {
	owner    autoScalingAPIRecorder
	request  awsapi.DecodedRequest
	metadata awsctx.Metadata
	rejected *awswire.Error
	public   *awswire.Error
}

func (e *autoScalingDependencyRejection) Error() string { return e.Unwrap().Error() }
func (e *autoScalingDependencyRejection) Unwrap() error {
	if e.public != nil {
		return e.public
	}
	return e.rejected
}
func (e *autoScalingDependencyRejection) RecordRejection(ctx context.Context) error {
	// The parent's completion context retains its reserved outcome identity.
	// This rolled-back child needs its own identity, not the parent's reservation.
	ctx, err := apievents.Reserve(awsctx.WithMetadata(ctx, e.metadata))
	if err != nil {
		return err
	}
	return e.owner.RecordRequestError(ctx, e.request, e.rejected)
}

func (a *AutoScaling) command(ctx context.Context, name string, input any) (any, error) {
	if a.EC2 == nil {
		return nil, errors.New("autoscaling: EC2 owner is not configured")
	}
	ctx = autoScalingCommandContext(ctx)
	model, _ := awscatalog.LookupService("ec2")
	op, _ := model.Operation(name)
	request := awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input}
	out, rejected := a.EC2.ExecuteCommand(ctx, request)
	if rejected != nil {
		failure := &autoScalingDependencyRejection{owner: a.EC2, request: request, metadata: awsctx.FromContext(ctx), rejected: rejected}
		if name == "DescribeLaunchTemplates" || name == "DescribeLaunchTemplateVersions" {
			// Auto Scaling exposes template selection failures as ValidationError;
			// the EC2 child's audit must retain its native rejection code.
			if strings.HasPrefix(rejected.Code, "InvalidLaunchTemplate") || rejected.Code == "InvalidParameterValue" {
				failure.public = autoScalingInvalid(rejected.Message)
			}
		}
		return nil, failure
	}
	return out, nil
}

func (a *AutoScaling) Template(ctx context.Context, spec api.LaunchTemplateSpecification) (api.LaunchTemplateSpecification, error) {
	input := &ec2api.DescribeLaunchTemplatesRequest{}
	if id := autoScalingString(spec.LaunchTemplateId); id != "" {
		input.LaunchTemplateIds = ec2api.LaunchTemplateIdStringList{ec2api.LaunchTemplateId(id)}
	} else if name := autoScalingString(spec.LaunchTemplateName); name != "" {
		input.LaunchTemplateNames = ec2api.LaunchTemplateNameStringList{ec2api.LaunchTemplateName(name)}
	} else {
		return api.LaunchTemplateSpecification{}, autoScalingInvalid("A launch template ID or name is required.")
	}
	out, err := a.command(ctx, "DescribeLaunchTemplates", input)
	if err != nil {
		return api.LaunchTemplateSpecification{}, err
	}
	templates, ok := out.(*ec2api.DescribeLaunchTemplatesResult)
	if !ok || len(templates.LaunchTemplates) != 1 {
		return api.LaunchTemplateSpecification{}, errors.New("autoscaling: EC2 did not resolve one launch template")
	}
	template := templates.LaunchTemplates[0]
	if autoScalingString(template.LaunchTemplateId) == "" || autoScalingString(template.LaunchTemplateName) == "" {
		return api.LaunchTemplateSpecification{}, errors.New("autoscaling: EC2 returned an incomplete launch template")
	}
	if name := autoScalingString(spec.LaunchTemplateName); name != "" && name != autoScalingString(template.LaunchTemplateName) {
		return api.LaunchTemplateSpecification{}, autoScalingInvalid("The launch template ID and name do not refer to the same template.")
	}
	spec.LaunchTemplateId = new(api.XmlStringMaxLen255(*template.LaunchTemplateId))
	version, err := a.templateVersion(ctx, spec)
	if err != nil {
		return api.LaunchTemplateSpecification{}, err
	}
	return api.LaunchTemplateSpecification{
		LaunchTemplateId:   new(api.XmlStringMaxLen255(*template.LaunchTemplateId)),
		LaunchTemplateName: new(api.LaunchTemplateName(*template.LaunchTemplateName)),
		Version:            new(api.XmlStringMaxLen255(strconv.FormatInt(int64(*version.VersionNumber), 10))),
	}, nil
}

func (a *AutoScaling) templateVersion(ctx context.Context, spec api.LaunchTemplateSpecification) (ec2api.LaunchTemplateVersion, error) {
	version := autoScalingString(spec.Version)
	if version == "" {
		version = "$Default"
	}
	input := &ec2api.DescribeLaunchTemplateVersionsRequest{Versions: ec2api.VersionStringList{ec2api.String(version)}}
	if id := autoScalingString(spec.LaunchTemplateId); id != "" {
		input.LaunchTemplateId = new(ec2api.LaunchTemplateId(id))
	} else {
		input.LaunchTemplateName = new(ec2api.LaunchTemplateName(autoScalingString(spec.LaunchTemplateName)))
	}
	out, err := a.command(ctx, "DescribeLaunchTemplateVersions", input)
	if err != nil {
		return ec2api.LaunchTemplateVersion{}, err
	}
	versions, ok := out.(*ec2api.DescribeLaunchTemplateVersionsResult)
	if !ok || len(versions.LaunchTemplateVersions) != 1 || versions.LaunchTemplateVersions[0].VersionNumber == nil || *versions.LaunchTemplateVersions[0].VersionNumber < 1 || versions.LaunchTemplateVersions[0].LaunchTemplateData == nil {
		return ec2api.LaunchTemplateVersion{}, errors.New("autoscaling: EC2 did not resolve one numeric launch template version")
	}
	return versions.LaunchTemplateVersions[0], nil
}

func (a *AutoScaling) Placement(ctx context.Context, ids, zones []string) ([]ec2api.Subnet, error) {
	if len(ids) == 0 && len(zones) == 0 {
		return nil, autoScalingInvalid("At least one subnet or Availability Zone must be specified.")
	}
	input := &ec2api.DescribeSubnetsRequest{SubnetIds: make(ec2api.SubnetIdStringList, len(ids))}
	for i, id := range ids {
		input.SubnetIds[i] = ec2api.SubnetId(id)
	}
	if len(ids) == 0 {
		// EC2 owns account-specific AZ names and actual default subnets. Merely
		// concatenating the region and a zone letter would accept nonexistent AZs.
		zoneInput := &ec2api.DescribeAvailabilityZonesRequest{ZoneNames: make(ec2api.ZoneNameStringList, len(zones))}
		values := make(ec2api.ValueStringList, len(zones))
		for i, zone := range zones {
			zoneInput.ZoneNames[i], values[i] = ec2api.String(zone), ec2api.String(zone)
		}
		if _, err := a.command(ctx, "DescribeAvailabilityZones", zoneInput); err != nil {
			return nil, err
		}
		input.Filters = ec2api.FilterList{
			{Name: new(ec2api.String("default-for-az")), Values: ec2api.ValueStringList{"true"}},
			{Name: new(ec2api.String("availability-zone")), Values: values},
		}
	}
	var subnets []ec2api.Subnet
	for {
		out, err := a.command(ctx, "DescribeSubnets", input)
		if err != nil {
			return nil, err
		}
		result, ok := out.(*ec2api.DescribeSubnetsResult)
		if !ok {
			return nil, errors.New("autoscaling: invalid EC2 subnet response")
		}
		subnets = append(subnets, result.Subnets...)
		if autoScalingString(result.NextToken) == "" {
			break
		}
		input.NextToken = result.NextToken
	}
	for _, subnet := range subnets {
		if autoScalingString(subnet.State) != "available" || autoScalingString(subnet.SubnetId) == "" || autoScalingString(subnet.VpcId) == "" || autoScalingString(subnet.AvailabilityZone) == "" {
			return nil, autoScalingInvalid("The selected subnets must be available VPC subnets.")
		}
		if len(zones) != 0 && !slices.Contains(zones, autoScalingString(subnet.AvailabilityZone)) {
			return nil, autoScalingInvalid("The subnets and Availability Zones do not match.")
		}
	}
	for _, zone := range zones {
		if !slices.ContainsFunc(subnets, func(subnet ec2api.Subnet) bool { return autoScalingString(subnet.AvailabilityZone) == zone }) {
			return nil, autoScalingInvalid("No selected subnet exists in Availability Zone " + zone + ".")
		}
	}
	return subnets, nil
}

func autoScalingLaunchInput(version ec2api.LaunchTemplateVersion, subnet string, tags api.TagDescriptionList) *ec2api.RunInstancesRequest {
	template := &ec2api.LaunchTemplateSpecification{
		LaunchTemplateId: new(ec2api.LaunchTemplateId(autoScalingString(version.LaunchTemplateId))),
		Version:          new(ec2api.String(strconv.FormatInt(int64(*version.VersionNumber), 10))),
	}
	input := &ec2api.RunInstancesRequest{LaunchTemplate: template, MinCount: new(ec2api.Integer(1)), MaxCount: new(ec2api.Integer(1))}
	if len(version.LaunchTemplateData.NetworkInterfaces) != 0 {
		// A top-level SubnetId conflicts with template NetworkInterfaces on AWS.
		// EC2 merges this indexed override with the retained primary interface.
		input.NetworkInterfaces = ec2api.InstanceNetworkInterfaceSpecificationList{{DeviceIndex: new(ec2api.Integer(0)), SubnetId: new(ec2api.String(subnet))}}
	} else {
		input.SubnetId = new(ec2api.SubnetId(subnet))
	}
	var propagated ec2api.TagList
	for _, tag := range tags {
		if tag.PropagateAtLaunch != nil && bool(*tag.PropagateAtLaunch) {
			propagated = append(propagated, ec2api.Tag{Key: new(ec2api.String(autoScalingString(tag.Key))), Value: new(ec2api.String(autoScalingString(tag.Value)))})
		}
	}
	if len(propagated) != 0 {
		input.TagSpecifications = ec2api.TagSpecificationList{{ResourceType: new(ec2api.ResourceType("instance")), Tags: propagated}}
	}
	return input
}

func (a *AutoScaling) Admit(ctx context.Context, group asg.GroupRecord) error {
	if group.Data.LaunchTemplate == nil {
		return autoScalingInvalid("A launch template is required.")
	}
	service, err := a.Context(ctx, group)
	if err != nil {
		return err
	}
	version, err := a.templateVersion(service, *group.Data.LaunchTemplate)
	if err != nil {
		return err
	}
	// Probe every selectable subnet, not only the first one: IAM can restrict
	// RunInstances to specific subnets and all future launch placements must pass.
	for _, subnet := range strings.Split(autoScalingString(group.Data.VPCZoneIdentifier), ",") {
		input := autoScalingLaunchInput(version, strings.TrimSpace(subnet), group.Data.Tags)
		input.DryRun = new(ec2api.Boolean(true))
		_, err := a.command(ctx, "RunInstances", input)
		var rejected *awswire.Error
		if errors.As(err, &rejected) && rejected.Code == "DryRunOperation" {
			continue
		}
		if err == nil {
			return errors.New("autoscaling: EC2 RunInstances did not return the required DryRunOperation")
		}
		if rejected != nil && (rejected.Code == "UnauthorizedOperation" || rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException") {
			var dependency *autoScalingDependencyRejection
			if errors.As(err, &dependency) {
				dependency.public = &awswire.Error{Code: "AccessDenied", Message: "You are not authorized to use launch template: " + autoScalingString(version.LaunchTemplateId), StatusCode: 403}
			}
		}
		return err
	}
	return nil
}

func (a *AutoScaling) ValidateWarmPool(ctx context.Context, group asg.GroupRecord) error {
	pool := group.Data.WarmPoolConfiguration
	if pool == nil || autoScalingString(pool.PoolState) != "Hibernated" {
		return nil
	}
	if a.EC2 == nil {
		return errors.New("autoscaling: EC2 owner is not configured")
	}
	spec := group.Data.LaunchTemplate
	if spec == nil {
		return autoScalingInvalid("A launch template is required for the warm pool.")
	}
	input := &ec2api.LaunchTemplateSpecification{Version: new(ec2api.String(autoScalingString(spec.Version)))}
	if id := autoScalingString(spec.LaunchTemplateId); id != "" {
		input.LaunchTemplateId = new(ec2api.LaunchTemplateId(id))
	} else {
		input.LaunchTemplateName = new(ec2api.String(autoScalingString(spec.LaunchTemplateName)))
	}
	if rejected := a.EC2.ValidateAutoScalingWarmPool(ctx, input); rejected != nil {
		return autoScalingInvalid(rejected.Message)
	}
	return nil
}

func (a *AutoScaling) Launch(ctx context.Context, group asg.GroupRecord, activity asg.ActivityRecord) (ec2api.Instance, error) {
	if activity.Group != group.Key || activity.GroupID != group.ID || activity.Key.ID == "" {
		return ec2api.Instance{}, errors.New("autoscaling: launch activity does not belong to this group incarnation")
	}
	version, err := a.templateVersion(ctx, activity.LaunchTemplate)
	if err != nil {
		return ec2api.Instance{}, err
	}
	input := autoScalingLaunchInput(version, activity.SubnetID, activity.LaunchTags)
	if activity.WarmPoolState == "Hibernated" {
		input.HibernationOptions = &ec2api.HibernationOptionsRequest{Configured: new(ec2api.Boolean(true))}
	}
	input.ClientToken = new(ec2api.String(activity.Key.ID))
	ctx = autoScalingCommandContext(ctx)
	reservation, rejected := a.EC2.RunAutoScalingInstance(ctx, group.Key.ARN(group.ID), input)
	if rejected != nil {
		model, _ := awscatalog.LookupService("ec2")
		op, _ := model.Operation("RunInstances")
		return ec2api.Instance{}, &autoScalingDependencyRejection{owner: a.EC2, request: awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input}, metadata: awsctx.FromContext(ctx), rejected: rejected}
	}
	if reservation == nil || len(reservation.Instances) != 1 || autoScalingString(reservation.Instances[0].InstanceId) == "" {
		return ec2api.Instance{}, errors.New("autoscaling: EC2 did not return the launched instance")
	}
	return reservation.Instances[0], nil
}

func (a *AutoScaling) Observe(ctx context.Context, ids []string) ([]asg.InstanceObservation, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	selected := make(ec2api.InstanceIdStringList, len(ids))
	for i, id := range ids {
		selected[i] = ec2api.InstanceId(id)
	}
	input := &ec2api.DescribeInstancesRequest{InstanceIds: selected}
	var observations []asg.InstanceObservation
	for {
		out, err := a.command(ctx, "DescribeInstances", input)
		if err != nil {
			return nil, err
		}
		result, ok := out.(*ec2api.DescribeInstancesResult)
		if !ok {
			return nil, errors.New("autoscaling: invalid EC2 instance response")
		}
		for _, reservation := range result.Reservations {
			for _, instance := range reservation.Instances {
				observations = append(observations, asg.InstanceObservation{Instance: instance})
			}
		}
		if autoScalingString(result.NextToken) == "" {
			break
		}
		input.NextToken = result.NextToken
	}
	statuses := &ec2api.DescribeInstanceStatusRequest{InstanceIds: selected, IncludeAllInstances: new(ec2api.Boolean(true))}
	failedChecks := make(map[string]bool, len(ids))
	for {
		out, err := a.command(ctx, "DescribeInstanceStatus", statuses)
		if err != nil {
			return nil, err
		}
		result, ok := out.(*ec2api.DescribeInstanceStatusResult)
		if !ok {
			return nil, errors.New("autoscaling: invalid EC2 instance status response")
		}
		for _, status := range result.InstanceStatuses {
			// Initialization and insufficient data are not failed EC2 checks.
			// ASG acts on impairment, not the absence of a completed observation.
			failedChecks[autoScalingString(status.InstanceId)] =
				status.InstanceStatus != nil && autoScalingString(status.InstanceStatus.Status) == "impaired" ||
					status.SystemStatus != nil && autoScalingString(status.SystemStatus.Status) == "impaired"
		}
		if autoScalingString(result.NextToken) == "" {
			break
		}
		statuses.NextToken = result.NextToken
	}
	var volumeIDs ec2api.VolumeIdStringList
	for _, observation := range observations {
		if observation.Instance.State == nil || autoScalingString(observation.Instance.State.Name) != "stopped" {
			continue
		}
		for _, mapping := range observation.Instance.BlockDeviceMappings {
			if mapping.Ebs != nil && autoScalingString(mapping.Ebs.VolumeId) != "" {
				volumeIDs = append(volumeIDs, ec2api.VolumeId(autoScalingString(mapping.Ebs.VolumeId)))
			}
		}
	}
	impairedVolumes := map[string]bool{}
	if len(volumeIDs) != 0 {
		request := &ec2api.DescribeVolumeStatusRequest{VolumeIds: volumeIDs}
		for {
			out, err := a.command(ctx, "DescribeVolumeStatus", request)
			if err != nil {
				return nil, err
			}
			result, ok := out.(*ec2api.DescribeVolumeStatusResult)
			if !ok {
				return nil, errors.New("autoscaling: invalid EC2 volume status response")
			}
			for _, status := range result.VolumeStatuses {
				if status.VolumeStatus != nil && autoScalingString(status.VolumeStatus.Status) == "impaired" {
					impairedVolumes[autoScalingString(status.VolumeId)] = true
				}
			}
			if autoScalingString(result.NextToken) == "" {
				break
			}
			request.NextToken = result.NextToken
		}
	}
	for i := range observations {
		instance := observations[i].Instance
		state := ""
		if instance.State != nil {
			state = autoScalingString(instance.State.Name)
		}
		observations[i].Healthy = state == "running" && !failedChecks[autoScalingString(instance.InstanceId)]
		if state == "stopped" {
			observations[i].Healthy = true
			for _, mapping := range instance.BlockDeviceMappings {
				if mapping.Ebs != nil && impairedVolumes[autoScalingString(mapping.Ebs.VolumeId)] {
					observations[i].Healthy = false
				}
			}
		}
	}
	return observations, nil
}

func (a *AutoScaling) Start(ctx context.Context, id string) error {
	if _, err := a.sourceGroup(ctx); err != nil {
		return err
	}
	_, err := a.command(ctx, "StartInstances", &ec2api.StartInstancesRequest{InstanceIds: ec2api.InstanceIdStringList{ec2api.InstanceId(id)}})
	return err
}

func (a *AutoScaling) Stop(ctx context.Context, id string, hibernate bool) error {
	if _, err := a.sourceGroup(ctx); err != nil {
		return err
	}
	_, err := a.command(ctx, "StopInstances", &ec2api.StopInstancesRequest{InstanceIds: ec2api.InstanceIdStringList{ec2api.InstanceId(id)}, Hibernate: new(ec2api.Boolean(hibernate))})
	if errors.Is(err, ec2svc.ErrInstanceHibernationNotReady) {
		return asg.ErrInstanceHibernationNotReady
	}
	return err
}

func (a *AutoScaling) Terminate(ctx context.Context, id string) error {
	source, err := a.sourceGroup(ctx)
	if err != nil {
		return err
	}
	ctx = autoScalingCommandContext(ctx)
	input := &ec2api.TerminateInstancesRequest{InstanceIds: ec2api.InstanceIdStringList{ec2api.InstanceId(id)}}
	_, rejected := a.EC2.TerminateAutoScalingInstance(ctx, source, input)
	if rejected == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("ec2")
	op, _ := model.Operation("TerminateInstances")
	return &autoScalingDependencyRejection{owner: a.EC2, request: awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input}, metadata: awsctx.FromContext(ctx), rejected: rejected}
}

func (a *AutoScaling) SetGroup(ctx context.Context, id, groupARN string) error {
	source, err := a.sourceGroup(ctx)
	if err != nil {
		return err
	}
	return a.EC2.SetAutoScalingGroup(ctx, id, source, groupARN)
}

func (a *AutoScaling) sourceGroup(ctx context.Context) (string, error) {
	source, ok := ctx.Value(autoScalingSourceKey{}).(awsctx.ServicePrincipal)
	if !ok || source.Name != asg.ServicePrincipal || source.SourceARN == "" {
		return "", errors.New("autoscaling: instance mutation requires the current group's execution context")
	}
	if a.EC2 == nil {
		return "", errors.New("autoscaling: EC2 owner is not configured")
	}
	return source.SourceARN, nil
}

// AutoScalingTargetOwner is ELBv2's incarnation-fenced target command boundary.
type AutoScalingTargetOwner interface {
	ValidateInstanceTargetGroup(context.Context, elbv2.Scope, string, string) error
	RegisterOwnedTarget(context.Context, elbv2.Scope, string, elbapi.TargetDescription, string, string) error
	DeregisterOwnedTarget(context.Context, elbv2.Scope, string, elbapi.TargetDescription, string, string) error
	OwnedTargetHealth(context.Context, elbv2.Scope, string, elbapi.TargetDescription, string, string) (elbv2.TargetRecord, bool, error)
}

type AutoScalingTargetGroups struct{ ELBv2 AutoScalingTargetOwner }

var _ asg.TargetGroups = AutoScalingTargetGroups{}

func autoScalingELBScope(ctx context.Context) elbv2.Scope {
	m := awsctx.FromContext(ctx)
	return elbv2.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
}

func (a AutoScalingTargetGroups) Validate(ctx context.Context, arns []string, subnets []ec2api.Subnet) error {
	if a.ELBv2 == nil {
		return errors.New("autoscaling: ELBv2 owner is not configured")
	}
	if len(subnets) == 0 {
		return autoScalingInvalid("Target groups require VPC subnets.")
	}
	vpc := autoScalingString(subnets[0].VpcId)
	for _, subnet := range subnets {
		if vpc == "" || autoScalingString(subnet.VpcId) != vpc {
			return autoScalingInvalid("Target groups and subnets must belong to the same VPC.")
		}
	}
	for _, target := range arns {
		if err := a.ELBv2.ValidateInstanceTargetGroup(ctx, autoScalingELBScope(ctx), target, vpc); err != nil {
			return err
		}
	}
	return nil
}

func autoScalingTarget(id string) elbapi.TargetDescription {
	return elbapi.TargetDescription{Id: new(elbapi.TargetId(id))}
}
func (a AutoScalingTargetGroups) Register(ctx context.Context, group, target, id string) error {
	if a.ELBv2 == nil {
		return errors.New("autoscaling: ELBv2 owner is not configured")
	}
	return a.ELBv2.RegisterOwnedTarget(ctx, autoScalingELBScope(ctx), target, autoScalingTarget(id), group, id)
}
func (a AutoScalingTargetGroups) Deregister(ctx context.Context, group, target, id string) error {
	if a.ELBv2 == nil {
		return errors.New("autoscaling: ELBv2 owner is not configured")
	}
	return a.ELBv2.DeregisterOwnedTarget(ctx, autoScalingELBScope(ctx), target, autoScalingTarget(id), group, id)
}
func (a AutoScalingTargetGroups) Healthy(ctx context.Context, group, target, id string) (bool, error) {
	if a.ELBv2 == nil {
		return false, errors.New("autoscaling: ELBv2 owner is not configured")
	}
	state, exists, err := a.ELBv2.OwnedTargetHealth(ctx, autoScalingELBScope(ctx), target, autoScalingTarget(id), group, id)
	return err == nil && exists && state.State == "healthy", err
}
func (a AutoScalingTargetGroups) Drained(ctx context.Context, group, target, id string) (bool, error) {
	if a.ELBv2 == nil {
		return false, errors.New("autoscaling: ELBv2 owner is not configured")
	}
	_, exists, err := a.ELBv2.OwnedTargetHealth(ctx, autoScalingELBScope(ctx), target, autoScalingTarget(id), group, id)
	return err == nil && !exists, err
}

// AutoScalingSQS owns current queue lookup/send authority and their API outcomes.
type AutoScalingSQS interface {
	SQSSender
	autoScalingAPIRecorder
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}

// AutoScalingSNS owns publication and the retained outcome of rejected admission.
type AutoScalingSNS interface {
	SNSPublisher
	autoScalingAPIRecorder
}

// AutoScalingEvents joins producer transitions to native EventBridge, SNS and SQS
// transactions. The current hook role is assumed anew for each notification.
type AutoScalingEvents struct {
	Publisher EventBridgeEventPublisher
	SNS       AutoScalingSNS
	SQS       AutoScalingSQS
	Roles     ServiceRoles
	Clock     clock.Clock
}

var _ asg.Events = AutoScalingEvents{}

func (a AutoScalingEvents) Publish(ctx context.Context, group asg.GroupRecord, kind string, detail []byte) error {
	if a.Publisher == nil || a.Clock == nil {
		return errors.New("autoscaling: EventBridge publisher and clock are not configured")
	}
	m := awsctx.FromContext(ctx)
	if parent := apievents.EventID(ctx); parent != "" {
		m.ParentEventID = parent
	}
	m.Partition, m.AccountID, m.Region = group.Key.Partition, group.Key.AccountID, group.Key.Region
	ctx = awsctx.WithServicePrincipal(awsctx.WithMetadata(ctx, m), awsctx.ServicePrincipal{Name: asg.ServicePrincipal, SourceARN: group.Key.ARN(group.ID), Type: "AWSService"})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{
		ID: uuid.NewString(), Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: group.Key.Partition, Account: group.Key.AccountID, Region: group.Key.Region}, Name: "default"},
		Source: "aws.autoscaling", DetailType: kind, Detail: string(detail), Resources: []string{group.Key.ARN(group.ID)}, Time: a.Clock.Now(), Account: group.Key.AccountID, RequestID: m.RequestID,
	})
}

func (a AutoScalingEvents) Notify(ctx context.Context, hook asg.HookRecord, payload []byte) error {
	target, err := arn.Parse(autoScalingString(hook.Data.NotificationTargetARN))
	if err != nil || target.Partition != hook.Key.Partition || target.Region != hook.Key.Region || target.AccountID == "" || target.Resource == "" || target.Service != "sns" && target.Service != "sqs" {
		return autoScalingInvalid("Lifecycle notifications require an SNS topic or SQS queue in the group's Region.")
	}
	if strings.HasSuffix(target.Resource, ".fifo") {
		return autoScalingInvalid("FIFO notification targets are not supported by lifecycle hooks.")
	}
	roleARN := autoScalingString(hook.Data.RoleARN)
	role, err := arn.Parse(roleARN)
	if err != nil || role.Partition != hook.Key.Partition || role.Service != "iam" || role.Region != "" || role.AccountID != hook.Key.AccountID || !strings.HasPrefix(role.Resource, "role/") {
		return autoScalingInvalid("The notification role must belong to the Auto Scaling group's account.")
	}
	var document map[string]string
	if err := json.Unmarshal(payload, &document); err != nil {
		return err
	}
	testNotification := document["Event"] == "autoscaling:TEST_NOTIFICATION"
	notificationError := func(rejected *awswire.Error) *awswire.Error {
		if testNotification && rejected.StatusCode >= 400 && rejected.StatusCode < 500 {
			return autoScalingInvalid("Unable to publish test message to notification target " + target.String() + " using IAM role " + roleARN + ". Please check your target and role configuration and try to put lifecycle hook again.")
		}
		return rejected
	}
	dependencyError := func(owner autoScalingAPIRecorder, service, operation string, input any, rejected *awswire.Error) error {
		model, _ := awscatalog.LookupService(service)
		op, _ := model.Operation(operation)
		return &autoScalingDependencyRejection{
			owner: owner, request: awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input},
			metadata: awsctx.FromContext(ctx), rejected: rejected, public: notificationError(rejected),
		}
	}
	if a.Clock == nil {
		return errors.New("autoscaling: notification clock is not configured")
	}
	sourceARN := hook.Key.GroupKey.ARN(hook.GroupID)
	if testNotification {
		if a.Roles.Authorizer == nil {
			return errors.New("autoscaling: notification role authority is not configured")
		}
		if rejected := a.Roles.Authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: roleARN, ResourceAccountID: hook.Key.AccountID, Context: map[string][]string{"iam:PassedToService": {asg.ServicePrincipal}, "iam:AssociatedResourceArn": {sourceARN}}}); rejected != nil {
			return rejected
		}
	}
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = hook.Key.Partition, hook.Key.AccountID, hook.Key.Region
	if parent := apievents.EventID(ctx); parent != "" {
		m.ParentEventID = parent
	}
	ctx = awsctx.WithMetadata(ctx, m)
	credential, rejected := a.Roles.assume(ctx, awsctx.ServicePrincipal{Name: asg.ServicePrincipal, SourceARN: sourceARN, Type: "AWSService"}, roleARN, identity.RoleSessionSpec{SessionName: "AutoScaling"}, "")
	if rejected != nil {
		return notificationError(rejected)
	}
	ctx, rejected = serviceRoleRequestContext(ctx, credential, hook.Key.Region, asg.ServicePrincipal)
	if rejected != nil {
		return notificationError(rejected)
	}
	document["Service"], document["Time"], document["RequestId"] = "AWS Auto Scaling", a.Clock.Now().UTC().Format(time.RFC3339Nano), m.RequestID
	document["AccountId"], document["AutoScalingGroupName"] = hook.Key.AccountID, hook.Key.GroupKey.Name
	if testNotification {
		document["AutoScalingGroupARN"] = sourceARN
	}
	if target.Service == "sqs" {
		if a.SQS == nil {
			return errors.New("autoscaling: SQS notification owner is not configured")
		}
		body, err := json.Marshal(document)
		if err != nil {
			return err
		}
		// Native hook notification roles need GetQueueUrl as well as SendMessage.
		// Use the ordinary command so current lookup authority and audit remain
		// owned by SQS, including when the queue was deleted after hook admission.
		ctx = autoScalingCommandContext(ctx)
		lookup := &sqsapi.GetQueueUrlInput{QueueName: new(sqsapi.String(target.Resource)), QueueOwnerAWSAccountId: new(sqsapi.String(target.AccountID))}
		model, _ := awscatalog.LookupService("sqs")
		op, _ := model.Operation("GetQueueUrl")
		out, rejected := a.SQS.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: lookup})
		if rejected != nil {
			return dependencyError(a.SQS, "sqs", "GetQueueUrl", lookup, rejected)
		}
		ctx = autoScalingCommandContext(ctx)
		input := &sqsapi.SendMessageInput{QueueUrl: out.(*sqsapi.GetQueueUrlOutput).QueueUrl, MessageBody: new(sqsapi.String(body))}
		if _, rejected := a.SQS.SendToQueue(ctx, target.String(), input); rejected != nil {
			return dependencyError(a.SQS, "sqs", "SendMessage", input, rejected)
		}
	} else {
		if a.SNS == nil {
			return errors.New("autoscaling: SNS notification owner is not configured")
		}
		// PutLifecycleHook documents JSON for SQS and email key-value pairs for SNS.
		var body strings.Builder
		for _, field := range []string{"Service", "Time", "RequestId", "Event", "Action", "Origin", "Destination", "LifecycleActionToken", "AccountId", "AutoScalingGroupName", "AutoScalingGroupARN", "LifecycleHookName", "EC2InstanceId", "LifecycleTransition", "NotificationMetadata"} {
			if value, exists := document[field]; exists {
				body.WriteString(field)
				body.WriteString(": ")
				body.WriteString(value)
				body.WriteByte('\n')
			}
		}
		ctx = autoScalingCommandContext(ctx)
		input := &snsapi.PublishInput{TopicArn: new(snsapi.TopicARN(target.String())), Message: new(snsapi.Message(body.String()))}
		if _, rejected := a.SNS.Publish(ctx, input); rejected != nil {
			return dependencyError(a.SNS, "sns", "Publish", input, rejected)
		}
	}
	return nil
}

func autoScalingString[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func autoScalingInvalid(message string) *awswire.Error {
	return &awswire.Error{Code: "ValidationError", Message: message, StatusCode: 400}
}
