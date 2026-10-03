package integrations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"strconv"

	"stackd/compute/lambda/managed"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	ec2api "stackd/internal/awsapi/ec2"
	ssmapi "stackd/internal/awsapi/ssm"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	lambda "stackd/internal/services/lambda"
)

// LambdaCapacityEC2 preserves EC2's initial-transaction managed operator and
// source fencing; the adapter must not launch an ordinary unmarked instance.
type LambdaCapacityEC2 interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	RunLambdaManagedInstance(context.Context, string, *ec2api.RunInstancesRequest) (*ec2api.Reservation, *awswire.Error)
	TerminateLambdaManagedInstance(context.Context, string, *ec2api.TerminateInstancesRequest) (*ec2api.TerminateInstancesResult, *awswire.Error)
}
type LambdaCapacitySSM interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}
type LambdaCapacityRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

// LambdaCapacityConfig selects an explicitly prepared real EC2 AMI. Its official
// SSM agent, Docker, pinned runtime images and stackd-lambda-agent must already be
// installed. No image is downloaded or host container used as a guest fallback.
type LambdaCapacityConfig struct {
	ImageID, InstanceProfileARN, InstanceType string
	AgentPort                                 int
	Images                                    []managed.Image
}
type LambdaCapacity struct {
	EC2         LambdaCapacityEC2
	SSM         LambdaCapacitySSM
	Roles       ServiceRoles
	LinkedRoles LambdaCapacityRoles
	Config      LambdaCapacityConfig
}

var _ lambda.CapacityBackend = (*LambdaCapacity)(nil)

func (a *LambdaCapacity) roleContext(ctx context.Context, p lambda.CapacityProviderRecord, termination bool) (context.Context, error) {
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = p.Key.Partition, p.Key.Account, p.Key.Region
	ctx = awsctx.WithMetadata(ctx, m)
	role := p.OperatorRoleARN
	if termination {
		role = "arn:" + p.Key.Partition + ":iam::" + p.Key.Account + ":role/aws-service-role/lambda.amazonaws.com/AWSServiceRoleForLambda"
	}
	credential, rejected := a.Roles.assume(ctx, awsctx.ServicePrincipal{Name: "lambda.amazonaws.com", SourceARN: p.Key.ARN(), Type: "AWSService"}, role, identity.RoleSessionSpec{SessionName: "LambdaCapacity"}, "")
	if rejected != nil {
		return nil, rejected
	}
	out, rejected := serviceRoleRequestContext(ctx, credential, p.Key.Region, "lambda.amazonaws.com")
	if rejected != nil {
		return nil, rejected
	}
	return out, nil
}
func capacityCommand(ctx context.Context, owner LambdaCapacitySSM, service, operation string, in any) (any, error) {
	model, ok := awscatalog.LookupService(service)
	if !ok {
		return nil, fmt.Errorf("missing %s service model", service)
	}
	op, ok := model.Operation(operation)
	if !ok {
		return nil, fmt.Errorf("missing %s operation", operation)
	}
	out, rejected := owner.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: in})
	if rejected != nil {
		return nil, rejected
	}
	return out, nil
}
func capacityValue[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func (a *LambdaCapacity) Validate(ctx context.Context, p lambda.CapacityProviderRecord) error {
	if a.EC2 == nil || a.SSM == nil || a.Config.ImageID == "" || a.Config.InstanceProfileARN == "" || a.Config.InstanceType == "" || a.Config.AgentPort < 1 || a.Config.AgentPort > 65535 || len(a.Config.Images) == 0 {
		return &awswire.Error{Code: "NotImplementedException", Message: "A prepared EC2 managed guest AMI, instance profile, instance type, guest agent port and runtime images are required.", StatusCode: 501}
	}
	caller := awsctx.FromContext(ctx)
	if caller.AccessKeyID != "" {
		if a.Roles.Authorizer == nil {
			return errors.New("lambda capacity role authorizer is unavailable")
		}
		if rejected := a.Roles.Authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: p.OperatorRoleARN, ResourceAccountID: p.Key.Account, Context: map[string][]string{"iam:PassedToService": {"lambda.amazonaws.com"}, "iam:AssociatedResourceArn": {p.Key.ARN()}}}); rejected != nil {
			return rejected
		}
		if a.LinkedRoles == nil {
			return errors.New("lambda capacity service-linked-role authority is unavailable")
		}
		if err := a.LinkedRoles.EnsureServiceLinkedRole(ctx, "lambda.amazonaws.com"); err != nil {
			return err
		}
	}
	role, err := a.roleContext(ctx, p, false)
	if err != nil {
		return err
	}
	_, _, err = a.launchFacts(role, p)
	return err
}

type capacityHardware struct{ cpus, memoryMB int32 }

func (a *LambdaCapacity) launchFacts(ctx context.Context, p lambda.CapacityProviderRecord) (ec2api.Image, capacityHardware, error) {
	instanceType := a.Config.InstanceType
	matches := func(patterns []string) bool {
		for _, pattern := range patterns {
			ok, _ := path.Match(pattern, instanceType)
			if ok {
				return true
			}
		}
		return false
	}
	if len(p.AllowedInstanceTypes) > 0 && !matches(p.AllowedInstanceTypes) || matches(p.ExcludedInstanceTypes) {
		return ec2api.Image{}, capacityHardware{}, &awswire.Error{Code: "InvalidParameterValueException", Message: "The configured guest instance type does not satisfy provider instance requirements.", StatusCode: 400}
	}
	raw, err := capacityCommand(ctx, a.EC2, "ec2", "DescribeInstanceTypes", &ec2api.DescribeInstanceTypesRequest{InstanceTypes: ec2api.RequestInstanceTypeList{ec2api.InstanceType(instanceType)}})
	if err != nil {
		return ec2api.Image{}, capacityHardware{}, err
	}
	types, ok := raw.(*ec2api.DescribeInstanceTypesResult)
	if !ok || len(types.InstanceTypes) != 1 || types.InstanceTypes[0].VCpuInfo == nil || types.InstanceTypes[0].VCpuInfo.DefaultVCpus == nil || types.InstanceTypes[0].MemoryInfo == nil || types.InstanceTypes[0].MemoryInfo.SizeInMiB == nil {
		return ec2api.Image{}, capacityHardware{}, errors.New("EC2 did not resolve managed instance vCPUs and memory")
	}
	hardware := capacityHardware{cpus: int32(*types.InstanceTypes[0].VCpuInfo.DefaultVCpus), memoryMB: int32(*types.InstanceTypes[0].MemoryInfo.SizeInMiB)}
	if hardware.cpus > p.MaxVCPUs {
		return ec2api.Image{}, capacityHardware{}, &awswire.Error{Code: "InvalidParameterValueException", Message: "MaxVCpuCount is smaller than the configured guest instance.", StatusCode: 400}
	}
	raw, err = capacityCommand(ctx, a.EC2, "ec2", "DescribeImages", &ec2api.DescribeImagesRequest{ImageIds: ec2api.ImageIdStringList{ec2api.ImageId(a.Config.ImageID)}})
	if err != nil {
		return ec2api.Image{}, capacityHardware{}, err
	}
	images, ok := raw.(*ec2api.DescribeImagesResult)
	if !ok || len(images.Images) != 1 {
		return ec2api.Image{}, capacityHardware{}, errors.New("EC2 did not resolve the managed guest AMI")
	}
	image := images.Images[0]
	if capacityValue(image.Architecture) != p.Architecture || capacityValue(image.State) != "available" || capacityValue(image.RootDeviceName) == "" {
		return ec2api.Image{}, capacityHardware{}, &awswire.Error{Code: "InvalidParameterValueException", Message: "The managed guest AMI architecture/state/root device does not satisfy the provider.", StatusCode: 400}
	}
	subnets := ec2api.SubnetIdStringList{}
	for _, id := range p.SubnetIDs {
		subnets = append(subnets, ec2api.SubnetId(id))
	}
	raw, err = capacityCommand(ctx, a.EC2, "ec2", "DescribeSubnets", &ec2api.DescribeSubnetsRequest{SubnetIds: subnets})
	if err != nil {
		return ec2api.Image{}, capacityHardware{}, err
	}
	subnetResult, ok := raw.(*ec2api.DescribeSubnetsResult)
	if !ok || len(subnetResult.Subnets) != len(p.SubnetIDs) {
		return ec2api.Image{}, capacityHardware{}, errors.New("provider subnet selection is incomplete")
	}
	vpc := ""
	for _, subnet := range subnetResult.Subnets {
		if vpc != "" && vpc != capacityValue(subnet.VpcId) {
			return ec2api.Image{}, capacityHardware{}, errors.New("provider subnets must belong to one VPC")
		}
		vpc = capacityValue(subnet.VpcId)
	}
	if len(p.SecurityGroupIDs) > 0 {
		groups := ec2api.GroupIdStringList{}
		for _, id := range p.SecurityGroupIDs {
			groups = append(groups, ec2api.SecurityGroupId(id))
		}
		raw, err = capacityCommand(ctx, a.EC2, "ec2", "DescribeSecurityGroups", &ec2api.DescribeSecurityGroupsRequest{GroupIds: groups})
		if err != nil {
			return ec2api.Image{}, capacityHardware{}, err
		}
		groupResult, ok := raw.(*ec2api.DescribeSecurityGroupsResult)
		if !ok || len(groupResult.SecurityGroups) != len(p.SecurityGroupIDs) {
			return ec2api.Image{}, capacityHardware{}, errors.New("provider security group selection is incomplete")
		}
		for _, group := range groupResult.SecurityGroups {
			if capacityValue(group.VpcId) != vpc {
				return ec2api.Image{}, capacityHardware{}, errors.New("provider security groups and subnets must belong to one VPC")
			}
		}
	}
	return image, hardware, nil
}
func (a *LambdaCapacity) Launch(ctx context.Context, p lambda.CapacityProviderRecord, g lambda.CapacityGuestRecord) (lambda.CapacityGuestRecord, error) {
	role, err := a.roleContext(ctx, p, false)
	if err != nil {
		return g, err
	}
	image, hardware, err := a.launchFacts(role, p)
	if err != nil {
		return g, err
	}
	if hardware.cpus < g.VCPUs || hardware.memoryMB < g.MemoryMB {
		return g, errors.New("the managed guest instance type is too small for the function")
	}
	input := &ec2api.RunInstancesRequest{ImageId: new(ec2api.ImageId(a.Config.ImageID)), InstanceType: new(ec2api.InstanceType(a.Config.InstanceType)), ClientToken: new(ec2api.String(g.Generation)), MinCount: new(ec2api.Integer(1)), MaxCount: new(ec2api.Integer(1)), SubnetId: new(ec2api.SubnetId(g.SubnetID)), IamInstanceProfile: &ec2api.IamInstanceProfileSpecification{Arn: new(ec2api.String(a.Config.InstanceProfileARN))}}
	for _, id := range p.SecurityGroupIDs {
		input.SecurityGroupIds = append(input.SecurityGroupIds, ec2api.SecurityGroupId(id))
	}
	disk := &ec2api.EbsBlockDevice{Encrypted: new(ec2api.Boolean(true)), DeleteOnTermination: new(ec2api.Boolean(true))}
	if p.KMSKeyARN != "" {
		disk.KmsKeyId = new(ec2api.String(p.KMSKeyARN))
	}
	input.BlockDeviceMappings = ec2api.BlockDeviceMappingRequestList{{DeviceName: new(ec2api.String(capacityValue(image.RootDeviceName))), Ebs: disk}}
	if len(p.PropagateTags) > 0 {
		tags := ec2api.TagList{}
		for key, value := range p.PropagateTags {
			tags = append(tags, ec2api.Tag{Key: new(ec2api.String(key)), Value: new(ec2api.String(value))})
		}
		for _, kind := range []string{"instance", "volume", "network-interface"} {
			input.TagSpecifications = append(input.TagSpecifications, ec2api.TagSpecification{ResourceType: new(ec2api.ResourceType(kind)), Tags: tags})
		}
	}
	reservation, rejected := a.EC2.RunLambdaManagedInstance(role, p.Key.ARN(), input)
	if rejected != nil {
		return g, rejected
	}
	if reservation == nil || len(reservation.Instances) != 1 {
		return g, errors.New("EC2 did not admit exactly one managed guest")
	}
	instance := reservation.Instances[0]
	g.InstanceID = capacityValue(instance.InstanceId)
	g.InstanceType = a.Config.InstanceType
	g.VCPUs = hardware.cpus
	g.MemoryMB = hardware.memoryMB
	g.State = "Booting"
	return g, nil
}
func (a *LambdaCapacity) instance(ctx context.Context, p lambda.CapacityProviderRecord, g lambda.CapacityGuestRecord) (ec2api.Instance, error) {
	raw, err := capacityCommand(ctx, a.EC2, "ec2", "DescribeInstances", &ec2api.DescribeInstancesRequest{InstanceIds: ec2api.InstanceIdStringList{ec2api.InstanceId(g.InstanceID)}})
	if err != nil {
		return ec2api.Instance{}, err
	}
	result, ok := raw.(*ec2api.DescribeInstancesResult)
	if !ok || len(result.Reservations) != 1 || len(result.Reservations[0].Instances) != 1 {
		return ec2api.Instance{}, errors.New("EC2 managed guest identity is missing")
	}
	instance := result.Reservations[0].Instances[0]
	if capacityValue(instance.ClientToken) != g.Generation || instance.Operator == nil || instance.Operator.Managed == nil || !bool(*instance.Operator.Managed) || capacityValue(instance.Operator.Principal) != "scaler.lambda.amazonaws.com" {
		return ec2api.Instance{}, errors.New("EC2 managed guest incarnation or operator differs")
	}
	return instance, nil
}
func (a *LambdaCapacity) Observe(ctx context.Context, p lambda.CapacityProviderRecord, g lambda.CapacityGuestRecord) (lambda.CapacityGuestRecord, error) {
	role, err := a.roleContext(ctx, p, false)
	if err != nil {
		return g, err
	}
	instance, err := a.instance(role, p, g)
	if err != nil {
		return g, err
	}
	state := ""
	if instance.State != nil {
		state = capacityValue(instance.State.Name)
	}
	if state == "pending" {
		return g, nil
	}
	if state != "running" {
		return g, &managed.RemoteError{Status: 410, Message: fmt.Sprintf("managed guest EC2 state is %s", state)}
	}
	address := capacityValue(instance.PrivateIpAddress)
	if net.ParseIP(address) == nil {
		return g, errors.New("EC2 managed guest has no private address")
	}
	g.Endpoint = "https://" + net.JoinHostPort(address, strconv.Itoa(a.Config.AgentPort))
	if g.CommandID == "" {
		script, err := a.bootstrap(g, p)
		if err != nil {
			return g, err
		}
		raw, err := capacityCommand(role, a.SSM, "ssm", "SendCommand", &ssmapi.SendCommandRequest{DocumentName: new(ssmapi.DocumentARN("AWS-RunShellScript")), InstanceIds: ssmapi.InstanceIdList{ssmapi.InstanceId(g.InstanceID)}, Parameters: ssmapi.Parameters{"commands": ssmapi.ParameterValueList{ssmapi.ParameterValue(script)}}, TimeoutSeconds: new(ssmapi.TimeoutSeconds(600))})
		var rejected *awswire.Error
		if errors.As(err, &rejected) && rejected.Code == "InvalidInstanceId" {
			return g, nil
		}
		if err != nil {
			return g, err
		}
		command, ok := raw.(*ssmapi.SendCommandResult)
		if !ok || command.Command == nil || command.Command.CommandId == nil {
			return g, errors.New("SSM did not admit managed guest bootstrap")
		}
		g.CommandID = capacityValue(command.Command.CommandId)
		g.State = "Bootstrapping"
		return g, nil
	}
	raw, err := capacityCommand(role, a.SSM, "ssm", "GetCommandInvocation", &ssmapi.GetCommandInvocationRequest{CommandId: new(ssmapi.CommandId(g.CommandID)), InstanceId: new(ssmapi.InstanceId(g.InstanceID))})
	if err != nil {
		return g, err
	}
	command, ok := raw.(*ssmapi.GetCommandInvocationResult)
	if !ok {
		return g, errors.New("SSM bootstrap status has unexpected type")
	}
	switch capacityValue(command.Status) {
	case "Pending", "InProgress", "Delayed":
		return g, nil
	case "Success":
		client, err := managed.NewClient(g.Endpoint, managed.Identity{ProviderARN: p.Key.ARN(), Generation: g.Generation, Token: g.AgentToken}, g.AgentCertificate)
		if err != nil {
			return g, err
		}
		defer client.Close()
		if err = client.Ready(ctx); err != nil {
			return g, fmt.Errorf("managed guest agent readiness: %w", err)
		}
		g.State = "Ready"
		return g, nil
	default:
		g.CommandID = ""
		g.State = "Pending"
		return g, &managed.RemoteError{Status: 422, Message: fmt.Sprintf("managed guest SSM bootstrap %s: %s", capacityValue(command.Status), capacityValue(command.StandardErrorContent))}
	}
}
func (a *LambdaCapacity) bootstrap(g lambda.CapacityGuestRecord, p lambda.CapacityProviderRecord) (string, error) {
	config := managed.AgentConfig{Identity: managed.Identity{ProviderARN: p.Key.ARN(), Generation: g.Generation, Token: g.AgentToken}, ListenAddress: net.JoinHostPort("0.0.0.0", strconv.Itoa(a.Config.AgentPort)), CertificateFile: "/etc/stackd-lambda-agent.crt", PrivateKeyFile: "/etc/stackd-lambda-agent.key", StateDirectory: "/var/lib/stackd-lambda-managed", Images: a.Config.Images}
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	encode := func(data []byte) string { return base64.StdEncoding.EncodeToString(data) }
	// Replayed Run Command delivery is idempotent and must not restart a live agent
	// or overwrite another incarnation's private control capability.
	script := "set -eu\numask 077\ncommand -v stackd-lambda-agent >/dev/null\ncommand -v docker >/dev/null\n"
	script += "printf '%s' '" + encode(encoded) + "' | base64 -d > /etc/stackd-lambda-agent.next\n"
	script += "if test -e /etc/stackd-lambda-agent.json; then cmp -s /etc/stackd-lambda-agent.json /etc/stackd-lambda-agent.next || { rm -f /etc/stackd-lambda-agent.next; echo 'guest incarnation mismatch' >&2; exit 1; }; rm -f /etc/stackd-lambda-agent.next; else mv /etc/stackd-lambda-agent.next /etc/stackd-lambda-agent.json; fi\n"
	script += "printf '%s' '" + encode(g.AgentCertificate) + "' | base64 -d > /etc/stackd-lambda-agent.crt\nprintf '%s' '" + encode(g.AgentPrivateKey) + "' | base64 -d > /etc/stackd-lambda-agent.key\n"
	script += "systemctl start stackd-lambda-agent.service\nsystemctl is-active --quiet stackd-lambda-agent.service\n"
	return script, nil
}
func (a *LambdaCapacity) Client(ctx context.Context, p lambda.CapacityProviderRecord, g lambda.CapacityGuestRecord) (*managed.Client, error) {
	role, err := a.roleContext(ctx, p, false)
	if err != nil {
		return nil, err
	}
	instance, err := a.instance(role, p, g)
	if err != nil {
		return nil, err
	}
	if instance.State == nil || capacityValue(instance.State.Name) != "running" {
		return nil, &managed.RemoteError{Status: 410, Message: "Managed EC2 guest is not running"}
	}
	if g.State != "Ready" || g.Endpoint == "" {
		return nil, errors.New("managed guest has not completed bootstrap")
	}
	return managed.NewClient(g.Endpoint, managed.Identity{ProviderARN: p.Key.ARN(), Generation: g.Generation, Token: g.AgentToken}, g.AgentCertificate)
}
func (a *LambdaCapacity) Terminate(ctx context.Context, p lambda.CapacityProviderRecord, g lambda.CapacityGuestRecord) error {
	role, err := a.roleContext(ctx, p, true)
	if err != nil {
		return err
	}
	if g.InstanceID == "" {
		raw, err := capacityCommand(role, a.EC2, "ec2", "DescribeInstances", &ec2api.DescribeInstancesRequest{Filters: ec2api.FilterList{{Name: new(ec2api.String("client-token")), Values: ec2api.ValueStringList{ec2api.String(g.Generation)}}}})
		if err != nil {
			return err
		}
		result, ok := raw.(*ec2api.DescribeInstancesResult)
		if !ok {
			return errors.New("invalid EC2 managed guest lookup response")
		}
		for _, reservation := range result.Reservations {
			for _, instance := range reservation.Instances {
				if g.InstanceID != "" {
					return errors.New("multiple EC2 guests match the retained capacity generation")
				}
				g.InstanceID = capacityValue(instance.InstanceId)
			}
		}
		if g.InstanceID == "" {
			return nil
		}
	}
	instance, err := a.instance(role, p, g)
	if err != nil {
		return err
	}
	if instance.State != nil && capacityValue(instance.State.Name) == "terminated" {
		return nil
	}
	_, rejected := a.EC2.TerminateLambdaManagedInstance(role, p.Key.ARN(), &ec2api.TerminateInstancesRequest{InstanceIds: ec2api.InstanceIdStringList{ec2api.InstanceId(g.InstanceID)}})
	if rejected != nil {
		return rejected
	}
	// Admission is not proof of native cleanup. The retained row remains until a
	// later EC2 observation confirms terminal state through this same method.
	return &managed.RemoteError{Status: 409, Message: "Managed EC2 guest termination is in progress"}
}
