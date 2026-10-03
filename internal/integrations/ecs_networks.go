package integrations

import (
	"context"
	"errors"

	"stackd/compute/network"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
	"stackd/internal/services/ecs"
)

// ECSTaskNetworks issues a native ECS service-linked role session. Public callers
// never receive EC2 permissions from this adapter.
type ECSTaskNetworks struct {
	EC2      *ec2.Service
	Roles    ServiceRoles
	sessions serviceRoleSessions
}

var _ ecs.TaskNetworks = (*ECSTaskNetworks)(nil)

func (a *ECSTaskNetworks) serviceContext(ctx context.Context, taskARN string) (context.Context, error) {
	if a.EC2 == nil {
		return nil, errors.New("ecs: EC2 task network service is not configured")
	}
	m := awsctx.FromContext(ctx)
	roleARN := "arn:" + m.Partition + ":iam::" + m.AccountID + ":role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"
	return a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: "ecs.amazonaws.com", SourceARN: taskARN, Type: "AWSService"}, roleARN, "ecs-eni-provisioning", "")
}

func (a *ECSTaskNetworks) Select(ctx context.Context, clusterARN string, configuration api.AwsVpcConfiguration) (ecs.TaskPlacement, error) {
	service, err := a.serviceContext(ctx, clusterARN)
	if err != nil {
		return ecs.TaskPlacement{}, err
	}
	subnet, err := a.EC2.SelectTaskSubnet(service, ecsNetworkStrings(configuration.Subnets), ecsNetworkStrings(configuration.SecurityGroups))
	if err != nil {
		return ecs.TaskPlacement{}, err
	}
	return ecs.TaskPlacement{SubnetID: subnet.Key.ID, AvailabilityZone: ecsNetworkString(subnet.Data.AvailabilityZone)}, nil
}

func (a *ECSTaskNetworks) Allocate(ctx context.Context, taskARN string, attachment api.Attachment, configuration api.AwsVpcConfiguration) (ecs.TaskNetwork, error) {
	var out ecs.TaskNetwork
	service, err := a.serviceContext(ctx, taskARN)
	if err != nil {
		return out, err
	}
	subnetID := ecsNetworkDetail(attachment, "subnetId")
	if subnetID == "" {
		return out, errors.New("ecs: PRECREATED network attachment has no selected subnet")
	}
	selected := false
	for _, subnet := range configuration.Subnets {
		if string(subnet) == subnetID {
			selected = true
			break
		}
	}
	if !selected {
		return out, errors.New("ecs: selected subnet is outside task network configuration")
	}
	attachmentARN, err := ecsNetworkAttachmentARN(service, attachment)
	if err != nil {
		return out, err
	}
	network, err := a.EC2.AllocateTaskNetwork(service, ec2.TaskNetworkRequest{TaskARN: taskARN, AttachmentARN: attachmentARN, SubnetID: subnetID, SecurityGroups: ecsNetworkStrings(configuration.SecurityGroups), PublicNetworking: ecsNetworkString(configuration.AssignPublicIp) == "ENABLED"})
	if err != nil {
		return out, err
	}
	out.Network = network.Network
	out.Attachment = api.Attachment{Id: attachment.Id, Type: new(api.String("ElasticNetworkInterface")), Status: new(api.String("ATTACHED"))}
	for _, detail := range []struct{ name, value string }{
		{"subnetId", ecsNetworkString(network.Interface.SubnetId)},
		{"networkInterfaceId", ecsNetworkString(network.Interface.NetworkInterfaceId)},
		{"macAddress", ecsNetworkString(network.Interface.MacAddress)},
		{"privateIPv4Address", ecsNetworkString(network.Interface.PrivateIpAddress)},
	} {
		out.Attachment.Details = append(out.Attachment.Details, api.KeyValuePair{Name: new(api.String(detail.name)), Value: new(api.String(detail.value))})
	}
	if dns := ecsNetworkString(network.Interface.PrivateDnsName); dns != "" {
		out.Attachment.Details = append(out.Attachment.Details, api.KeyValuePair{Name: new(api.String("privateDnsName")), Value: new(api.String(dns))})
	}
	return out, nil
}

func (a *ECSTaskNetworks) Resolve(ctx context.Context, taskARN string, attachment api.Attachment) (network.Specification, error) {
	service, err := a.serviceContext(ctx, taskARN)
	if err != nil {
		return network.Specification{}, err
	}
	arn, err := ecsNetworkAttachmentARN(service, attachment)
	if err != nil {
		return network.Specification{}, err
	}
	return a.EC2.ResolveTaskNetwork(service, taskARN, arn, ecsNetworkDetail(attachment, "networkInterfaceId"))
}

func (a *ECSTaskNetworks) Release(ctx context.Context, taskARN string, attachment api.Attachment) error {
	id := ecsNetworkDetail(attachment, "networkInterfaceId")
	if id == "" {
		return nil
	} // PRECREATED has no committed reservation to release.
	service, err := a.serviceContext(ctx, taskARN)
	if err != nil {
		return err
	}
	arn, err := ecsNetworkAttachmentARN(service, attachment)
	if err != nil {
		return err
	}
	return a.EC2.ReleaseTaskNetwork(service, taskARN, arn, id)
}

func ecsNetworkAttachmentARN(ctx context.Context, attachment api.Attachment) (string, error) {
	id := ecsNetworkString(attachment.Id)
	if id == "" {
		return "", errors.New("ecs: network attachment has no identity")
	}
	m := awsctx.FromContext(ctx)
	return "arn:" + m.Partition + ":ecs:" + m.Region + ":" + m.AccountID + ":attachment/" + id, nil
}

func ecsNetworkDetail(attachment api.Attachment, name string) string {
	for _, detail := range attachment.Details {
		if ecsNetworkString(detail.Name) == name {
			return ecsNetworkString(detail.Value)
		}
	}
	return ""
}

func ecsNetworkStrings(values api.StringList) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = string(value)
	}
	return out
}

func ecsNetworkString[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
