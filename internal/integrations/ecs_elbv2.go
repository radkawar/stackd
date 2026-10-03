package integrations

import (
	"context"
	"errors"

	ecsapi "stackd/internal/awsapi/ecs"
	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
	"stackd/internal/services/ecs"
	"stackd/internal/services/elbv2"
)

// ECSLoadBalancers consumes owner commands under freshly evaluated ECS linked-role
// authority. It never reads ELB or EC2 repositories or borrows caller permissions.
type ECSLoadBalancers struct {
	ELBv2    *elbv2.Service
	EC2      *ec2.Service
	Roles    ServiceRoles
	sessions serviceRoleSessions
}

var _ ecs.ServiceLoadBalancers = (*ECSLoadBalancers)(nil)

func (a *ECSLoadBalancers) serviceContext(ctx context.Context, sourceARN string) (context.Context, elbv2.Scope, error) {
	m := awsctx.FromContext(ctx)
	scope := elbv2.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
	if a.ELBv2 == nil || a.EC2 == nil {
		return nil, scope, errors.New("ecs: ELBv2 task target lifecycle is not configured")
	}
	roleARN := "arn:" + m.Partition + ":iam::" + m.AccountID + ":role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"
	service, err := a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: "ecs.amazonaws.com", SourceARN: sourceARN, Type: "AWSService"}, roleARN, "ecs-load-balancing", "")
	return service, scope, err
}

func (a *ECSLoadBalancers) Validate(ctx context.Context, serviceARN string, configuration ecsapi.AwsVpcConfiguration, bindings ecsapi.LoadBalancers) error {
	service, scope, err := a.serviceContext(ctx, serviceARN)
	if err != nil {
		return err
	}
	subnet, err := a.EC2.SelectTaskSubnet(service, ecsNetworkStrings(configuration.Subnets), ecsNetworkStrings(configuration.SecurityGroups))
	if err != nil {
		return err
	}
	vpcID := ecsNetworkString(subnet.Data.VpcId)
	if vpcID == "" {
		return &awswire.Error{Code: "InvalidParameterException", Message: "A load balanced service requires a VPC subnet.", StatusCode: 400}
	}
	for _, binding := range bindings {
		if err := a.ELBv2.ValidateTargetGroup(service, scope, ecsNetworkString(binding.TargetGroupArn), vpcID); err != nil {
			return err
		}
	}
	return nil
}

func ecsELBTarget(target ecs.ServiceTarget) api.TargetDescription {
	return api.TargetDescription{Id: new(api.TargetId(target.PrivateIP)), Port: new(api.Port(target.Port))}
}

func (a *ECSLoadBalancers) Register(ctx context.Context, target ecs.ServiceTarget) error {
	service, scope, err := a.serviceContext(ctx, target.TaskARN)
	if err != nil {
		return err
	}
	network, err := a.EC2.ResolveTaskNetwork(service, target.TaskARN, target.AttachmentARN, target.NetworkInterfaceID)
	if err != nil {
		return err
	}
	if network.Address.String() != target.PrivateIP {
		return errors.New("ecs: target address no longer belongs to the task ENI")
	}
	return a.ELBv2.RegisterOwnedTarget(service, scope, target.TargetGroupARN, ecsELBTarget(target), target.TaskARN, target.NetworkInterfaceID)
}

func (a *ECSLoadBalancers) Health(ctx context.Context, target ecs.ServiceTarget) (ecs.ServiceTargetHealth, error) {
	service, scope, err := a.serviceContext(ctx, target.TaskARN)
	if err != nil {
		return ecs.ServiceTargetInitial, err
	}
	observed, exists, err := a.ELBv2.OwnedTargetHealth(service, scope, target.TargetGroupARN, ecsELBTarget(target), target.TaskARN, target.NetworkInterfaceID)
	if err != nil || !exists {
		return ecs.ServiceTargetInitial, err
	}
	return ecs.ServiceTargetHealth(observed.State), nil
}

func (a *ECSLoadBalancers) Deregister(ctx context.Context, target ecs.ServiceTarget) error {
	service, scope, err := a.serviceContext(ctx, target.TaskARN)
	if err != nil {
		return err
	}
	return a.ELBv2.DeregisterOwnedTarget(service, scope, target.TargetGroupARN, ecsELBTarget(target), target.TaskARN, target.NetworkInterfaceID)
}

func (a *ECSLoadBalancers) Drained(ctx context.Context, target ecs.ServiceTarget) (bool, error) {
	service, scope, err := a.serviceContext(ctx, target.TaskARN)
	if err != nil {
		return false, err
	}
	_, exists, err := a.ELBv2.OwnedTargetHealth(service, scope, target.TargetGroupARN, ecsELBTarget(target), target.TaskARN, target.NetworkInterfaceID)
	return !exists && err == nil, err
}
