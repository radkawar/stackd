package integrations

import (
	"context"
	"errors"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
	"stackd/internal/services/elbv2"
	"stackd/internal/services/iam"
)

// ELBV2Networks delegates ENI, address and packet-policy authority to EC2. IAM
// owns the linked role and the existing ServiceRoles authority issues sessions;
// neither public callers nor retained ALB records receive copied EC2 authority.
type ELBV2Networks struct {
	EC2      *ec2.Service
	Roles    *iam.Service
	Sessions ServiceRoles
	sessions serviceRoleSessions
}

var _ elbv2.NetworkAuthority = (*ELBV2Networks)(nil)

func elbv2ScopeContext(ctx context.Context, scope elbv2.Scope) error {
	m := awsctx.FromContext(ctx)
	if scope.Partition == "" || scope.AccountID == "" || scope.Region == "" || m.Partition != scope.Partition || m.AccountID != scope.AccountID || m.Region != scope.Region {
		return errors.New("elbv2: resource and request scopes differ")
	}
	return nil
}

func (a *ELBV2Networks) serviceContext(ctx context.Context, scope elbv2.Scope, owner string, ensure bool) (context.Context, error) {
	if a.EC2 == nil || a.Roles == nil {
		return nil, errors.New("elbv2: EC2 and IAM network authorities are not configured")
	}
	if err := elbv2ScopeContext(ctx, scope); err != nil {
		return nil, err
	}
	if ensure {
		if err := a.Roles.EnsureServiceLinkedRole(ctx, "elasticloadbalancing.amazonaws.com"); err != nil {
			return nil, err
		}
	}
	m := awsctx.FromContext(ctx)
	if parent := apievents.EventID(ctx); parent != "" {
		m.ParentEventID = parent
		ctx = awsctx.WithMetadata(ctx, m)
	}
	role := "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing"
	return a.sessions.context(ctx, a.Sessions, awsctx.ServicePrincipal{Name: "elasticloadbalancing.amazonaws.com", SourceARN: owner, Type: "AWSService"}, role, "elbv2-eni-provisioning", "")
}

func (a *ELBV2Networks) Validate(ctx context.Context, scope elbv2.Scope, subnets, groups []string) (string, api.AvailabilityZones, error) {
	service, err := a.serviceContext(ctx, scope, "", true)
	if err != nil {
		return "", nil, err
	}
	vpc, selected, err := a.EC2.ValidateLoadBalancerNetworks(service, subnets, groups)
	if err != nil {
		return "", nil, err
	}
	zones := make(api.AvailabilityZones, len(selected))
	for i, subnet := range selected {
		zones[i] = api.AvailabilityZone{SubnetId: new(api.SubnetId(subnet.Key.ID)), ZoneName: new(api.ZoneName(ecsNetworkString(subnet.Data.AvailabilityZone)))}
	}
	return vpc, zones, nil
}

func (a *ELBV2Networks) ValidateVPC(ctx context.Context, scope elbv2.Scope, vpcID string) error {
	service, err := a.serviceContext(ctx, scope, "", true)
	if err != nil {
		return err
	}
	return a.EC2.ValidateLoadBalancerVPC(service, vpcID)
}

func (a *ELBV2Networks) DefaultSecurityGroups(ctx context.Context, scope elbv2.Scope, vpcID string) ([]string, error) {
	service, err := a.serviceContext(ctx, scope, "", false)
	if err != nil {
		return nil, err
	}
	return a.EC2.DefaultLoadBalancerSecurityGroups(service, vpcID)
}

func (a *ELBV2Networks) Allocate(ctx context.Context, scope elbv2.Scope, owner, subnetID string, generation uint64, internetFacing bool, groups []string) (elbv2.NetworkAttachment, error) {
	service, err := a.serviceContext(ctx, scope, owner, false)
	if err != nil {
		return elbv2.NetworkAttachment{}, err
	}
	attachment, err := a.EC2.AllocateLoadBalancerNetwork(service, owner, subnetID, generation, internetFacing, groups)
	if err != nil {
		return elbv2.NetworkAttachment{}, err
	}
	return elbv2NetworkAttachment(attachment), nil
}

func (a *ELBV2Networks) Observe(ctx context.Context, scope elbv2.Scope, owner, id string) (elbv2.NetworkAttachment, error) {
	service, err := a.serviceContext(ctx, scope, owner, false)
	if err != nil {
		return elbv2.NetworkAttachment{}, err
	}
	attachment, err := a.EC2.ObserveLoadBalancerNetwork(service, owner, id)
	if errors.Is(err, ec2.ErrNotFound) {
		return elbv2.NetworkAttachment{}, elbv2.ErrNotFound
	}
	if err != nil {
		return elbv2.NetworkAttachment{}, err
	}
	return elbv2NetworkAttachment(attachment), nil
}

func (a *ELBV2Networks) SetSecurityGroups(ctx context.Context, scope elbv2.Scope, owner, id string, groups []string) (elbv2.NetworkAttachment, error) {
	service, err := a.serviceContext(ctx, scope, owner, false)
	if err != nil {
		return elbv2.NetworkAttachment{}, err
	}
	attachment, err := a.EC2.SetLoadBalancerSecurityGroups(service, owner, id, groups)
	if errors.Is(err, ec2.ErrNotFound) {
		return elbv2.NetworkAttachment{}, elbv2.ErrNotFound
	}
	if err != nil {
		return elbv2.NetworkAttachment{}, err
	}
	return elbv2NetworkAttachment(attachment), nil
}

func (a *ELBV2Networks) Release(ctx context.Context, scope elbv2.Scope, owner, id string) error {
	service, err := a.serviceContext(ctx, scope, owner, false)
	if err != nil {
		return err
	}
	return a.EC2.ReleaseLoadBalancerNetwork(service, owner, id)
}

func (a *ELBV2Networks) ResolveTarget(ctx context.Context, scope elbv2.Scope, vpcID, targetType, targetID string) (elbv2.TargetEndpoint, error) {
	service, err := a.serviceContext(ctx, scope, "", false)
	if err != nil {
		return elbv2.TargetEndpoint{}, err
	}
	endpoint, err := a.EC2.ResolveLoadBalancerTarget(service, vpcID, targetType, targetID)
	if err != nil {
		return elbv2.TargetEndpoint{}, err
	}
	return elbv2.TargetEndpoint{Address: endpoint.Address, AvailabilityZone: endpoint.AvailabilityZone, InterfaceID: endpoint.InterfaceID, OwnerARN: endpoint.OwnerARN, Incarnation: endpoint.Incarnation}, nil
}

func elbv2NetworkAttachment(attachment ec2.LoadBalancerNetwork) elbv2.NetworkAttachment {
	out := elbv2.NetworkAttachment{ID: ecsNetworkString(attachment.Interface.NetworkInterfaceId), SubnetID: ecsNetworkString(attachment.Interface.SubnetId), Network: attachment.Network}
	if address := attachment.Network.Policy.PublicIPv4; address.IsValid() {
		out.PublicAddress = address.String()
	}
	return out
}
