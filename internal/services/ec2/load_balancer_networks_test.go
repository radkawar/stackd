package ec2_test

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	ecsapi "stackd/internal/awsapi/ecs"
	elbapi "stackd/internal/awsapi/elbv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/integrations"
	"stackd/internal/services/ec2"
	"stackd/internal/services/elbv2"
	"stackd/internal/services/iam"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
	sqlelb "stackd/storage/sqlite/elbv2"
	sqliam "stackd/storage/sqlite/iam"
)

type loadBalancerNetworkFixture struct {
	ctx     context.Context
	scope   elbv2.Scope
	service *ec2.Service
	iam     *iam.Service
	roles   integrations.ServiceRoles
	repo    ec2.Repository
	iamRepo iam.Repository
	adapter *integrations.ELBV2Networks
	vpc     string
	subnets []string
	owner   string
}

func loadBalancerCommand[T any](t *testing.T, f loadBalancerNetworkFixture, action string, input any) *T {
	t.Helper()
	model, _ := awscatalog.LookupService("ec2")
	op, ok := model.Operation(action)
	if !ok {
		t.Fatalf("unknown EC2 operation %s", action)
	}
	result, err := f.service.ExecuteCommand(f.ctx, awsapi.DecodedRequest{Operation: op, Input: input})
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return result.(*T)
}

func newLoadBalancerNetworkFixture(t *testing.T) loadBalancerNetworkFixture {
	t.Helper()
	return newLoadBalancerNetworkFixtureWithRepositories(t, ec2.NewMemoryRepository(nil), iam.NewMemoryRepository(nil))
}

func newLoadBalancerNetworkFixtureWithRepositories(t *testing.T, repository ec2.Repository, iamRepository iam.Repository) loadBalancerNetworkFixture {
	t.Helper()
	f := loadBalancerNetworkFixture{scope: elbv2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, repo: repository, iamRepo: iamRepository}
	f.ctx = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: f.scope.Partition, AccountID: f.scope.AccountID, Region: f.scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: f.scope.AccountID})
	credentials := identity.NewWithConfig(identity.Config{AccountID: f.scope.AccountID, Repository: iam.NewCredentialRepository(f.iamRepo, nil)})
	f.iam = iam.NewWithConfig(iam.Config{Repository: f.iamRepo, Credentials: credentials})
	authorizer := authorization.New(f.iam, nil)
	f.roles = integrations.ServiceRoles{IAM: f.iam, Credentials: credentials, Authorizer: authorizer}
	f.service = ec2.New(ec2.Config{Repository: f.repo, Authorizer: authorizer})
	t.Cleanup(func() { _ = f.service.Close(); _ = f.iam.Close() })
	f.adapter = &integrations.ELBV2Networks{EC2: f.service, Roles: f.iam, Sessions: f.roles}
	f.owner = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/network-test/0123456789abcdef"
	vpc := loadBalancerCommand[api.CreateVpcResult](t, f, "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.42.0.0/16"))})
	f.vpc = string(*vpc.Vpc.VpcId)
	for i, zone := range []string{"us-east-1a", "us-east-1b"} {
		cidr := []string{"10.42.1.0/24", "10.42.2.0/24"}[i]
		subnet := loadBalancerCommand[api.CreateSubnetResult](t, f, "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(f.vpc)), CidrBlock: new(api.String(cidr)), AvailabilityZone: new(api.String(zone))})
		f.subnets = append(f.subnets, string(*subnet.Subnet.SubnetId))
	}
	return f
}

func TestLoadBalancerNetworkExactOwnershipAndReplay(t *testing.T) {
	f := newLoadBalancerNetworkFixture(t)
	vpc, zones, err := f.adapter.Validate(f.ctx, f.scope, f.subnets, nil)
	if err != nil || vpc != f.vpc || len(zones) != 2 || string(*zones[0].SubnetId) != f.subnets[0] || string(*zones[1].ZoneName) != "us-east-1b" {
		t.Fatalf("validated topology = %s %#v, %v", vpc, zones, err)
	}
	if _, _, err := f.adapter.Validate(f.ctx, f.scope, []string{f.subnets[0], f.subnets[0]}, nil); err == nil {
		t.Fatal("two copies of one AZ admitted")
	}
	allocated, err := f.adapter.Allocate(f.ctx, f.scope, f.owner, f.subnets[0], 1, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := f.adapter.Allocate(f.ctx, f.scope, f.owner, f.subnets[0], 1, false, nil)
	if err != nil || repeated.ID != allocated.ID || repeated.Network.Address != allocated.Network.Address {
		t.Fatalf("retry changed the reservation: %#v %v", repeated, err)
	}
	if _, err := f.adapter.Allocate(f.ctx, f.scope, f.owner, f.subnets[0], 2, false, nil); err == nil {
		t.Fatal("a second generation displaced an unreleased subnet attachment")
	}
	if allocated.Network.Address != netip.MustParseAddr("10.42.1.4") || allocated.Network.NetworkID != "arn:aws:ec2:us-east-1:123456789012:vpc/"+f.vpc {
		t.Fatalf("not an EC2 reservation: %#v", allocated.Network)
	}
	if err := f.adapter.Release(f.ctx, f.scope, f.owner+"-other", allocated.ID); err == nil {
		t.Fatal("another ALB incarnation released this reservation")
	}
	if err := f.repo.View(f.ctx, func(tx ec2.Reader) error {
		record, err := tx.NetworkInterface(ec2.ResourceKey{Scope: ec2.Scope(f.scope), ID: allocated.ID})
		if err != nil {
			return err
		}
		if record.TaskOwnerARN != "" || record.Data.RequesterManaged == nil || !bool(*record.Data.RequesterManaged) {
			t.Fatal("ALB interface became an ECS task or lost service ownership")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.adapter.Release(f.ctx, f.scope, f.owner, allocated.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.adapter.Release(f.ctx, f.scope, f.owner, allocated.ID); err != nil {
		t.Fatalf("repeated cleanup: %v", err)
	}
	if _, err := f.adapter.Observe(f.ctx, f.scope, f.owner, allocated.ID); !errors.Is(err, elbv2.ErrNotFound) {
		t.Fatalf("released interface remains observable: %v", err)
	}
	if _, err := f.adapter.Allocate(f.ctx, f.scope, f.owner, f.subnets[0], 1, false, nil); err == nil {
		t.Fatal("retained creation token resurrected a released ALB reservation")
	}
	other, err := f.adapter.Allocate(f.ctx, f.scope, f.owner, f.subnets[0], 2, false, nil)
	if err != nil || other.ID == allocated.ID || other.Network.Address != allocated.Network.Address {
		t.Fatalf("address capacity not returned to a new incarnation: %#v %v", other, err)
	}
	if err := f.adapter.Release(f.ctx, f.scope, f.owner, allocated.ID); err != nil {
		t.Fatal(err)
	}
	current, err := f.adapter.Observe(f.ctx, f.scope, f.owner, other.ID)
	if err != nil || current.ID != other.ID || current.Network.Address != other.Network.Address {
		t.Fatalf("stale cleanup damaged the new attachment generation: %#v %v", current, err)
	}
	cross := f.scope
	cross.Region = "us-west-2"
	if _, err := f.adapter.Observe(f.ctx, cross, f.owner, other.ID); err == nil {
		t.Fatal("cross-region adapter context accepted")
	}
}

func TestLoadBalancerNetworkCurrentPolicyAndTargetOwnership(t *testing.T) {
	f := newLoadBalancerNetworkFixture(t)
	if _, _, err := f.adapter.Validate(f.ctx, f.scope, f.subnets, nil); err != nil {
		t.Fatal(err)
	}
	allocated, err := f.adapter.Allocate(f.ctx, f.scope, f.owner, f.subnets[0], 1, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	group := loadBalancerCommand[api.CreateSecurityGroupResult](t, f, "CreateSecurityGroup", &api.CreateSecurityGroupRequest{VpcId: new(api.VpcId(f.vpc)), GroupName: new(api.String("alb-web")), Description: new(api.String("ALB web"))})
	loadBalancerCommand[api.AuthorizeSecurityGroupIngressResult](t, f, "AuthorizeSecurityGroupIngress", &api.AuthorizeSecurityGroupIngressRequest{GroupId: new(api.SecurityGroupId(*group.GroupId)), IpPermissions: api.IpPermissionList{{IpProtocol: new(api.String("tcp")), FromPort: new(api.Integer(8080)), ToPort: new(api.Integer(8080)), IpRanges: api.IpRangeList{{CidrIp: new(api.String("10.42.2.0/24"))}}}}})
	updated, err := f.adapter.SetSecurityGroups(f.ctx, f.scope, f.owner, allocated.ID, []string{string(*group.GroupId)})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Network.Policy.SecurityIngress) != 1 || updated.Network.Policy.SecurityIngress[0].FromPort != 8080 || updated.Network.Policy.SecurityIngress[0].CIDR != netip.MustParsePrefix("10.42.2.0/24") {
		t.Fatalf("SG replacement did not reach current packet policy: %#v", updated.Network.Policy)
	}
	acls := loadBalancerCommand[api.DescribeNetworkAclsResult](t, f, "DescribeNetworkAcls", &api.DescribeNetworkAclsRequest{})
	aclID := ""
	for _, acl := range acls.NetworkAcls {
		for _, association := range acl.Associations {
			if string(*association.SubnetId) == f.subnets[0] {
				aclID = string(*acl.NetworkAclId)
			}
		}
	}
	if aclID == "" {
		t.Fatal("subnet has no current EC2 ACL")
	}
	loadBalancerCommand[api.Unit](t, f, "CreateNetworkAclEntry", &api.CreateNetworkAclEntryRequest{NetworkAclId: new(api.NetworkAclId(aclID)), Egress: new(api.Boolean(false)), RuleNumber: new(api.Integer(50)), RuleAction: new(api.RuleAction("deny")), Protocol: new(api.String("6")), PortRange: &api.PortRange{From: new(api.Integer(8080)), To: new(api.Integer(8080))}, CidrBlock: new(api.String("10.42.2.0/24"))})
	current, err := f.adapter.Observe(f.ctx, f.scope, f.owner, allocated.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Network.Policy.ACLIngress) == 0 || current.Network.Policy.ACLIngress[0].Number != 50 || current.Network.Policy.ACLIngress[0].Allow || current.Network.Policy.ACLIngress[0].Rule.FromPort != 8080 {
		t.Fatalf("current NACL denial did not precede allowed traffic: %#v", current.Network.Policy.ACLIngress)
	}
	if err := f.iam.EnsureServiceLinkedRole(f.ctx, "ecs.amazonaws.com"); err != nil {
		t.Fatal(err)
	}
	tasks := &integrations.ECSTaskNetworks{EC2: f.service, Roles: f.roles}
	taskARN := "arn:aws:ecs:us-east-1:123456789012:task/network-test/actual-task"
	task, err := tasks.Allocate(f.ctx, taskARN, ecsapi.Attachment{Id: new(ecsapi.String("actual-attachment")), Details: ecsapi.AttachmentDetails{{Name: new(ecsapi.String("subnetId")), Value: new(ecsapi.String(f.subnets[1]))}}}, ecsapi.AwsVpcConfiguration{Subnets: ecsapi.StringList{ecsapi.String(f.subnets[1])}})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := f.adapter.ResolveTarget(f.ctx, f.scope, f.vpc, "ip", task.Network.Address.String())
	if err != nil || endpoint.OwnerARN != taskARN || endpoint.InterfaceID != endpoint.Incarnation || endpoint.AvailabilityZone != "us-east-1b" {
		t.Fatalf("current task endpoint = %#v, %v", endpoint, err)
	}
	for _, address := range []string{"127.0.0.1", "169.254.169.254", "8.8.8.8", "10.42.99.250"} {
		if _, err := f.adapter.ResolveTarget(f.ctx, f.scope, f.vpc, "ip", address); err == nil {
			t.Fatalf("ineligible address %s accepted", address)
		}
	}
	if err := tasks.Release(f.ctx, taskARN, task.Attachment); err != nil {
		t.Fatal(err)
	}
	released, err := f.adapter.ResolveTarget(f.ctx, f.scope, f.vpc, "ip", task.Network.Address.String())
	if err != nil || released.OwnerARN != "" || released.Incarnation != "" || released.InterfaceID != "" || released.AvailabilityZone != "us-east-1b" {
		t.Fatalf("released ECS ownership survived on a plain subnet IP target: %#v %v", released, err)
	}
	external, err := f.adapter.ResolveTarget(f.ctx, f.scope, f.vpc, "ip", "192.168.253.254")
	if err != nil || external.AvailabilityZone != "all" || external.InterfaceID != "" || external.OwnerARN != "" {
		t.Fatalf("outside-VPC private target invented topology or ownership: %#v %v", external, err)
	}
	// An already issued service session must not outlive its IAM role identity.
	if err := f.iamRepo.Update(f.ctx, func(tx iam.WriteTx) error {
		return tx.DeleteRole(iam.Scope{Partition: f.scope.Partition, AccountID: f.scope.AccountID}, "AWSServiceRoleForElasticLoadBalancing")
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.adapter.Observe(f.ctx, f.scope, f.owner, allocated.ID); err == nil {
		t.Fatal("cached service session bypassed current IAM role deletion")
	}
}

func TestLoadBalancerNetworkAutomaticPublicAddressAndCurrentRoute(t *testing.T) {
	f := newLoadBalancerNetworkFixture(t)
	if _, _, err := f.adapter.Validate(f.ctx, f.scope, f.subnets, nil); err != nil {
		t.Fatal(err)
	}
	groups, err := f.adapter.DefaultSecurityGroups(f.ctx, f.scope, f.vpc)
	if err != nil || len(groups) != 1 {
		t.Fatalf("current default group: %v %v", groups, err)
	}
	allocated, err := f.adapter.Allocate(f.ctx, f.scope, f.owner, f.subnets[0], 1, true, groups)
	if err != nil {
		t.Fatal(err)
	}
	public := netip.MustParseAddr(allocated.PublicAddress)
	if !netip.MustParsePrefix("198.18.0.0/15").Contains(public) || allocated.Network.Policy.PublicIPv4 != public || allocated.Network.Policy.PublicEgress {
		t.Fatalf("public allocation without IGW invented packet admission: %#v", allocated)
	}
	repeated, err := f.adapter.Allocate(f.ctx, f.scope, f.owner, f.subnets[0], 1, true, groups)
	if err != nil || repeated.PublicAddress != allocated.PublicAddress || repeated.ID != allocated.ID {
		t.Fatalf("public replay changed the assignment: %#v %v", repeated, err)
	}
	if _, err := f.adapter.Allocate(f.ctx, f.scope, f.owner, f.subnets[0], 1, false, groups); err == nil {
		t.Fatal("allocation replay changed the retained load-balancer scheme")
	}
	addresses := loadBalancerCommand[api.DescribeAddressesResult](t, f, "DescribeAddresses", &api.DescribeAddressesRequest{})
	if len(addresses.Addresses) != 0 {
		t.Fatal("automatic ALB public assignment became a customer EIP")
	}
	countAssignments := func() int {
		t.Helper()
		count := 0
		if err := f.repo.View(f.ctx, func(tx ec2.Reader) error {
			rows, err := tx.PublicAddresses(ec2.Scope(f.scope))
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Data.NetworkInterfaceId != nil && string(*row.Data.NetworkInterfaceId) == allocated.ID {
					count++
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if countAssignments() != 1 {
		t.Fatal("idempotent ALB allocation leaked another public reservation")
	}
	gateway := loadBalancerCommand[api.CreateInternetGatewayResult](t, f, "CreateInternetGateway", &api.CreateInternetGatewayRequest{})
	gatewayID := string(*gateway.InternetGateway.InternetGatewayId)
	loadBalancerCommand[api.Unit](t, f, "AttachInternetGateway", &api.AttachInternetGatewayRequest{InternetGatewayId: new(api.InternetGatewayId(gatewayID)), VpcId: new(api.VpcId(f.vpc))})
	tables := loadBalancerCommand[api.DescribeRouteTablesResult](t, f, "DescribeRouteTables", &api.DescribeRouteTablesRequest{})
	tableID := ""
	for _, table := range tables.RouteTables {
		if string(*table.VpcId) == f.vpc {
			tableID = string(*table.RouteTableId)
		}
	}
	loadBalancerCommand[api.CreateRouteResult](t, f, "CreateRoute", &api.CreateRouteRequest{RouteTableId: new(api.RouteTableId(tableID)), DestinationCidrBlock: new(api.String("0.0.0.0/0")), GatewayId: new(api.RouteGatewayId(gatewayID))})
	current, err := f.adapter.Observe(f.ctx, f.scope, f.owner, allocated.ID)
	if err != nil || !current.Network.Policy.PublicEgress || current.PublicAddress != allocated.PublicAddress {
		t.Fatalf("current attached IGW route did not grant packet admission: %#v %v", current, err)
	}
	loadBalancerCommand[api.Unit](t, f, "DeleteRoute", &api.DeleteRouteRequest{RouteTableId: new(api.RouteTableId(tableID)), DestinationCidrBlock: new(api.String("0.0.0.0/0"))})
	current, err = f.adapter.Observe(f.ctx, f.scope, f.owner, allocated.ID)
	if err != nil || current.Network.Policy.PublicEgress || current.PublicAddress != allocated.PublicAddress {
		t.Fatalf("route withdrawal lost the allocation or retained admission: %#v %v", current, err)
	}
	if err := f.adapter.Release(f.ctx, f.scope, f.owner, allocated.ID); err != nil {
		t.Fatal(err)
	}
	if countAssignments() != 0 {
		t.Fatal("exact ENI cleanup leaked its automatic public assignment")
	}
	if _, err := f.adapter.Allocate(f.ctx, f.scope, f.owner, f.subnets[0], 1, false, groups); err == nil {
		t.Fatal("changing scheme bypassed the released generation token")
	}
}

func TestLoadBalancerNetworkInstanceTargetUsesCurrentPrimaryAttachment(t *testing.T) {
	f := newLoadBalancerNetworkFixture(t)
	if _, _, err := f.adapter.Validate(f.ctx, f.scope, f.subnets, nil); err != nil {
		t.Fatal(err)
	}
	created := loadBalancerCommand[api.CreateNetworkInterfaceResult](t, f, "CreateNetworkInterface", &api.CreateNetworkInterfaceRequest{SubnetId: new(api.SubnetId(f.subnets[0]))})
	interfaceID := string(*created.NetworkInterface.NetworkInterfaceId)
	instanceID := "i-0123456789abcdef0"
	// This fixture supplies retained instance lifecycle state, not a fake VMM.
	// Its private address and interface were allocated by the ordinary EC2 API.
	if err := f.repo.Update(f.ctx, func(tx ec2.Transaction) error {
		record, err := tx.NetworkInterface(ec2.ResourceKey{Scope: ec2.Scope(f.scope), ID: interfaceID})
		if err != nil {
			return err
		}
		record.Data.Status = new(api.NetworkInterfaceStatus("in-use"))
		record.Data.Attachment = &api.NetworkInterfaceAttachment{InstanceId: new(api.String(instanceID)), AttachmentId: new(api.String("eni-attach-0123456789abcdef0")), Status: new(api.AttachmentStatus("attached")), DeviceIndex: new(api.Integer(0))}
		if err := tx.PutNetworkInterface(record); err != nil {
			return err
		}
		return tx.PutInstance(ec2.InstanceRecord{Key: ec2.ResourceKey{Scope: ec2.Scope(f.scope), ID: instanceID}, Data: api.Instance{InstanceId: new(api.String(instanceID)), VpcId: record.Data.VpcId, SubnetId: record.Data.SubnetId, PrivateIpAddress: record.Data.PrivateIpAddress, State: &api.InstanceState{Name: new(api.InstanceStateName("running"))}}})
	}); err != nil {
		t.Fatal(err)
	}
	endpoint, err := f.adapter.ResolveTarget(f.ctx, f.scope, f.vpc, "instance", instanceID)
	if err != nil || endpoint.Address != string(*created.NetworkInterface.PrivateIpAddress) || endpoint.InterfaceID != interfaceID || endpoint.Incarnation != interfaceID || endpoint.OwnerARN != "arn:aws:ec2:us-east-1:123456789012:instance/"+instanceID {
		t.Fatalf("instance primary target = %#v, %v", endpoint, err)
	}
	if err := f.repo.Update(f.ctx, func(tx ec2.Transaction) error {
		record, err := tx.NetworkInterface(ec2.ResourceKey{Scope: ec2.Scope(f.scope), ID: interfaceID})
		if err != nil {
			return err
		}
		record.Data.Attachment.DeviceIndex = new(api.Integer(1))
		return tx.PutNetworkInterface(record)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.adapter.ResolveTarget(f.ctx, f.scope, f.vpc, "instance", instanceID); err == nil {
		t.Fatal("secondary ENI replaced the instance target's primary interface")
	}
	if err := f.repo.Update(f.ctx, func(tx ec2.Transaction) error {
		instance, err := tx.Instance(ec2.ResourceKey{Scope: ec2.Scope(f.scope), ID: instanceID})
		if err != nil {
			return err
		}
		instance.Data.State.Name = new(api.InstanceStateName("stopped"))
		return tx.PutInstance(instance)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.adapter.ResolveTarget(f.ctx, f.scope, f.vpc, "ip", endpoint.Address); err == nil {
		t.Fatal("IP target retained a stopped instance's live endpoint")
	}
}

func TestLoadBalancerNetworkAllocationRollsBackWithAttachmentWrite(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var networks ec2.Repository
			var roles iam.Repository
			var balancers elbv2.Repository
			if backend == "memory" {
				domain := memory.NewDomain()
				networks, roles, balancers = ec2.NewMemoryRepository(domain), iam.NewMemoryRepository(domain), elbv2.NewMemoryRepository(domain)
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "allocation.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				networks, roles, balancers = sqlec2.New(db), sqliam.New(db), sqlelb.New(db)
			}
			f := newLoadBalancerNetworkFixtureWithRepositories(t, networks, roles)
			if _, _, err := f.adapter.Validate(f.ctx, f.scope, f.subnets, nil); err != nil {
				t.Fatal(err)
			}
			var generation uint64
			if err := balancers.Update(f.ctx, func(tx elbv2.Transaction) error {
				var err error
				generation, err = tx.NextID()
				if err != nil {
					return err
				}
				return tx.PutLoadBalancer(elbv2.LoadBalancerRecord{
					Scope:                 f.scope,
					Data:                  elbapi.LoadBalancer{LoadBalancerArn: new(elbapi.LoadBalancerArn(f.owner)), LoadBalancerName: new(elbapi.LoadBalancerName("network-test")), Scheme: new(elbapi.LoadBalancerSchemeEnum("internet-facing")), VpcId: new(elbapi.VpcId(f.vpc))},
					AttachmentGenerations: map[string]uint64{f.subnets[0]: generation},
					AttachmentIDs:         map[string]string{},
				})
			}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("attachment transaction commit rejected")
			var aborted elbv2.NetworkAttachment
			allocateAndRetain := func(tx elbv2.Transaction) error {
				record, err := tx.LoadBalancer(f.scope, f.owner)
				if err != nil {
					return err
				}
				aborted, err = f.adapter.Allocate(tx.Context(), f.scope, f.owner, f.subnets[0], generation, true, nil)
				if err != nil {
					return err
				}
				record.AttachmentIDs[f.subnets[0]] = aborted.ID
				return tx.PutLoadBalancer(record)
			}
			err := balancers.Update(f.ctx, func(tx elbv2.Transaction) error {
				if err := allocateAndRetain(tx); err != nil {
					return err
				}
				return injected
			})
			if !errors.Is(err, injected) {
				t.Fatalf("allocation did not reach the injected commit failure: %v", err)
			}
			if err := balancers.View(f.ctx, func(tx elbv2.Reader) error {
				record, err := tx.LoadBalancer(f.scope, f.owner)
				if err != nil {
					return err
				}
				if record.AttachmentIDs[f.subnets[0]] != "" || record.AttachmentGenerations[f.subnets[0]] != generation {
					t.Fatalf("failed attachment write changed durable allocation intent: %#v", record)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := networks.View(f.ctx, func(tx ec2.Reader) error {
				if _, err := tx.NetworkInterface(ec2.ResourceKey{Scope: ec2.Scope(f.scope), ID: aborted.ID}); !errors.Is(err, ec2.ErrNotFound) {
					t.Fatalf("failed ALB attachment write left its EC2 ENI: %v", err)
				}
				addresses, err := tx.PublicAddresses(ec2.Scope(f.scope))
				if err != nil {
					return err
				}
				for _, address := range addresses {
					if address.Data.PublicIp != nil && string(*address.Data.PublicIp) == aborted.PublicAddress {
						t.Fatalf("failed ALB attachment write leaked public assignment %s", aborted.PublicAddress)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			failed := aborted
			// Retry the same retained generation without compensating Release:
			// a committed creation token/tombstone would reject or resurrect it.
			if err := balancers.Update(f.ctx, allocateAndRetain); err != nil {
				t.Fatalf("same-generation retry was poisoned by aborted allocation: %v", err)
			}
			if err := balancers.View(f.ctx, func(tx elbv2.Reader) error {
				record, err := tx.LoadBalancer(f.scope, f.owner)
				if err != nil {
					return err
				}
				if record.AttachmentIDs[f.subnets[0]] != aborted.ID || record.AttachmentGenerations[f.subnets[0]] != generation {
					t.Fatalf("retry committed EC2 allocation without matching ALB attachment: %#v", record)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if aborted.Network.Address != failed.Network.Address || aborted.PublicAddress != failed.PublicAddress {
				t.Fatalf("rollback did not restore private/public reservation capacity: failed=%#v retry=%#v", failed, aborted)
			}
			current, err := f.adapter.Observe(f.ctx, f.scope, f.owner, aborted.ID)
			if err != nil || current.PublicAddress != aborted.PublicAddress || current.Network.Address != aborted.Network.Address {
				t.Fatalf("committed retry is not observable: %#v %v", current, err)
			}
			if err := f.adapter.Release(f.ctx, f.scope, f.owner+"-foreign", aborted.ID); err == nil {
				t.Fatal("retry lost exact ALB ownership")
			}
			if err := f.adapter.Release(f.ctx, f.scope, f.owner, aborted.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.adapter.Observe(f.ctx, f.scope, f.owner, aborted.ID); !errors.Is(err, elbv2.ErrNotFound) {
				t.Fatalf("exact retry cleanup retained the ENI: %v", err)
			}
			if err := networks.View(f.ctx, func(tx ec2.Reader) error {
				addresses, err := tx.PublicAddresses(ec2.Scope(f.scope))
				if err != nil {
					return err
				}
				for _, address := range addresses {
					if address.Data.NetworkInterfaceId != nil && string(*address.Data.NetworkInterfaceId) == aborted.ID {
						t.Fatal("exact cleanup retained the retry's public assignment")
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
