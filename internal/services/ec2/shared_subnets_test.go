package ec2_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	ebsapi "stackd/internal/awsapi/ebs"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	ramapi "stackd/internal/awsapi/ram"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/integrations"
	"stackd/internal/services/ebs"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
	"stackd/internal/services/ram"
	"stackd/storage/memory"
	"stackd/storage/organizations"
	"stackd/storage/sqlite"
	sqlebs "stackd/storage/sqlite/ebs"
	sqlec2 "stackd/storage/sqlite/ec2"
	sqliam "stackd/storage/sqlite/iam"
	sqlorg "stackd/storage/sqlite/organizations"
	sqlram "stackd/storage/sqlite/ram"
)

type subnetCommandOwner interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}

func subnetCommand(t *testing.T, ctx context.Context, owner subnetCommandOwner, service, action string, input any) (any, *awswire.Error) {
	t.Helper()
	model, _ := awscatalog.LookupService(service)
	op, ok := model.Operation(action)
	if !ok {
		t.Fatalf("unknown operation %s:%s", service, action)
	}
	return owner.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: input})
}

func subnetResult[T any](t *testing.T, ctx context.Context, owner subnetCommandOwner, service, action string, input any) *T {
	t.Helper()
	out, rejected := subnetCommand(t, ctx, owner, service, action, input)
	if rejected != nil {
		t.Fatalf("%s:%s: %v", service, action, rejected)
	}
	return out.(*T)
}

func TestRAMSubnetParticipantLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const ownerID, participantID, outsiderID = "111111111111", "222222222222", "333333333333"
			actor := func(account, region string) context.Context {
				return awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", Region: region, AccountID: account, PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account})
			}
			owner, participant := actor(ownerID, "us-east-1"), actor(participantID, "us-east-1")
			source := clock.NewManual(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))
			domain := memory.NewDomain()
			var networks ec2.Repository = ec2.NewMemoryRepository(domain)
			var grants ram.Repository = ram.NewMemoryRepository(domain)
			var identities iam.Repository = iam.NewMemoryRepository(domain)
			var organization organizations.Storage = organizations.NewMemory(domain)
			var disks ebs.Repository = ebs.NewMemoryRepository(domain)
			var db *sql.DB
			var service *ec2.Service
			var sharing *ram.Service
			var identity *iam.Service
			var volumes *ebs.Service
			path := filepath.Join(t.TempDir(), "shared-subnet.sqlite")
			open := func() {
				t.Helper()
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					networks, grants, identities, organization, disks = sqlec2.New(db), sqlram.New(db), sqliam.New(db), sqlorg.New(db), sqlebs.New(db)
				}
				identity = iam.NewWithConfig(iam.Config{Repository: identities, Clock: source})
				authorizer := authorization.NewWithClock(identity, nil, source)
				volumes = ebs.New(ebs.Config{Repository: disks, Clock: source, Authorizer: authorizer})
				service = ec2.New(ec2.Config{Repository: networks, Clock: source, Authorizer: authorizer, ImageSnapshots: volumes, InstanceVolumes: volumes, Volumes: volumes})
				sharing = ram.New(ram.Config{Repository: grants, Clock: source, Authorizer: authorizer, Resources: integrations.RAMResources{EC2: service}, ResourceTypes: []string{"ec2:Subnet"}, Organization: integrations.RAMOrganizations{Storage: organization, IdentityRepository: identities}})
				service.SetSharedSubnets(integrations.RAMSharedSubnets{RAM: sharing})
			}
			closeOwners := func() {
				if service != nil {
					_ = service.Close()
				}
				if volumes != nil {
					_ = volumes.Close()
				}
				if identity != nil {
					_ = identity.Close()
				}
				if db != nil {
					_ = db.Close()
					db = nil
				}
			}
			open()
			t.Cleanup(closeOwners)
			graph := organizations.PartitionRecord{Organizations: []organizations.OrganizationRecord{{
				Organization: organizations.OrganizationDetails{ID: "o-subnetfixture", ARN: "arn:aws:organizations::" + ownerID + ":organization/o-subnetfixture", FeatureSet: "ALL", MasterAccountID: ownerID, MasterAccountARN: "arn:aws:organizations::" + ownerID + ":account/o-subnetfixture/" + ownerID, MasterAccountEmail: "owner@example.test"},
				Root:         organizations.RootRecord{ID: "r-subnet", ARN: "arn:aws:organizations::" + ownerID + ":root/o-subnetfixture/r-subnet", Name: "Root"},
				Accounts:     []organizations.AccountRecord{{ID: ownerID, Name: "owner", State: "ACTIVE", Status: "ACTIVE"}, {ID: participantID, Name: "participant", State: "ACTIVE", Status: "ACTIVE"}},
				Parents:      []organizations.ParentRecord{{ChildID: ownerID, ParentID: "r-subnet"}, {ChildID: participantID, ParentID: "r-subnet"}},
				Services:     []organizations.ServiceAccessRecord{{Principal: "ram.amazonaws.com"}},
			}}}
			if ok, err := organization.CompareAndSwap(owner, "aws", 0, graph, nil); err != nil || !ok {
				t.Fatalf("organization fixture: %v/%v", ok, err)
			}
			if err := identity.EnsureServiceLinkedRole(owner, "ram.amazonaws.com"); err != nil {
				t.Fatal(err)
			}
			vpc := subnetResult[api.CreateVpcResult](t, owner, service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.62.0.0/16"))}).Vpc
			subnet := subnetResult[api.CreateSubnetResult](t, owner, service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(*vpc.VpcId)), CidrBlock: new(api.String("10.62.1.0/24")), AvailabilityZone: new(api.String("us-east-1a")), TagSpecifications: api.TagSpecificationList{{ResourceType: new(api.ResourceType("subnet")), Tags: api.TagList{{Key: new(api.String("private-owner-tag")), Value: new(api.String("secret"))}}}}}).Subnet
			subnetARN := string(*subnet.SubnetArn)
			share := subnetResult[ramapi.CreateResourceShareResponse](t, owner, sharing, "ram", "CreateResourceShare", &ramapi.CreateResourceShareRequest{Name: new(ramapi.String("network")), ResourceArns: ramapi.ResourceArnList{ramapi.String(subnetARN)}, Principals: ramapi.PrincipalArnOrIdList{ramapi.String(participantID)}, AllowExternalPrincipals: new(ramapi.Boolean(false))}).ResourceShare
			expect := func(ctx context.Context, target subnetCommandOwner, namespace, action string, input any, code string) {
				t.Helper()
				_, rejected := subnetCommand(t, ctx, target, namespace, action, input)
				if rejected == nil || rejected.Code != code {
					t.Fatalf("%s want %s, got %v", action, code, rejected)
				}
			}
			_, rejected := subnetCommand(t, owner, sharing, "ram", "CreateResourceShare", &ramapi.CreateResourceShareRequest{Name: new(ramapi.String("external-network")), ResourceArns: ramapi.ResourceArnList{ramapi.String(subnetARN)}, Principals: ramapi.PrincipalArnOrIdList{ramapi.String(outsiderID)}, AllowExternalPrincipals: new(ramapi.Boolean(true))})
			if rejected == nil {
				t.Fatal("subnet sharing admitted a principal outside the organization")
			}
			visible := subnetResult[api.DescribeSubnetsResult](t, participant, service, "ec2", "DescribeSubnets", &api.DescribeSubnetsRequest{SubnetIds: api.SubnetIdStringList{api.SubnetId(*subnet.SubnetId)}})
			if len(visible.Subnets) != 1 || string(*visible.Subnets[0].OwnerId) != ownerID || len(visible.Subnets[0].Tags) != 0 {
				t.Fatalf("shared subnet owner/private tags: %+v", visible)
			}
			participantVPC := subnetResult[api.DescribeVpcsResult](t, participant, service, "ec2", "DescribeVpcs", &api.DescribeVpcsRequest{VpcIds: api.VpcIdStringList{api.VpcId(*vpc.VpcId)}})
			if len(participantVPC.Vpcs) != 1 || string(*participantVPC.Vpcs[0].OwnerId) != ownerID {
				t.Fatalf("shared VPC owner: %+v", participantVPC)
			}
			group := subnetResult[api.CreateSecurityGroupResult](t, participant, service, "ec2", "CreateSecurityGroup", &api.CreateSecurityGroupRequest{VpcId: new(api.VpcId(*vpc.VpcId)), GroupName: new(api.String("participant")), Description: new(api.String("participant security"))})
			request := &api.CreateNetworkInterfaceRequest{SubnetId: new(api.SubnetId(*subnet.SubnetId)), Groups: api.SecurityGroupIdStringList{api.SecurityGroupId(*group.GroupId)}}
			owned := subnetResult[api.CreateNetworkInterfaceResult](t, owner, service, "ec2", "CreateNetworkInterface", &api.CreateNetworkInterfaceRequest{SubnetId: request.SubnetId}).NetworkInterface
			attached := subnetResult[api.CreateNetworkInterfaceResult](t, participant, service, "ec2", "CreateNetworkInterface", request).NetworkInterface
			if string(*attached.OwnerId) != participantID || string(*attached.SubnetId) != string(*subnet.SubnetId) || string(*attached.PrivateIpAddress) == string(*owned.PrivateIpAddress) {
				t.Fatalf("participant allocation/ownership: owner=%+v participant=%+v", owned, attached)
			}
			collision := *request
			collision.PrivateIpAddress = owned.PrivateIpAddress
			expect(participant, service, "ec2", "CreateNetworkInterface", &collision, "InvalidIPAddress.InUse")
			expect(participant, service, "ec2", "CreateNetworkInterface", &api.CreateNetworkInterfaceRequest{SubnetId: request.SubnetId}, "InvalidGroup.NotFound")
			ownerView := subnetResult[api.DescribeNetworkInterfacesResult](t, owner, service, "ec2", "DescribeNetworkInterfaces", &api.DescribeNetworkInterfacesRequest{NetworkInterfaceIds: api.NetworkInterfaceIdList{api.NetworkInterfaceId(*attached.NetworkInterfaceId)}})
			if len(ownerView.NetworkInterfaces) != 1 || string(*ownerView.NetworkInterfaces[0].OwnerId) != participantID {
				t.Fatalf("owner cannot inspect participant ENI: %+v", ownerView)
			}
			for _, hidden := range []context.Context{actor(outsiderID, "us-east-1"), actor(participantID, "us-west-2")} {
				expect(hidden, service, "ec2", "CreateNetworkInterface", request, "InvalidSubnetID.NotFound")
			}
			expect(participant, service, "ec2", "DeleteSubnet", &api.DeleteSubnetRequest{SubnetId: request.SubnetId}, "InvalidSubnetID.NotFound")
			expect(participant, service, "ec2", "ModifySubnetAttribute", &api.ModifySubnetAttributeRequest{SubnetId: request.SubnetId, MapPublicIpOnLaunch: &api.AttributeBooleanValue{Value: new(api.Boolean(true))}}, "InvalidSubnetID.NotFound")
			if err := service.AuthorizeSubnetSharing(participant, subnetARN); !errors.Is(err, ec2.ErrSubnetNotShareable) {
				t.Fatalf("participant obtained reshare authority: %v", err)
			}
			user := subnetResult[iamapi.CreateUserResponse](t, participant, identity, "iam", "CreateUser", &iamapi.CreateUserRequest{UserName: new(iamapi.UserNameType("network-user"))}).User
			subnetResult[iamapi.Unit](t, participant, identity, "iam", "PutUserPolicy", &iamapi.PutUserPolicyRequest{UserName: new(iamapi.ExistingUserNameType("network-user")), PolicyName: new(iamapi.PolicyNameType("network")), PolicyDocument: new(iamapi.PolicyDocumentType(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Effect":"Deny","Action":"ec2:CreateNetworkInterface","Resource":"` + subnetARN + `"}]}`))})
			userCtx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: participantID, Region: "us-east-1", PrincipalARN: string(*user.Arn), PrincipalID: string(*user.UserId)})
			expect(userCtx, service, "ec2", "CreateNetworkInterface", request, "UnauthorizedOperation")

			// Real EBS/image admission reaches the shared subnet's RunInstances
			// checks without substituting a fake guest executor in this fixture.
			snapshot := subnetResult[ebsapi.StartSnapshotResponse](t, participant, volumes, "ebs", "StartSnapshot", &ebsapi.StartSnapshotRequest{VolumeSize: new(ebsapi.VolumeSize(8))})
			subnetResult[ebsapi.CompleteSnapshotResponse](t, participant, volumes, "ebs", "CompleteSnapshot", &ebsapi.CompleteSnapshotRequest{SnapshotId: snapshot.SnapshotId, ChangedBlocksCount: new(ebsapi.ChangedBlocksCount(0))})
			if err := source.Advance(ebs.CompletionDelay + ebs.ReadinessDelay); err != nil {
				t.Fatal(err)
			}
			if _, err := volumes.JobDriver().RunDue(participant, 100); err != nil {
				t.Fatal(err)
			}
			image := subnetResult[api.RegisterImageResult](t, participant, service, "ec2", "RegisterImage", &api.RegisterImageRequest{Name: new(api.ImageNameRequest("shared-subnet-image")), Architecture: new(api.ArchitectureValues("x86_64")), VirtualizationType: new(api.String("hvm")), RootDeviceName: new(api.String("/dev/xvda")), BlockDeviceMappings: api.BlockDeviceMappingRequestList{{DeviceName: new(api.String("/dev/xvda")), Ebs: &api.EbsBlockDevice{SnapshotId: new(api.SnapshotId(*snapshot.SnapshotId)), VolumeSize: new(api.Integer(8)), VolumeType: new(api.VolumeType("gp3"))}}}})
			launch := &api.RunInstancesRequest{ImageId: new(api.ImageId(*image.ImageId)), InstanceType: new(api.InstanceType("t3.micro")), SubnetId: request.SubnetId, SecurityGroupIds: request.Groups, MinCount: new(api.Integer(1)), MaxCount: new(api.Integer(1)), DryRun: new(api.Boolean(true))}
			expect(participant, service, "ec2", "RunInstances", launch, "DryRunOperation")
			closeOwners()
			open()
			expect(participant, service, "ec2", "RunInstances", launch, "DryRunOperation")
			if err := networks.View(owner, func(tx ec2.Reader) error {
				current, err := tx.Subnet(ec2.ResourceKey{Scope: ec2.Scope{Partition: "aws", AccountID: ownerID, Region: "us-east-1"}, ID: string(*subnet.SubnetId)})
				if err != nil {
					return err
				}
				if *current.Data.AvailableIpAddressCount != 249 || len(current.Data.Tags) != 1 {
					t.Fatalf("owner capacity/tags not retained: %+v", current.Data)
				}
				_, err = tx.Subnet(ec2.ResourceKey{Scope: ec2.Scope{Partition: "aws", AccountID: participantID, Region: "us-east-1"}, ID: string(*subnet.SubnetId)})
				if !errors.Is(err, ec2.ErrNotFound) {
					t.Fatalf("participant received copied subnet: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			subnetResult[ramapi.DisassociateResourceShareResponse](t, owner, sharing, "ram", "DisassociateResourceShare", &ramapi.DisassociateResourceShareRequest{ResourceShareArn: share.ResourceShareArn, Principals: ramapi.PrincipalArnOrIdList{ramapi.String(participantID)}})
			expect(participant, service, "ec2", "CreateNetworkInterface", request, "InvalidSubnetID.NotFound")
			expect(participant, service, "ec2", "RunInstances", launch, "InvalidSubnetID.NotFound")
			retained := subnetResult[api.DescribeNetworkInterfacesResult](t, participant, service, "ec2", "DescribeNetworkInterfaces", &api.DescribeNetworkInterfacesRequest{NetworkInterfaceIds: api.NetworkInterfaceIdList{api.NetworkInterfaceId(*attached.NetworkInterfaceId)}})
			if len(retained.NetworkInterfaces) != 1 || string(*retained.NetworkInterfaces[0].PrivateIpAddress) != string(*attached.PrivateIpAddress) {
				t.Fatalf("revocation destroyed admitted resource: %+v", retained)
			}
			subnetResult[api.AssignPrivateIpAddressesResult](t, participant, service, "ec2", "AssignPrivateIpAddresses", &api.AssignPrivateIpAddressesRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(*attached.NetworkInterfaceId)), SecondaryPrivateIpAddressCount: new(api.Integer(1))})
			expect(owner, service, "ec2", "DeleteNetworkInterface", &api.DeleteNetworkInterfaceRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(*attached.NetworkInterfaceId))}, "InvalidNetworkInterfaceID.NotFound")
			expect(owner, service, "ec2", "DeleteSubnet", &api.DeleteSubnetRequest{SubnetId: request.SubnetId}, "DependencyViolation")
			subnetResult[ramapi.AssociateResourceShareResponse](t, owner, sharing, "ram", "AssociateResourceShare", &ramapi.AssociateResourceShareRequest{ResourceShareArn: share.ResourceShareArn, Principals: ramapi.PrincipalArnOrIdList{ramapi.String(participantID)}})
			expect(participant, service, "ec2", "RunInstances", launch, "DryRunOperation")
			subnetResult[ramapi.DisassociateResourceShareResponse](t, owner, sharing, "ram", "DisassociateResourceShare", &ramapi.DisassociateResourceShareRequest{ResourceShareArn: share.ResourceShareArn, ResourceArns: ramapi.ResourceArnList{ramapi.String(subnetARN)}})
			closeOwners()
			open()
			expect(participant, service, "ec2", "CreateNetworkInterface", request, "InvalidSubnetID.NotFound")
			subnetResult[api.Unit](t, participant, service, "ec2", "DeleteNetworkInterface", &api.DeleteNetworkInterfaceRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(*attached.NetworkInterfaceId))})
			subnetResult[api.Unit](t, owner, service, "ec2", "DeleteNetworkInterface", &api.DeleteNetworkInterfaceRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(*owned.NetworkInterfaceId))})
			subnetResult[ramapi.AssociateResourceShareResponse](t, owner, sharing, "ram", "AssociateResourceShare", &ramapi.AssociateResourceShareRequest{ResourceShareArn: share.ResourceShareArn, ResourceArns: ramapi.ResourceArnList{ramapi.String(subnetARN)}})
			// A removed organization member immediately loses discovery/admission.
			currentGraph, revision, err := organization.Load(owner, "aws")
			if err != nil {
				t.Fatal(err)
			}
			currentGraph.Organizations[0].Accounts = currentGraph.Organizations[0].Accounts[:1]
			if ok, err := organization.CompareAndSwap(owner, "aws", revision, currentGraph, nil); err != nil || !ok {
				t.Fatalf("remove participant: %v/%v", ok, err)
			}
			expect(participant, service, "ec2", "CreateNetworkInterface", request, "InvalidSubnetID.NotFound")
			// Subnet deletion and the RAM association transition share one
			// transaction, including rollback of a surrounding owner command.
			abort := errors.New("abort enclosing network command")
			err = networks.Update(owner, func(tx ec2.Transaction) error {
				_, rejected := subnetCommand(t, tx.Context(), service, "ec2", "DeleteSubnet", &api.DeleteSubnetRequest{SubnetId: request.SubnetId})
				if rejected != nil {
					return rejected
				}
				return abort
			})
			if !errors.Is(err, abort) {
				t.Fatal(err)
			}
			checkAssociation := func(status string) {
				t.Helper()
				if err := grants.View(owner, func(tx ram.Reader) error {
					current, err := tx.Share(string(*share.ResourceShareArn))
					if err != nil {
						return err
					}
					if len(current.Resources) != 1 || current.Resources[0].ARN != subnetARN || current.Resources[0].Status != status {
						t.Fatalf("deletion association transition: %+v, want %s", current.Resources, status)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			checkAssociation("ASSOCIATED")
			subnetResult[api.Unit](t, owner, service, "ec2", "DeleteSubnet", &api.DeleteSubnetRequest{SubnetId: request.SubnetId})
			closeOwners()
			open()
			checkAssociation("DISASSOCIATED")
			replacement := subnetResult[api.CreateSubnetResult](t, owner, service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(*vpc.VpcId)), CidrBlock: new(api.String("10.62.1.0/24")), AvailabilityZone: new(api.String("us-east-1a"))}).Subnet
			if *replacement.SubnetId == *subnet.SubnetId {
				t.Fatal("deleted subnet ID was reused")
			}
		})
	}
}
