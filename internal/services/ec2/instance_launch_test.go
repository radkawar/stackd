package ec2_test

import (
	"context"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	ebsapi "stackd/internal/awsapi/ebs"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/integrations"
	"stackd/internal/services/ebs"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
)

func TestRunInstancesDryRunWithoutExecutor(t *testing.T) {
	source := clock.NewManual(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))
	identity := iam.NewWithConfig(iam.Config{Clock: source})
	t.Cleanup(func() { identity.Close() })
	authorizer := authorization.NewWithClock(identity, nil, source)
	volumes := ebs.New(ebs.Config{Clock: source, Authorizer: authorizer})
	t.Cleanup(func() { volumes.Close() })
	service := ec2.New(ec2.Config{Clock: source, Authorizer: authorizer, ImageSnapshots: volumes, InstanceVolumes: volumes, Volumes: volumes, InstanceProfiles: &integrations.EC2InstanceProfiles{IAM: identity}})
	t.Cleanup(func() { service.Close() })
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	command := func(ctx context.Context, owner interface {
		ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	}, name, action string, input any) (any, *awswire.Error) {
		t.Helper()
		model, ok := awscatalog.LookupService(name)
		if !ok {
			t.Fatalf("missing service %s", name)
		}
		op, ok := model.Operation(action)
		if !ok {
			t.Fatalf("missing operation %s:%s", name, action)
		}
		return owner.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
	}
	must := func(out any, rejected *awswire.Error) any {
		t.Helper()
		if rejected != nil {
			t.Fatal(rejected)
		}
		return out
	}

	// Real snapshot completion and image registration exercise the same EBS
	// plan used by an actual launch, without installing any execution backend.
	snapshot := must(command(root, volumes, "ebs", "StartSnapshot", &ebsapi.StartSnapshotRequest{VolumeSize: new(ebsapi.VolumeSize(8))})).(*ebsapi.StartSnapshotResponse)
	must(command(root, volumes, "ebs", "CompleteSnapshot", &ebsapi.CompleteSnapshotRequest{SnapshotId: snapshot.SnapshotId, ChangedBlocksCount: new(ebsapi.ChangedBlocksCount(0))}))
	if err := source.Advance(ebs.CompletionDelay + ebs.ReadinessDelay); err != nil {
		t.Fatal(err)
	}
	if _, err := volumes.JobDriver().RunDue(root, 100); err != nil {
		t.Fatal(err)
	}
	image := must(command(root, service, "ec2", "RegisterImage", &api.RegisterImageRequest{
		Name: new(api.ImageNameRequest("dry-run-image")), Architecture: new(api.ArchitectureValues("x86_64")), VirtualizationType: new(api.String("hvm")), RootDeviceName: new(api.String("/dev/xvda")),
		BlockDeviceMappings: api.BlockDeviceMappingRequestList{{DeviceName: new(api.String("/dev/xvda")), Ebs: &api.EbsBlockDevice{SnapshotId: new(api.SnapshotId(*snapshot.SnapshotId)), VolumeSize: new(api.Integer(8)), VolumeType: new(api.VolumeType("gp3"))}}},
	})).(*api.RegisterImageResult)
	vpc := must(command(root, service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.84.0.0/16"))})).(*api.CreateVpcResult)
	subnet := must(command(root, service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(*vpc.Vpc.VpcId)), CidrBlock: new(api.String("10.84.0.0/24")), AvailabilityZone: new(api.String("us-east-1a"))})).(*api.CreateSubnetResult)
	must(command(root, identity, "iam", "CreateRole", &iamapi.CreateRoleRequest{RoleName: new(iamapi.RoleNameType("dry-run-role")), AssumeRolePolicyDocument: new(iamapi.PolicyDocumentType(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`))}))
	must(command(root, identity, "iam", "CreateInstanceProfile", &iamapi.CreateInstanceProfileRequest{InstanceProfileName: new(iamapi.InstanceProfileNameType("dry-run-profile"))}))
	must(command(root, identity, "iam", "AddRoleToInstanceProfile", &iamapi.AddRoleToInstanceProfileRequest{InstanceProfileName: new(iamapi.InstanceProfileNameType("dry-run-profile")), RoleName: new(iamapi.RoleNameType("dry-run-role"))}))
	user := must(command(root, identity, "iam", "CreateUser", &iamapi.CreateUserRequest{UserName: new(iamapi.UserNameType("launcher"))})).(*iamapi.CreateUserResponse).User
	launcher := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: string(*user.Arn), PrincipalID: string(*user.UserId)})
	policy := &iamapi.PutUserPolicyRequest{UserName: new(iamapi.ExistingUserNameType("launcher")), PolicyName: new(iamapi.PolicyNameType("launch")), PolicyDocument: new(iamapi.PolicyDocumentType(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*"}}`))}
	must(command(root, identity, "iam", "PutUserPolicy", policy))
	request := api.RunInstancesRequest{ImageId: new(api.ImageId(*image.ImageId)), InstanceType: new(api.InstanceType("t3.micro")), SubnetId: new(api.SubnetId(*subnet.Subnet.SubnetId)), MinCount: new(api.Integer(1)), MaxCount: new(api.Integer(1)), DryRun: new(api.Boolean(true))}
	expect := func(ctx context.Context, input *api.RunInstancesRequest, code string, status int) {
		t.Helper()
		_, rejected := command(ctx, service, "ec2", "RunInstances", input)
		if rejected == nil || rejected.Code != code || rejected.StatusCode != status {
			t.Fatalf("RunInstances: want %s/%d, got %v", code, status, rejected)
		}
	}
	expect(launcher, &request, "DryRunOperation", 412)
	request.Monitoring = &api.RunInstancesMonitoringEnabled{Enabled: new(api.Boolean(true))}
	expect(launcher, &request, "DryRunOperation", 412)

	managedRole := must(command(root, identity, "iam", "CreateRole", &iamapi.CreateRoleRequest{
		RoleName:                 new(iamapi.RoleNameType("lambda-operator")),
		AssumeRolePolicyDocument: new(iamapi.PolicyDocumentType(`{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)),
	})).(*iamapi.CreateRoleResponse).Role
	must(command(root, identity, "iam", "PutRolePolicy", &iamapi.PutRolePolicyRequest{
		RoleName: managedRole.RoleName, PolicyName: new(iamapi.PolicyNameType("managed-launch")),
		PolicyDocument: new(iamapi.PolicyDocumentType(`{"Statement":[{"Effect":"Allow","Action":"ec2:RunInstances","Resource":["arn:aws:ec2:*:*:instance/*","arn:aws:ec2:*:*:volume/*","arn:aws:ec2:*:*:network-interface/*"],"Condition":{"StringEquals":{"ec2:ManagedResourceOperator":"scaler.lambda.amazonaws.com"}}},{"Effect":"Allow","Action":"ec2:RunInstances","Resource":["arn:aws:ec2:*:*:image/*","arn:aws:ec2:*:*:subnet/*","arn:aws:ec2:*:*:security-group/*"]}]}`)),
	}))
	managedContext := lambdaEC2RoleContext(root, managedRole)
	managedRequest := request
	managedRequest.ClientToken = new(api.String("00000000-0000-4000-8000-000000000003"))
	if _, rejected := service.RunLambdaManagedInstance(managedContext, "arn:aws:lambda:us-east-1:123456789012:capacity-provider:owned", &managedRequest); rejected == nil || rejected.Code != "DryRunOperation" {
		t.Fatalf("managed operator condition was not supplied at launch admission: %v", rejected)
	}
	expect(managedContext, &managedRequest, "UnauthorizedOperation", 403)

	// Hardware independence must not bypass the authoritative admission checks.
	for _, test := range []struct {
		name string
		edit func(*api.RunInstancesRequest)
		code string
	}{
		{"missing-image", func(in *api.RunInstancesRequest) { in.ImageId = new(api.ImageId("ami-00000000000000001")) }, "InvalidAMIID.NotFound"},
		{"unknown-type", func(in *api.RunInstancesRequest) { in.InstanceType = new(api.InstanceType("invalid.type")) }, "InvalidInstanceType"},
		{"architecture", func(in *api.RunInstancesRequest) { in.InstanceType = new(api.InstanceType("t4g.micro")) }, "InvalidParameterValue"},
		{"missing-subnet", func(in *api.RunInstancesRequest) { in.SubnetId = new(api.SubnetId("subnet-00000000000000001")) }, "InvalidSubnetID.NotFound"},
		{"ebs-performance-guarantee", func(in *api.RunInstancesRequest) { in.EbsOptimized = new(api.Boolean(true)) }, "UnsupportedOperation"},
		{"snapshot-size", func(in *api.RunInstancesRequest) {
			in.BlockDeviceMappings = api.BlockDeviceMappingRequestList{{DeviceName: new(api.String("/dev/xvda")), Ebs: &api.EbsBlockDevice{VolumeSize: new(api.Integer(1))}}}
		}, "InvalidBlockDeviceMapping"},
		{"hibernate-unencrypted-root", func(in *api.RunInstancesRequest) {
			in.HibernationOptions = &api.HibernationOptionsRequest{Configured: new(api.Boolean(true))}
		}, "UnsupportedHibernationConfiguration"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := request
			test.edit(&input)
			_, rejected := command(launcher, service, "ec2", "RunInstances", &input)
			if rejected == nil || rejected.Code != test.code {
				t.Fatalf("want %s, got %v", test.code, rejected)
			}
		})
	}

	hibernating := request
	hibernating.HibernationOptions = &api.HibernationOptionsRequest{Configured: new(api.Boolean(true))}
	hibernating.BlockDeviceMappings = api.BlockDeviceMappingRequestList{{DeviceName: new(api.String("/dev/xvda")), Ebs: &api.EbsBlockDevice{Encrypted: new(api.Boolean(true))}}}
	expect(launcher, &hibernating, "DryRunOperation", 412)

	request.IamInstanceProfile = &api.IamInstanceProfileSpecification{Name: new(api.String("dry-run-profile"))}
	expect(launcher, &request, "UnauthorizedOperation", 403)
	policy.PolicyDocument = new(iamapi.PolicyDocumentType(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*"},{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/dry-run-role","Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}}]}`))
	must(command(root, identity, "iam", "PutUserPolicy", policy))
	expect(launcher, &request, "DryRunOperation", 412)
	request.DryRun = nil
	expect(launcher, &request, "UnsupportedOperation", 400)

	instances := must(command(root, service, "ec2", "DescribeInstances", &api.DescribeInstancesRequest{})).(*api.DescribeInstancesResult)
	if len(instances.Reservations) != 0 {
		t.Fatalf("admission allocated instances: %#v", instances.Reservations)
	}
	disks := must(command(root, service, "ec2", "DescribeVolumes", &api.DescribeVolumesRequest{})).(*api.DescribeVolumesResult)
	if len(disks.Volumes) != 0 {
		t.Fatalf("admission allocated EBS volumes: %#v", disks.Volumes)
	}
	network := must(command(root, service, "ec2", "DescribeNetworkInterfaces", &api.DescribeNetworkInterfacesRequest{})).(*api.DescribeNetworkInterfacesResult)
	if len(network.NetworkInterfaces) != 0 {
		t.Fatalf("admission allocated network interfaces: %#v", network.NetworkInterfaces)
	}
}
