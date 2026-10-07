package ec2_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
)

// Private CloudFormation claims are native state: public tags neither grant nor
// revoke them, current IAM precedes every fence, and claims are scope-local.
func TestCloudFormationNetworkOwnerPrivateClaims(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
			identity := iam.NewWithConfig(iam.Config{})
			t.Cleanup(func() { _ = identity.Close() })
			var repo ec2.Repository = ec2.NewMemoryRepository(nil)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "ec2.sqlite")
			open := func() {
				var err error
				if db, err = sqlite.Open(root, path); err != nil {
					t.Fatal(err)
				}
				repo = sqlec2.New(db)
			}
			if backend == "sqlite" {
				open()
				t.Cleanup(func() { _ = db.Close() })
			}
			var service *ec2.Service
			assemble := func() { service = ec2.New(ec2.Config{Repository: repo, Authorizer: authorization.New(identity, nil)}) }
			assemble()
			t.Cleanup(func() { _ = service.Close() })

			const vpcType = "AWS::EC2::VPC"
			owner := "arn:aws:cloudformation:us-east-1:111111111111:stack/net/1/VPC/incarnation-1"
			createVPC := func(ctx context.Context, cidr string) (string, *awswire.Error) {
				out, err := subnetCommand(t, ctx, service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String(cidr))})
				if err != nil {
					return "", err
				}
				return string(*out.(*api.CreateVpcResult).Vpc.VpcId), nil
			}
			dns := func(ctx context.Context, id string, value bool) *awswire.Error {
				_, err := subnetCommand(t, ctx, service, "ec2", "ModifyVpcAttribute", &api.ModifyVpcAttributeRequest{VpcId: new(api.VpcId(id)), EnableDnsSupport: &api.AttributeBooleanValue{Value: new(api.Boolean(value))}})
				return err
			}
			markers := func() []api.Tag {
				return []api.Tag{
					{Key: new(api.String("stackd:cloudformation:stack-id")), Value: new(api.String("arn:aws:cloudformation:us-east-1:111111111111:stack/net/1"))},
					{Key: new(api.String("stackd:cloudformation:logical-id")), Value: new(api.String("VPC"))},
					{Key: new(api.String("stackd:cloudformation:incarnation")), Value: new(api.String("incarnation-1"))},
				}
			}
			tag := func(action, id string) {
				t.Helper()
				if _, err := subnetCommand(t, root, service, "ec2", action, &api.CreateTagsRequest{Resources: api.ResourceIdList{api.TaggableResourceId(id)}, Tags: markers()}); err != nil {
					t.Fatalf("%s: %v", action, err)
				}
			}

			owned, err := createVPC(ec2.WithCloudFormationCreation(root, vpcType, owner), "10.90.0.0/16")
			if err != nil {
				t.Fatalf("admitted create: %v", err)
			}
			foreign, err := createVPC(root, "10.91.0.0/16")
			if err != nil {
				t.Fatal(err)
			}
			// Forged public markers on the foreign row grant nothing.
			tag("CreateTags", foreign)
			if id, err := service.CloudFormationCreation(root, vpcType, owner); err != nil || id != owned {
				t.Fatalf("recovery selected %q %v, want exact private %s", id, err, owned)
			}
			if err := service.CloudFormationOwned(root, vpcType, owner, foreign); err == nil {
				t.Fatal("forged public markers admitted a foreign VPC")
			}
			if err := dns(ec2.WithCloudFormationMutation(root, vpcType, owner, foreign), foreign, false); err == nil || err.Code != "IncorrectState" {
				t.Fatalf("stack mutation of a forged foreign VPC: %v", err)
			}
			if err := dns(ec2.WithCloudFormationMutation(root, vpcType, owner+"-other", owned), owned, false); err == nil || err.Code != "IncorrectState" {
				t.Fatalf("stale incarnation mutated the owned VPC: %v", err)
			}
			// Removing customer metadata (including marker-shaped keys) cannot strip ownership.
			tag("CreateTags", owned)
			if _, err := subnetCommand(t, root, service, "ec2", "DeleteTags", &api.DeleteTagsRequest{Resources: api.ResourceIdList{api.TaggableResourceId(owned)}}); err != nil {
				t.Fatal(err)
			}
			if err := service.CloudFormationOwned(root, vpcType, owner, owned); err != nil {
				t.Fatalf("tag removal changed private ownership: %v", err)
			}
			// A lost reply is recovered, never re-admitted as a second resource.
			if _, err := createVPC(ec2.WithCloudFormationCreation(root, vpcType, owner), "10.92.0.0/16"); err == nil {
				t.Fatal("one incarnation admitted two VPCs")
			}
			// Ordinary direct mutation retains, but never transfers, the claim.
			if err := dns(root, owned, false); err != nil {
				t.Fatal(err)
			}
			if err := dns(ec2.WithCloudFormationMutation(root, vpcType, owner, owned), owned, true); err != nil {
				t.Fatalf("owner mutation after direct change: %v", err)
			}

			// Idempotent native replay of an unclaimed row is not CloudFormation import.
			subnet := subnetResult[api.CreateSubnetResult](t, root, service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(foreign)), CidrBlock: new(api.String("10.91.1.0/24"))}).Subnet
			nat := &api.CreateNatGatewayRequest{SubnetId: new(api.SubnetId(*subnet.SubnetId)), ConnectivityType: new(api.ConnectivityType("private")), ClientToken: new(api.String("shared-token"))}
			existing := subnetResult[api.CreateNatGatewayResult](t, root, service, "ec2", "CreateNatGateway", nat).NatGateway
			natOwner := owner + "/nat"
			if _, err := subnetCommand(t, ec2.WithCloudFormationCreation(root, "AWS::EC2::NatGateway", natOwner), service, "ec2", "CreateNatGateway", nat); err == nil || err.Code != "IncorrectState" {
				t.Fatalf("token replay adopted an unclaimed NAT gateway: %v", err)
			}
			if err := service.CloudFormationOwned(root, "AWS::EC2::NatGateway", natOwner, string(*existing.NatGatewayId)); err == nil {
				t.Fatal("rejected replay left a private claim")
			}
			if _, err := service.CloudFormationCreation(root, "AWS::EC2::NatGateway", natOwner); !errors.Is(err, ec2.ErrNotFound) {
				t.Fatalf("rejected replay left a creation receipt: %v", err)
			}
			// Native networking tombstones cannot certify live creation recovery.
			deletedOwner := owner + "/deleted-nat"
			deletedNAT := subnetResult[api.CreateNatGatewayResult](t, ec2.WithCloudFormationCreation(root, "AWS::EC2::NatGateway", deletedOwner), service, "ec2", "CreateNatGateway", &api.CreateNatGatewayRequest{SubnetId: new(api.SubnetId(*subnet.SubnetId)), ConnectivityType: new(api.ConnectivityType("private")), ClientToken: new(api.String("deleted-owner-token"))}).NatGateway
			subnetResult[api.DeleteNatGatewayResult](t, root, service, "ec2", "DeleteNatGateway", &api.DeleteNatGatewayRequest{NatGatewayId: new(api.NatGatewayId(*deletedNAT.NatGatewayId))})
			if _, err := service.CloudFormationCreation(root, "AWS::EC2::NatGateway", deletedOwner); err == nil || errors.Is(err, ec2.ErrNotFound) {
				t.Fatalf("deleted native NAT receipt recovered as live creation or nonadmission: %v", err)
			}

			// Claims are exact to partition, account and region.
			for _, metadata := range []awsctx.Metadata{{Partition: "aws", AccountID: "222222222222", Region: "us-east-1", PrincipalARN: "arn:aws:iam::222222222222:root", PrincipalID: "222222222222"}, {Partition: "aws", AccountID: "111111111111", Region: "us-west-2", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"}} {
				outsider := awsctx.WithMetadata(t.Context(), metadata)
				if _, err := service.CloudFormationCreation(outsider, vpcType, owner); !errors.Is(err, ec2.ErrNotFound) {
					t.Fatalf("receipt leaked to %+v: %v", metadata, err)
				}
				if err := service.CloudFormationOwned(outsider, vpcType, owner, owned); err == nil {
					t.Fatalf("claim leaked to %+v", metadata)
				}
			}

			// Restart keeps the exact claim and receipt.
			_ = service.Close()
			if backend == "sqlite" {
				_ = db.Close()
				open()
			}
			assemble()
			if id, err := service.CloudFormationCreation(root, vpcType, owner); err != nil || id != owned {
				t.Fatalf("reopened recovery %q %v", id, err)
			}
			if err := service.CloudFormationOwned(root, vpcType, owner, foreign); err == nil {
				t.Fatal("reopen promoted a foreign VPC")
			}

			// Current IAM governs observations and mutations before any fence.
			user := subnetResult[iamapi.CreateUserResponse](t, root, identity, "iam", "CreateUser", &iamapi.CreateUserRequest{UserName: new(iamapi.UserNameType("stack-role"))}).User
			actor := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: string(*user.Arn), PrincipalID: string(*user.UserId)})
			policy := func(document string) {
				subnetResult[iamapi.Unit](t, root, identity, "iam", "PutUserPolicy", &iamapi.PutUserPolicyRequest{UserName: new(iamapi.ExistingUserNameType("stack-role")), PolicyName: new(iamapi.PolicyNameType("ec2")), PolicyDocument: new(iamapi.PolicyDocumentType(document))})
			}
			policy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`)
			if err := service.CloudFormationOwned(actor, vpcType, owner, owned); err != nil {
				t.Fatalf("authorized observation: %v", err)
			}
			policy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Effect":"Deny","Action":["ec2:DescribeVpcs","ec2:ModifyVpcAttribute","ec2:DeleteVpc"],"Resource":"*"}]}`)
			if _, err := service.CloudFormationCreation(actor, vpcType, owner); errors.Is(err, ec2.ErrNotFound) || err == nil {
				t.Fatalf("revoked caller certified recovery: %v", err)
			}
			if err := service.CloudFormationOwned(actor, vpcType, owner, owned); err == nil {
				t.Fatal("revoked caller observed ownership")
			}
			if err := dns(ec2.WithCloudFormationMutation(actor, vpcType, owner+"-other", owned), owned, false); err == nil || err.Code != "UnauthorizedOperation" {
				t.Fatalf("fence preceded current IAM: %v", err)
			}
			if _, err := subnetCommand(t, ec2.WithCloudFormationMutation(actor, vpcType, owner, owned), service, "ec2", "DeleteVpc", &api.DeleteVpcRequest{VpcId: new(api.VpcId(owned))}); err == nil || err.Code != "UnauthorizedOperation" {
				t.Fatalf("revoked owner deleted VPC: %v", err)
			}

			// Deletion clears the claim; recovery reports the stale incarnation and a
			// recreated row starts unclaimed.
			if _, err := subnetCommand(t, ec2.WithCloudFormationMutation(root, vpcType, owner, owned), service, "ec2", "DeleteVpc", &api.DeleteVpcRequest{VpcId: new(api.VpcId(owned))}); err != nil {
				t.Fatalf("private owner cleanup: %v", err)
			}
			if id, err := service.CloudFormationCreation(root, vpcType, owner); err == nil || errors.Is(err, ec2.ErrNotFound) {
				t.Fatalf("deleted incarnation recovered %q %v", id, err)
			}
			recreated, err := createVPC(root, "10.90.0.0/16")
			if err != nil {
				t.Fatal(err)
			}
			if err := service.CloudFormationOwned(root, vpcType, owner, recreated); err == nil {
				t.Fatal("recreated VPC inherited a deleted claim")
			}
		})
	}
}
