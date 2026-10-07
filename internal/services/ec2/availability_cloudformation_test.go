package ec2_test

import (
	"reflect"
	"slices"
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
)

func TestCloudFormationGetAZsNativeSubnetPlacementAndDefaultFiltering(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root"})
	repository := ec2.NewMemoryRepository(nil)
	service := ec2.New(ec2.Config{Repository: repository})
	t.Cleanup(func() { _ = service.Close() })
	zones := subnetResult[api.DescribeAvailabilityZonesResult](t, ctx, service, "ec2", "DescribeAvailabilityZones", &api.DescribeAvailabilityZonesRequest{}).AvailabilityZones
	expected := []string{}
	for _, zone := range zones {
		if zone.ZoneType != nil && string(*zone.ZoneType) == "availability-zone" && zone.State != nil && string(*zone.State) == "available" {
			expected = append(expected, string(*zone.ZoneName))
		}
	}
	actual, err := service.CloudFormationAvailabilityZones(ctx, "")
	if err != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatalf("no defaults: %v, %v; want %v", actual, err, expected)
	}
	if len(expected) < 2 {
		t.Fatal("expected standard inventory with multiple zones")
	}
	vpc := subnetResult[api.CreateVpcResult](t, ctx, service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.97.0.0/16"))}).Vpc
	var defaultSubnet *api.Subnet
	for i, body := range []string{
		`{"Resources":{"Subnet":{"Type":"AWS::EC2::Subnet","Properties":{"AvailabilityZone":{"Fn::Select":[0,{"Fn::GetAZs":""}]}}}}}`,
		"Resources:\n  Subnet:\n    Type: AWS::EC2::Subnet\n    Properties:\n      AvailabilityZone: !Select [1, !GetAZs {Ref: 'AWS::Region'}]\n",
	} {
		template, err := cloudformation.ParseTemplate(body)
		if err != nil {
			t.Fatal(err)
		}
		properties, err := template.ResolveResource("Subnet", cloudformation.Evaluation{Scope: cloudformation.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Context: ctx, AvailabilityZones: service})
		if err != nil {
			t.Fatal(err)
		}
		cidr := "10.97.0.0/24"
		if i == 1 {
			cidr = "10.97.1.0/24"
		}
		subnet := subnetResult[api.CreateSubnetResult](t, ctx, service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(*vpc.VpcId)), CidrBlock: new(api.String(cidr)), AvailabilityZone: new(api.String(properties["AvailabilityZone"].(string)))}).Subnet
		if !slices.Contains(expected, string(*subnet.AvailabilityZone)) {
			t.Fatal("GetAZs selected a zone absent from native inventory")
		}
		defaultSubnet = subnet
	}
	scope := ec2.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	if err := repository.Update(ctx, func(tx ec2.Transaction) error {
		subnet, err := tx.Subnet(ec2.ResourceKey{Scope: scope, ID: string(*defaultSubnet.SubnetId)})
		if err != nil {
			return err
		}
		subnet.Data.DefaultForAz = new(api.Boolean(true))
		return tx.PutSubnet(subnet)
	}); err != nil {
		t.Fatal(err)
	}
	actual, err = service.CloudFormationAvailabilityZones(ctx, "us-east-1")
	if err != nil || !reflect.DeepEqual(actual, []string{string(*defaultSubnet.AvailabilityZone)}) {
		t.Fatalf("default filtering: %v, %v", actual, err)
	}
	for _, metadata := range []awsctx.Metadata{
		{Partition: "aws", AccountID: "222222222222", Region: "us-east-1", PrincipalARN: "arn:aws:iam::222222222222:root"},
		{Partition: "aws", AccountID: "111111111111", Region: "us-west-2", PrincipalARN: "arn:aws:iam::111111111111:root"},
	} {
		actual, err := service.CloudFormationAvailabilityZones(awsctx.WithMetadata(t.Context(), metadata), "")
		if err != nil || len(actual) < 2 {
			t.Fatalf("defaults leaked across scope: %v, %v", actual, err)
		}
	}
	foreign, err := service.CloudFormationAvailabilityZones(ctx, "us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range foreign {
		if len(name) < 9 || name[:9] != "us-west-2" {
			t.Fatalf("explicit region ignored: %v", foreign)
		}
	}
}

func TestCloudFormationGetAZsUsesCurrentNativeReadIAM(t *testing.T) {
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root"})
	identity := iam.NewWithConfig(iam.Config{})
	t.Cleanup(func() { _ = identity.Close() })
	service := ec2.New(ec2.Config{Authorizer: authorization.New(identity, nil)})
	t.Cleanup(func() { _ = service.Close() })
	user := subnetResult[iamapi.CreateUserResponse](t, root, identity, "iam", "CreateUser", &iamapi.CreateUserRequest{UserName: new(iamapi.UserNameType("cfn-zones"))}).User
	actor := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: string(*user.Arn), PrincipalID: string(*user.UserId)})
	put := func(policy string) {
		subnetResult[iamapi.Unit](t, root, identity, "iam", "PutUserPolicy", &iamapi.PutUserPolicyRequest{UserName: new(iamapi.ExistingUserNameType("cfn-zones")), PolicyName: new(iamapi.PolicyNameType("read")), PolicyDocument: new(iamapi.PolicyDocumentType(policy))})
	}
	put(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:DescribeAvailabilityZones","ec2:DescribeAccountAttributes","ec2:DescribeSubnets"],"Resource":"*"}]}`)
	if _, err := service.CloudFormationAvailabilityZones(actor, ""); err != nil {
		t.Fatal(err)
	}
	for _, denied := range []string{"DescribeAvailabilityZones", "DescribeAccountAttributes", "DescribeSubnets"} {
		put(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Effect":"Deny","Action":"ec2:` + denied + `","Resource":"*"}]}`)
		if _, err := service.CloudFormationAvailabilityZones(actor, ""); err == nil {
			t.Fatalf("current %s deny ignored", denied)
		}
	}
}
