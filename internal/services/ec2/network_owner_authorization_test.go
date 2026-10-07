package ec2_test

import (
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
	"testing"
)

func TestNetworkOwnerNativeIAMAndScope(t *testing.T) {
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	identity := iam.NewWithConfig(iam.Config{})
	t.Cleanup(func() { _ = identity.Close() })
	service := ec2.New(ec2.Config{Authorizer: authorization.New(identity, nil)})
	t.Cleanup(func() { _ = service.Close() })
	user := subnetResult[iamapi.CreateUserResponse](t, root, identity, "iam", "CreateUser", &iamapi.CreateUserRequest{UserName: new(iamapi.UserNameType("network-owner"))}).User
	actor := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: string(*user.Arn), PrincipalID: string(*user.UserId)})
	vpc := subnetResult[api.CreateVpcResult](t, root, service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.76.0.0/24"))}).Vpc
	subnet := subnetResult[api.CreateSubnetResult](t, root, service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(*vpc.VpcId)), CidrBlock: new(api.String("10.76.0.0/25"))}).Subnet
	denied := func(action string, input any) {
		t.Helper()
		_, err := subnetCommand(t, actor, service, "ec2", action, input)
		if err == nil || err.Code != "UnauthorizedOperation" {
			t.Fatalf("%s err=%v want UnauthorizedOperation", action, err)
		}
	}
	natInput := &api.CreateNatGatewayRequest{SubnetId: new(api.SubnetId(*subnet.SubnetId)), ConnectivityType: new(api.ConnectivityType("private")), ClientToken: new(api.String("iam-create"))}
	endpointInput := &api.CreateVpcEndpointRequest{VpcId: new(api.VpcId(*vpc.VpcId)), ServiceName: new(api.String("com.amazonaws.us-east-1.dynamodb"))}
	denied("CreateNatGateway", natInput)
	denied("CreateVpcEndpoint", endpointInput)
	subnetResult[iamapi.Unit](t, root, identity, "iam", "PutUserPolicy", &iamapi.PutUserPolicyRequest{UserName: new(iamapi.ExistingUserNameType("network-owner")), PolicyName: new(iamapi.PolicyNameType("owners")), PolicyDocument: new(iamapi.PolicyDocumentType(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Effect":"Deny","Action":["ec2:DeleteNatGateway","ec2:ModifyVpcEndpoint","ec2:DeleteVpcEndpoints"],"Resource":"*"}]}`))})
	nat := subnetResult[api.CreateNatGatewayResult](t, actor, service, "ec2", "CreateNatGateway", natInput).NatGateway
	endpoint := subnetResult[api.CreateVpcEndpointResult](t, actor, service, "ec2", "CreateVpcEndpoint", endpointInput).VpcEndpoint
	denied("DeleteNatGateway", &api.DeleteNatGatewayRequest{NatGatewayId: new(api.NatGatewayId(*nat.NatGatewayId))})
	denied("ModifyVpcEndpoint", &api.ModifyVpcEndpointRequest{VpcEndpointId: new(api.VpcEndpointId(*endpoint.VpcEndpointId)), ResetPolicy: new(api.Boolean(true))})
	denied("DeleteVpcEndpoints", &api.DeleteVpcEndpointsRequest{VpcEndpointIds: api.VpcEndpointIdList{api.VpcEndpointId(*endpoint.VpcEndpointId)}})
	for _, metadata := range []awsctx.Metadata{{Partition: "aws", AccountID: "222222222222", Region: "us-east-1", PrincipalARN: "arn:aws:iam::222222222222:root", PrincipalID: "222222222222"}, {Partition: "aws", AccountID: "111111111111", Region: "us-west-2", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"}} {
		outsider := awsctx.WithMetadata(t.Context(), metadata)
		if _, err := subnetCommand(t, outsider, service, "ec2", "DescribeNatGateways", &api.DescribeNatGatewaysRequest{NatGatewayIds: api.NatGatewayIdStringList{api.NatGatewayId(*nat.NatGatewayId)}}); err == nil || err.Code != "NatGatewayNotFound" {
			t.Fatalf("NAT scope leaked: %v", err)
		}
		if _, err := subnetCommand(t, outsider, service, "ec2", "DescribeVpcEndpoints", &api.DescribeVpcEndpointsRequest{VpcEndpointIds: api.VpcEndpointIdList{api.VpcEndpointId(*endpoint.VpcEndpointId)}}); err == nil || err.Code != "InvalidVpcEndpointId.NotFound" {
			t.Fatalf("endpoint scope leaked: %v", err)
		}
	}
	invalid := ec2.CloneCreateVpcEndpointRequest(*endpointInput)
	invalid.ServiceName = new(api.String("com.amazonaws.us-west-2.s3"))
	if _, err := subnetCommand(t, root, service, "ec2", "CreateVpcEndpoint", &invalid); err == nil || err.Code != "InvalidServiceName" {
		t.Fatalf("accepted foreign service: %v", err)
	}
}
