package integrations

import (
	"testing"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

// Guard network admission exercises actual EC2 control commands and references;
// it does not claim NAT packet translation or endpoint service forwarding.
func TestCloudFormationEC2GuardNetworkReferencesWithoutGuest(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-2", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	owner := ec2.New(ec2.Config{})
	t.Cleanup(func() { _ = owner.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": owner})
	handlers := CloudFormationEC2Handlers(commands)
	var requests []cloudformation.ResourceRequest
	create := func(kind, name string, p cloudformation.Properties) cloudformation.ResourceResult {
		t.Helper()
		r := cloudformation.ResourceRequest{StackID: "arn:aws:cloudformation:us-east-2:123456789012:stack/guard/network", StackName: "guard", Type: "AWS::EC2::" + kind, LogicalID: name, Token: name + "-owner", Properties: p}
		h := handlers[r.Type]
		if h == nil {
			t.Fatalf("missing owner adapter %s", r.Type)
		}
		result, err := h.Create(ctx, r)
		if err != nil {
			t.Fatalf("%s create: %v", kind, err)
		}
		r.PhysicalID = result.PhysicalID
		requests = append(requests, r)
		if stabilizer, ok := h.(cloudformation.ResourceStabilizer); ok {
			complete, err := stabilizer.Stabilize(ctx, r)
			if err != nil || !complete {
				t.Fatalf("%s control not stable: %v %v", kind, complete, err)
			}
		}
		return result
	}
	vpc := create("VPC", "VPC", cloudformation.Properties{"CidrBlock": "10.57.0.0/16", "EnableDnsSupport": true, "EnableDnsHostnames": true})
	subnet := create("Subnet", "PrivateSubnet", cloudformation.Properties{"VpcId": vpc.Ref, "CidrBlock": "10.57.1.0/24"})
	table := create("RouteTable", "PrivateRoutes", cloudformation.Properties{"VpcId": vpc.Ref})
	group := create("SecurityGroup", "LambdaGroup", cloudformation.Properties{"VpcId": vpc.Ref, "GroupDescription": "Lambda network controls"})
	address := create("EIP", "NATAddress", cloudformation.Properties{"Domain": "vpc"})
	allocation, _ := address.Attributes["AllocationId"].(string)
	if allocation == "" {
		t.Fatalf("missing owner-backed EIP allocation: %+v", address)
	}
	nat := create("NatGateway", "NAT", cloudformation.Properties{"SubnetId": subnet.Ref, "AllocationId": allocation})
	direct := requests[len(requests)-1]
	direct.CloudControl = true
	natHandler := handlers[direct.Type]
	projected, err := natHandler.(cloudformation.ResourceReader).Read(ctx, direct)
	if err != nil {
		t.Fatalf("read zonal NAT for CloudControl: %v", err)
	}
	if _, regional := projected["VpcId"]; regional {
		t.Fatalf("zonal NAT projected unsupported regional create property: %+v", projected)
	}
	previous, err := cloudformation.WritableResourceProperties(direct.Type, projected)
	if err != nil {
		t.Fatal(err)
	}
	direct.Previous = previous
	properties, err := cloudformation.WritableResourceProperties(direct.Type, projected)
	if err != nil {
		t.Fatal(err)
	}
	direct.Properties = properties
	direct.Properties["Tags"] = []any{map[string]any{"Key": "purpose", "Value": "cloudcontrol-update"}}
	updated, err := natHandler.Update(ctx, direct)
	if err != nil || updated.PhysicalID != nat.PhysicalID {
		t.Fatalf("CloudControl zonal NAT tag update changed identity or failed: %+v %v", updated, err)
	}
	nativeNAT, err := cfnComputeCall[api.DescribeNatGatewaysResult](ctx, commands, "ec2", "DescribeNatGateways", map[string]any{"NatGatewayIds": []string{nat.PhysicalID}})
	if err != nil || len(nativeNAT.NatGateways) != 1 {
		t.Fatalf("describe updated NAT: %+v %v", nativeNAT, err)
	}
	natTags := cfnEC2Tags(nativeNAT.NatGateways[0].Tags)
	if natTags["purpose"] != "cloudcontrol-update" {
		t.Fatalf("CloudControl NAT tag update did not reach native owner: %+v", natTags)
	}
	if err = cfnEC2NativeOwned(ctx, commands, requests[len(requests)-1], nat.PhysicalID); err != nil {
		t.Fatalf("CloudControl update discarded private stack incarnation: %v", err)
	}
	create("Route", "NATRoute", cloudformation.Properties{"RouteTableId": table.Ref, "DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": nat.Ref})
	create("VPCEndpoint", "S3Endpoint", cloudformation.Properties{"VpcId": vpc.Ref, "ServiceName": "com.amazonaws.us-east-2.s3", "VpcEndpointType": "Gateway", "RouteTableIds": []any{table.Ref}})
	create("VPCEndpoint", "SQSEndpoint", cloudformation.Properties{"VpcId": vpc.Ref, "ServiceName": "com.amazonaws.us-east-2.sqs", "VpcEndpointType": "Interface", "SubnetIds": []any{subnet.Ref}, "SecurityGroupIds": []any{group.Ref}})
	if subnet.Attributes["SubnetId"] != subnet.Ref || group.Attributes["GroupId"] != group.Ref || vpc.Attributes["VpcId"] != vpc.Ref {
		t.Fatalf("Lambda VpcConfig references do not resolve service owners: %+v %+v %+v", vpc, subnet, group)
	}
	live, err := cfnComputeCall[api.DescribeNetworkInterfacesResult](ctx, commands, "ec2", "DescribeNetworkInterfaces", map[string]any{"Filters": []map[string]any{{"Name": "subnet-id", "Values": []string{subnet.Ref}}}})
	if err != nil || len(live.NetworkInterfaces) != 2 {
		t.Fatalf("NAT and interface endpoint did not reserve owned ENIs: %+v %v", live, err)
	}
	for _, eni := range live.NetworkInterfaces {
		if eni.RequesterId != nil {
			t.Fatalf("managed ENI fabricated an AWS requester identity: %+v", eni)
		}
	}
	for i := len(requests) - 1; i >= 0; i-- {
		r := requests[i]
		if err = handlers[r.Type].Delete(ctx, r); err != nil {
			t.Fatalf("delete %s: %v", r.Type, err)
		}
	}
}
