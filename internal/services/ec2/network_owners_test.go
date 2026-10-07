package ec2_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"stackd/clock"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/integrations"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
	"testing"
	"time"
)

func TestNetworkOwnerNativeLifecycleRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
			source := clock.NewManual(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
			var repository ec2.Repository = ec2.NewMemoryRepository(nil)
			var db *sql.DB
			var service *ec2.Service
			path := filepath.Join(t.TempDir(), "network.sqlite")
			open := func() {
				t.Helper()
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					repository = sqlec2.New(db)
				}
				service = ec2.New(ec2.Config{Repository: repository, Clock: source})
			}
			close := func() {
				if service != nil {
					_ = service.Close()
				}
				if db != nil {
					_ = db.Close()
					db = nil
				}
			}
			open()
			t.Cleanup(close)
			expect := func(action string, input any, code string) {
				t.Helper()
				_, err := subnetCommand(t, ctx, service, "ec2", action, input)
				if err == nil || err.Code != code {
					t.Fatalf("%s error=%v want %s", action, err, code)
				}
			}
			vpc := subnetResult[api.CreateVpcResult](t, ctx, service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.74.0.0/24"))}).Vpc
			subnet := subnetResult[api.CreateSubnetResult](t, ctx, service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(*vpc.VpcId)), CidrBlock: new(api.String("10.74.0.0/25"))}).Subnet
			eip := subnetResult[api.AllocateAddressResult](t, ctx, service, "ec2", "AllocateAddress", &api.AllocateAddressRequest{Domain: new(api.DomainType("vpc"))})
			request := &api.CreateNatGatewayRequest{SubnetId: new(api.SubnetId(*subnet.SubnetId)), AllocationId: new(api.AllocationId(*eip.AllocationId)), ClientToken: new(api.String("public-nat-fence")), PrivateIpAddress: new(api.String("10.74.0.10"))}
			created := subnetResult[api.CreateNatGatewayResult](t, ctx, service, "ec2", "CreateNatGateway", request).NatGateway
			natID := api.NatGatewayId(*created.NatGatewayId)
			replay := subnetResult[api.CreateNatGatewayResult](t, ctx, service, "ec2", "CreateNatGateway", request).NatGateway
			if *replay.NatGatewayId != *created.NatGatewayId {
				t.Fatal("replay changed identity")
			}
			changed := ec2.CloneCreateNatGatewayRequest(*request)
			changed.PrivateIpAddress = new(api.String("10.74.0.11"))
			expect("CreateNatGateway", &changed, "IdempotentParameterMismatch")
			duplicate := ec2.CloneCreateNatGatewayRequest(*request)
			duplicate.ClientToken = nil
			duplicate.PrivateIpAddress = new(api.String("10.74.0.12"))
			expect("CreateNatGateway", &duplicate, "Resource.AlreadyAssociated")
			expect("CreateNetworkInterface", &api.CreateNetworkInterfaceRequest{SubnetId: request.SubnetId, PrivateIpAddress: request.PrivateIpAddress}, "InvalidIPAddress.InUse")
			primary := created.NatGatewayAddresses[0]
			expect("DeleteNetworkInterface", &api.DeleteNetworkInterfaceRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(*primary.NetworkInterfaceId))}, "InvalidParameterValue")
			expect("DisassociateAddress", &api.DisassociateAddressRequest{AssociationId: new(api.ElasticIpAssociationId(*primary.AssociationId))}, "DependencyViolation")
			tables := subnetResult[api.DescribeRouteTablesResult](t, ctx, service, "ec2", "DescribeRouteTables", &api.DescribeRouteTablesRequest{}).RouteTables
			tableID := api.RouteTableId(*tables[0].RouteTableId)
			subnetResult[api.CreateRouteResult](t, ctx, service, "ec2", "CreateRoute", &api.CreateRouteRequest{RouteTableId: &tableID, DestinationCidrBlock: new(api.String("0.0.0.0/0")), NatGatewayId: &natID})
			gatewayInput := &api.CreateVpcEndpointRequest{VpcId: new(api.VpcId(*vpc.VpcId)), ServiceName: new(api.String("com.amazonaws.us-east-1.s3")), RouteTableIds: api.VpcEndpointRouteTableIdList{tableID}, ClientToken: new(api.String("gateway-fence"))}
			gateway := subnetResult[api.CreateVpcEndpointResult](t, ctx, service, "ec2", "CreateVpcEndpoint", gatewayInput).VpcEndpoint
			routes := subnetResult[api.DescribeRouteTablesResult](t, ctx, service, "ec2", "DescribeRouteTables", &api.DescribeRouteTablesRequest{RouteTableIds: api.RouteTableIdStringList{tableID}}).RouteTables[0].Routes
			found := false
			for _, route := range routes {
				if route.GatewayId != nil && *route.GatewayId == *gateway.VpcEndpointId {
					found = route.DestinationPrefixListId != nil
				}
			}
			if !found {
				t.Fatal("gateway endpoint did not own prefix-list route")
			}
			expect("DeleteRouteTable", &api.DeleteRouteTableRequest{RouteTableId: &tableID}, "DependencyViolation")
			interfaceInput := &api.CreateVpcEndpointRequest{VpcId: new(api.VpcId(*vpc.VpcId)), VpcEndpointType: new(api.VpcEndpointType("Interface")), ServiceName: new(api.String("com.amazonaws.us-east-1.kinesis-streams")), SubnetIds: api.VpcEndpointSubnetIdList{api.SubnetId(*subnet.SubnetId)}, ClientToken: new(api.String("interface-fence"))}
			for _, name := range []string{"com.amazonaws.us-west-2.kinesis-streams", "cn.com.amazonaws.us-east-1.kinesis-streams", "com.amazonaws.us-east-1.not-a-service"} {
				invalid := ec2.CloneCreateVpcEndpointRequest(*interfaceInput)
				invalid.ServiceName, invalid.ClientToken = new(api.String(name)), nil
				expect("CreateVpcEndpoint", &invalid, "InvalidServiceName")
			}
			wrongRegion := ec2.CloneCreateVpcEndpointRequest(*interfaceInput)
			wrongRegion.ServiceRegion, wrongRegion.ClientToken = new(api.String("us-west-2")), nil
			expect("CreateVpcEndpoint", &wrongRegion, "UnsupportedOperation")
			wrongType := ec2.CloneCreateVpcEndpointRequest(*interfaceInput)
			wrongType.VpcEndpointType, wrongType.ClientToken = new(api.VpcEndpointType("Gateway")), nil
			expect("CreateVpcEndpoint", &wrongType, "InvalidServiceName")
			wrongType.VpcEndpointType = new(api.VpcEndpointType("GatewayLoadBalancer"))
			expect("CreateVpcEndpoint", &wrongType, "UnsupportedOperation")
			endpoint := subnetResult[api.CreateVpcEndpointResult](t, ctx, service, "ec2", "CreateVpcEndpoint", interfaceInput).VpcEndpoint
			if len(endpoint.NetworkInterfaceIds) != 1 || len(endpoint.Groups) != 1 {
				t.Fatalf("missing endpoint controls %+v", endpoint)
			}
			endpointID := api.VpcEndpointId(*endpoint.VpcEndpointId)
			bedrockInput := ec2.CloneCreateVpcEndpointRequest(*interfaceInput)
			bedrockInput.ServiceName = new(api.String("com.amazonaws.us-east-1.bedrock-runtime"))
			bedrockInput.ClientToken = new(api.String("bedrock-fence"))
			if _, err := subnetCommand(t, ctx, service, "ec2", "ModifyVpcAttribute", &api.ModifyVpcAttributeRequest{VpcId: new(api.VpcId(*vpc.VpcId)), EnableDnsHostnames: &api.AttributeBooleanValue{Value: new(api.Boolean(true))}}); err != nil {
				t.Fatal(err)
			}
			bedrockInput.PrivateDnsEnabled = new(api.Boolean(true))
			bedrockInput.SecurityGroupIds = api.VpcEndpointSecurityGroupIdList{api.SecurityGroupId(*endpoint.Groups[0].GroupId)}
			bedrock := subnetResult[api.CreateVpcEndpointResult](t, ctx, service, "ec2", "CreateVpcEndpoint", &bedrockInput).VpcEndpoint
			bedrockID := api.VpcEndpointId(*bedrock.VpcEndpointId)
			if len(bedrock.NetworkInterfaceIds) != 1 || *bedrock.Groups[0].GroupId != *endpoint.Groups[0].GroupId {
				t.Fatalf("Bedrock did not allocate real SG-controlled ENI: %+v", bedrock)
			}
			subnetResult[api.ModifyVpcEndpointResult](t, ctx, service, "ec2", "ModifyVpcEndpoint", &api.ModifyVpcEndpointRequest{VpcEndpointId: &bedrockID, PolicyDocument: new(api.String(`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"bedrock:InvokeModel","Resource":"*"}]}`)), DnsOptions: &api.DnsOptionsSpecification{DnsRecordIpType: new(api.DnsRecordIpType("ipv4"))}})
			subnetResult[api.ModifyVpcEndpointResult](t, ctx, service, "ec2", "ModifyVpcEndpoint", &api.ModifyVpcEndpointRequest{VpcEndpointId: &endpointID, PolicyDocument: new(api.String(`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*"}]}`)), DnsOptions: &api.DnsOptionsSpecification{DnsRecordIpType: new(api.DnsRecordIpType("ipv4"))}})
			close()
			open()
			natRead := subnetResult[api.DescribeNatGatewaysResult](t, ctx, service, "ec2", "DescribeNatGateways", &api.DescribeNatGatewaysRequest{NatGatewayIds: api.NatGatewayIdStringList{natID}}).NatGateways[0]
			if *natRead.NatGatewayAddresses[0].AssociationId != *primary.AssociationId {
				t.Fatal("NAT association lost on restart")
			}
			read := subnetResult[api.DescribeVpcEndpointsResult](t, ctx, service, "ec2", "DescribeVpcEndpoints", &api.DescribeVpcEndpointsRequest{VpcEndpointIds: api.VpcEndpointIdList{endpointID}}).VpcEndpoints[0]
			if read.ServiceName == nil || *read.ServiceName != *interfaceInput.ServiceName || read.VpcEndpointType == nil || *read.VpcEndpointType != "Interface" || len(read.NetworkInterfaceIds) != 1 {
				t.Fatalf("official Kinesis interface endpoint lost on restart: %+v", read)
			}
			if read.DnsOptions == nil || *read.DnsOptions.DnsRecordIpType != "ipv4" || *read.PolicyDocument != `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*"}]}` {
				t.Fatalf("endpoint settings lost %+v", read)
			}
			bedrockRead := subnetResult[api.DescribeVpcEndpointsResult](t, ctx, service, "ec2", "DescribeVpcEndpoints", &api.DescribeVpcEndpointsRequest{VpcEndpointIds: api.VpcEndpointIdList{bedrockID}}).VpcEndpoints[0]
			if *bedrockRead.ServiceName != *bedrockInput.ServiceName || *bedrockRead.PolicyDocument != `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"bedrock:InvokeModel","Resource":"*"}]}` || bedrockRead.DnsOptions == nil || *bedrockRead.DnsOptions.DnsRecordIpType != "ipv4" || !slices.Equal(bedrockRead.NetworkInterfaceIds, bedrock.NetworkInterfaceIds) || bedrockRead.PrivateDnsEnabled == nil || !bool(*bedrockRead.PrivateDnsEnabled) {
				t.Fatalf("disabled-provider endpoint state lost on reopen: %+v", bedrockRead)
			}
			subnetResult[api.ModifyVpcEndpointResult](t, ctx, service, "ec2", "ModifyVpcEndpoint", &api.ModifyVpcEndpointRequest{VpcEndpointId: &bedrockID, ResetPolicy: new(api.Boolean(true)), PrivateDnsEnabled: new(api.Boolean(false))})
			reset := subnetResult[api.DescribeVpcEndpointsResult](t, ctx, service, "ec2", "DescribeVpcEndpoints", &api.DescribeVpcEndpointsRequest{VpcEndpointIds: api.VpcEndpointIdList{bedrockID}}).VpcEndpoints[0]
			if bool(*reset.PrivateDnsEnabled) || *reset.PolicyDocument != `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}` || !slices.Equal(reset.NetworkInterfaceIds, bedrock.NetworkInterfaceIds) {
				t.Fatalf("policy/DNS lifecycle replaced or damaged endpoint ENI: %+v", reset)
			}
			foreignMetadata := awsctx.FromContext(ctx)
			foreignMetadata.AccountID, foreignMetadata.PrincipalARN = "222222222222", "arn:aws:iam::222222222222:root"
			foreign := awsctx.WithMetadata(t.Context(), foreignMetadata)
			if _, err := subnetCommand(t, foreign, service, "ec2", "DescribeVpcEndpoints", &api.DescribeVpcEndpointsRequest{VpcEndpointIds: api.VpcEndpointIdList{bedrockID}}); err == nil || err.Code != "InvalidVpcEndpointId.NotFound" {
				t.Fatalf("Bedrock endpoint crossed accounts: %v", err)
			}
			subnetResult[api.DeleteVpcEndpointsResult](t, ctx, service, "ec2", "DeleteVpcEndpoints", &api.DeleteVpcEndpointsRequest{VpcEndpointIds: api.VpcEndpointIdList{endpointID, bedrockID, api.VpcEndpointId(*gateway.VpcEndpointId)}})
			subnetResult[api.DeleteNatGatewayResult](t, ctx, service, "ec2", "DeleteNatGateway", &api.DeleteNatGatewayRequest{NatGatewayId: &natID})
			blackholes := subnetResult[api.DescribeRouteTablesResult](t, ctx, service, "ec2", "DescribeRouteTables", &api.DescribeRouteTablesRequest{RouteTableIds: api.RouteTableIdStringList{tableID}}).RouteTables[0].Routes
			blackhole := false
			for _, route := range blackholes {
				if route.NatGatewayId != nil && string(*route.NatGatewayId) == string(natID) {
					blackhole = route.State != nil && *route.State == "blackhole"
				}
			}
			if !blackhole {
				t.Fatal("NAT deletion did not retain blackhole route")
			}
			replay = subnetResult[api.CreateNatGatewayResult](t, ctx, service, "ec2", "CreateNatGateway", request).NatGateway
			if string(*replay.NatGatewayId) != string(natID) || *replay.State != "deleted" {
				t.Fatal("deleted NAT token was not fenced")
			}
			addresses := subnetResult[api.DescribeAddressesResult](t, ctx, service, "ec2", "DescribeAddresses", &api.DescribeAddressesRequest{AllocationIds: api.AllocationIdList{api.AllocationId(*eip.AllocationId)}}).Addresses
			if len(addresses) != 1 || addresses[0].AssociationId != nil {
				t.Fatal("NAT deletion did not detach EIP")
			}
			interfaces := subnetResult[api.DescribeNetworkInterfacesResult](t, ctx, service, "ec2", "DescribeNetworkInterfaces", &api.DescribeNetworkInterfacesRequest{}).NetworkInterfaces
			if len(interfaces) != 0 {
				t.Fatalf("managed ENIs leaked %+v", interfaces)
			}
		})
	}
}

func TestNetworkOwnerCFNUsesNativeControlCommands(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-2", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	service := ec2.New(ec2.Config{})
	t.Cleanup(func() { _ = service.Close() })
	commands := integrations.NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": service})
	handlers := integrations.CloudFormationEC2NetworkExtensionHandlers(commands)
	vpc := subnetResult[api.CreateVpcResult](t, ctx, service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.75.0.0/24"))}).Vpc
	subnet := subnetResult[api.CreateSubnetResult](t, ctx, service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(*vpc.VpcId)), CidrBlock: new(api.String("10.75.0.0/25"))}).Subnet
	group := subnetResult[api.CreateSecurityGroupResult](t, ctx, service, "ec2", "CreateSecurityGroup", &api.CreateSecurityGroupRequest{VpcId: new(api.VpcId(*vpc.VpcId)), GroupName: new(api.String("bedrock-endpoint")), Description: new(api.String("Bedrock interface endpoint HTTPS"))})
	for _, kind := range []string{"AWS::EC2::NatGateway", "AWS::EC2::VPCEndpoint"} {
		t.Run(kind, func(t *testing.T) {
			properties := cloudformation.Properties{"SubnetId": string(*subnet.SubnetId), "ConnectivityType": "private"}
			if kind == "AWS::EC2::VPCEndpoint" {
				properties = cloudformation.Properties{"VpcId": string(*vpc.VpcId), "VpcEndpointType": "Interface", "ServiceName": "com.amazonaws.us-east-2.bedrock-runtime", "SubnetIds": []any{string(*subnet.SubnetId)}, "SecurityGroupIds": []any{string(*group.GroupId)}}
			}
			request := cloudformation.ResourceRequest{Type: kind, StackID: "stack-owner", LogicalID: "Network", Token: kind, Properties: properties}
			handler := handlers[kind]
			result, err := handler.Create(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if result.Ref != result.PhysicalID || result.PhysicalID == "" {
				t.Fatal("missing native Ref")
			}
			replay, err := handler.Create(ctx, request)
			if err != nil || replay.PhysicalID != result.PhysicalID {
				t.Fatalf("CFN recovery mismatch %+v %v", replay, err)
			}
			request.PhysicalID = result.PhysicalID
			reader := handler.(interface {
				Read(context.Context, cloudformation.ResourceRequest) (cloudformation.Properties, error)
			})
			if _, err = reader.Read(ctx, request); err != nil {
				t.Fatal(err)
			}
			wrong := request
			wrong.Token = "other-incarnation"
			if err = handler.Delete(ctx, wrong); err == nil {
				t.Fatal("different CFN incarnation deleted owner")
			}
			request.Previous = properties
			request.Properties = cloudformation.Properties{}
			for key, value := range properties {
				request.Properties[key] = value
			}
			if kind == "AWS::EC2::NatGateway" {
				request.Properties["SecondaryPrivateIpAddressCount"] = 2
			} else {
				request.Properties["PolicyDocument"] = map[string]any{"Statement": []any{map[string]any{"Effect": "Deny", "Principal": "*", "Action": "*", "Resource": "*"}}}
			}
			if _, err = handler.Update(ctx, request); err != nil {
				t.Fatal(err)
			}
			if err = handler.Delete(ctx, request); err != nil {
				t.Fatal(err)
			}
			if err = handler.Delete(ctx, request); err != nil {
				t.Fatal(err)
			}
		})
	}
}
