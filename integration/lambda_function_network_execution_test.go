package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/google/uuid"

	"stackd"
	native "stackd/compute/lambda"
	"stackd/compute/network"
	"stackd/storage"
)

const nativeVpcCustomer = `import boto3,json,os
from urllib.parse import urlsplit
from botocore.config import Config
def handler(event,context):
    service=event.get('service','sqs')
    variable='AWS_ENDPOINT_URL_'+service.upper()
    endpoint=os.environ['AWS_ENDPOINT_URL'] if event.get('nat') else os.environ[variable]
    client=boto3.client(service,endpoint_url=endpoint,config=Config(connect_timeout=2,read_timeout=2,retries={'max_attempts':0}))
    try:
        if service=='sqs':
            result=client.send_message(QueueUrl=endpoint+urlsplit(os.environ['QUEUE_URL']).path,MessageBody=event['marker'])
            return {'ok':True,'message_id':result['MessageId']}
        result=client.put_record(StreamName=os.environ['STREAM_NAME'],Data=event['marker'].encode(),PartitionKey='native-vpc')
        return {'ok':True,'sequence':result['SequenceNumber']}
    except Exception as error:
        return {'ok':False,'error':str(error)}
    finally:
        client.close()
`

// This opt-in smoke runs actual customer Python/boto3, real Docker namespaces,
// native nftables, actual stackd SigV4/IAM/service owners and pinned Kafka. There
// are no synthetic AWS responses or echo fixtures on the endpoint packet path.
func TestLambdaVpcDockerEndpointsPolicyAndPrivateNatPackets(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" || os.Getenv("STACKD_KINESIS_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 STACKD_KINESIS_DOCKER=1 for native VPC packet evidence")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			logs := newKinesisReplayRuntime(t)
			bridges, err := network.NewDaemonBridges(logs.client)
			if err != nil {
				t.Fatal(err)
			}
			namespace := "lambda-vpc-native-" + uuid.NewString()
			functionNetworks, err := native.NewFunctionNetworkRuntime(logs.client, bridges, namespace)
			if err != nil {
				t.Fatal(err)
			}
			callback := os.Getenv("STACKD_LAMBDA_CALLBACK_HOST")
			if callback == "" && goruntime.GOOS == "darwin" {
				callback = "host.docker.internal"
			}
			if err := functionNetworks.SetControllerAddress("0.0.0.0:0", callback); err != nil {
				t.Fatal(err)
			}
			backends := storage.NewMemory()
			if backend == "sqlite" {
				var closeDatabase func()
				backends, closeDatabase = openSQLiteBackends(t, t.TempDir()+"/vpc.sqlite")
				t.Cleanup(closeDatabase)
			}
			_, server := newLambdaDockerStack(t, stackd.Config{Storage: backends, KinesisRuntime: logs, LambdaFunctionNetworkRuntime: functionNetworks}, &native.DockerConfig{Client: logs.client, Namespace: namespace, CallbackHost: callback})
			clients := cloudClients{server}
			identity, queues, streams := clients.iam("test", "test", ""), clients.sqs("test", "test", ""), clients.kinesis("test", "test", "")
			networks := ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			functions := lambda.New(lambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			vpc, err := networks.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.91.0.0/16")})
			if err != nil {
				t.Fatal(err)
			}
			vpcID := vpc.Vpc.VpcId
			if _, err := networks.ModifyVpcAttribute(t.Context(), &ec2.ModifyVpcAttributeInput{VpcId: vpcID, EnableDnsHostnames: &ec2types.AttributeBooleanValue{Value: aws.Bool(true)}}); err != nil {
				t.Fatal(err)
			}
			makeSubnet := func(cidr string) *string {
				t.Helper()
				out, err := networks.CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: vpcID, CidrBlock: aws.String(cidr), AvailabilityZone: aws.String("us-east-1a")})
				if err != nil {
					t.Fatal(err)
				}
				return out.Subnet.SubnetId
			}
			functionSubnet, endpointSubnet, publicSubnet := makeSubnet("10.91.1.0/24"), makeSubnet("10.91.2.0/24"), makeSubnet("10.91.3.0/24")
			makeGroup := func(name string) *string {
				t.Helper()
				out, err := networks.CreateSecurityGroup(t.Context(), &ec2.CreateSecurityGroupInput{VpcId: vpcID, GroupName: aws.String(name), Description: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
				return out.GroupId
			}
			functionGroup, endpointGroup := makeGroup("function-egress"), makeGroup("endpoint-ingress")
			permission := []ec2types.IpPermission{{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("10.91.1.0/24")}}}}
			if _, err := networks.AuthorizeSecurityGroupIngress(t.Context(), &ec2.AuthorizeSecurityGroupIngressInput{GroupId: endpointGroup, IpPermissions: permission}); err != nil {
				t.Fatal(err)
			}
			privateTable, err := networks.CreateRouteTable(t.Context(), &ec2.CreateRouteTableInput{VpcId: vpcID})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := networks.AssociateRouteTable(t.Context(), &ec2.AssociateRouteTableInput{SubnetId: functionSubnet, RouteTableId: privateTable.RouteTable.RouteTableId}); err != nil {
				t.Fatal(err)
			}
			policy := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`
			endpoints := map[string]*string{}
			for _, service := range []string{"sqs", "kinesis"} {
				out, err := networks.CreateVpcEndpoint(t.Context(), &ec2.CreateVpcEndpointInput{VpcId: vpcID, VpcEndpointType: ec2types.VpcEndpointTypeInterface, ServiceName: aws.String("com.amazonaws.us-east-1." + service), SubnetIds: []string{aws.ToString(endpointSubnet)}, SecurityGroupIds: []string{aws.ToString(endpointGroup)}, PrivateDnsEnabled: aws.Bool(true), PolicyDocument: aws.String(policy)})
				if err != nil {
					t.Fatal(err)
				}
				endpoints[service] = out.VpcEndpoint.VpcEndpointId
			}
			queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("native-vpc-output")})
			if err != nil {
				t.Fatal(err)
			}
			streamName := "native-vpc-stream"
			if _, err := streams.CreateStream(t.Context(), &kinesis.CreateStreamInput{StreamName: &streamName, ShardCount: aws.Int32(1)}); err != nil {
				t.Fatal(err)
			}
			if err := kinesis.NewStreamExistsWaiter(streams).Wait(t.Context(), &kinesis.DescribeStreamInput{StreamName: &streamName}, time.Minute, func(o *kinesis.StreamExistsWaiterOptions) {
				o.MinDelay = 100 * time.Millisecond
				o.MaxDelay = 250 * time.Millisecond
			}); err != nil {
				t.Fatal(err)
			}
			roleName := "native-vpc-execution"
			role, err := identity.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := identity.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: &roleName, PolicyName: aws.String("native-vpc"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":["sqs:SendMessage","kinesis:PutRecord","ec2:CreateNetworkInterface","ec2:DeleteNetworkInterface","ec2:DescribeNetworkInterfaces","ec2:DescribeSubnets","ec2:DescribeSecurityGroups"],"Resource":"*"}}`)}); err != nil {
				t.Fatal(err)
			}
			name := aws.String("native-vpc-function")
			if _, err := functions.CreateFunction(t.Context(), &lambda.CreateFunctionInput{FunctionName: name, Role: role.Role.Arn, Runtime: lambdatypes.RuntimePython312, Handler: aws.String("handler.handler"), Timeout: aws.Int32(10), VpcConfig: &lambdatypes.VpcConfig{SubnetIds: []string{aws.ToString(functionSubnet)}, SecurityGroupIds: []string{aws.ToString(functionGroup)}}, Code: &lambdatypes.FunctionCode{ZipFile: lambdaZIP(t, map[string]string{"handler.py": nativeVpcCustomer})}, Environment: &lambdatypes.Environment{Variables: map[string]string{"QUEUE_URL": aws.ToString(queue.QueueUrl), "STREAM_NAME": streamName}}}); err != nil {
				t.Fatal(err)
			}
			if err := lambda.NewFunctionActiveWaiter(functions, fastLambdaActiveWaiter).Wait(t.Context(), &lambda.GetFunctionConfigurationInput{FunctionName: name}, time.Minute); err != nil {
				configuration, configurationErr := functions.GetFunctionConfiguration(t.Context(), &lambda.GetFunctionConfigurationInput{FunctionName: name})
				if configurationErr != nil {
					t.Fatalf("native VPC function activation failed: %v; GetFunctionConfiguration: %v", err, configurationErr)
				}
				t.Fatalf("native VPC function activation failed: %v; state=%s reason_code=%s reason=%q last_update_status=%s last_update_reason_code=%s last_update_reason=%q", err, configuration.State, configuration.StateReasonCode, aws.ToString(configuration.StateReason), configuration.LastUpdateStatus, configuration.LastUpdateStatusReasonCode, aws.ToString(configuration.LastUpdateStatusReason))
			}
			invoke := func(service, marker string, nat bool, want bool, stringError string) {
				t.Helper()
				payload, _ := json.Marshal(map[string]any{"service": service, "marker": marker, "nat": nat})
				out, err := functions.Invoke(t.Context(), &lambda.InvokeInput{FunctionName: name, Payload: payload})
				if err != nil {
					t.Fatal(err)
				}
				if out.FunctionError != nil {
					t.Fatalf("native customer failure: %s %s", aws.ToString(out.FunctionError), out.Payload)
				}
				var response struct {
					OK    bool   `json:"ok"`
					Error string `json:"error"`
				}
				if err := json.Unmarshal(out.Payload, &response); err != nil {
					t.Fatal(err)
				}
				if response.OK != want || stringError != "" && !strings.Contains(response.Error, stringError) {
					t.Fatalf("native endpoint result want=%t: %s", want, out.Payload)
				}
			}
			receive := func(want string) {
				t.Helper()
				out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
				if err != nil {
					t.Fatal(err)
				}
				if want == "" {
					if len(out.Messages) != 0 {
						t.Fatalf("denied packet path wrote queue messages: %+v", out.Messages)
					}
					return
				}
				if len(out.Messages) != 1 || aws.ToString(out.Messages[0].Body) != want {
					t.Fatalf("real queue did not receive %q: %+v", want, out.Messages)
				}
				if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: queue.QueueUrl, ReceiptHandle: out.Messages[0].ReceiptHandle}); err != nil {
					t.Fatal(err)
				}
			}
			invoke("sqs", "private-endpoint", false, true, "")
			receive("private-endpoint")
			invoke("kinesis", "private-kinesis", false, true, "")
			described, err := streams.DescribeStream(t.Context(), &kinesis.DescribeStreamInput{StreamName: &streamName})
			if err != nil {
				t.Fatal(err)
			}
			iterator, err := streams.GetShardIterator(t.Context(), &kinesis.GetShardIteratorInput{StreamName: &streamName, ShardId: described.StreamDescription.Shards[0].ShardId, ShardIteratorType: "TRIM_HORIZON"})
			if err != nil {
				t.Fatal(err)
			}
			records, err := streams.GetRecords(t.Context(), &kinesis.GetRecordsInput{ShardIterator: iterator.ShardIterator})
			if err != nil || len(records.Records) != 1 || string(records.Records[0].Data) != "private-kinesis" {
				t.Fatalf("real Kafka-backed record missing: %+v %v", records, err)
			}
			if _, err := networks.ModifyVpcEndpoint(t.Context(), &ec2.ModifyVpcEndpointInput{VpcEndpointId: endpoints["sqs"], PolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*"}}`)}); err != nil {
				t.Fatal(err)
			}
			invoke("sqs", "endpoint-denied", false, false, "AccessDenied")
			receive("")
			wrongVpc := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpc":"%s-other"}}}}`, aws.ToString(vpcID))
			if _, err := networks.ModifyVpcEndpoint(t.Context(), &ec2.ModifyVpcEndpointInput{VpcEndpointId: endpoints["sqs"], PolicyDocument: &wrongVpc}); err != nil {
				t.Fatal(err)
			}
			invoke("sqs", "wrong-vpc", false, false, "AccessDenied")
			receive("")
			if _, err := networks.ModifyVpcEndpoint(t.Context(), &ec2.ModifyVpcEndpointInput{VpcEndpointId: endpoints["sqs"], PolicyDocument: &policy}); err != nil {
				t.Fatal(err)
			}
			if _, err := networks.RevokeSecurityGroupIngress(t.Context(), &ec2.RevokeSecurityGroupIngressInput{GroupId: endpointGroup, IpPermissions: permission}); err != nil {
				t.Fatal(err)
			}
			invoke("sqs", "security-group-blocked", false, false, "")
			receive("")
			if _, err := networks.AuthorizeSecurityGroupIngress(t.Context(), &ec2.AuthorizeSecurityGroupIngressInput{GroupId: endpointGroup, IpPermissions: permission}); err != nil {
				t.Fatal(err)
			}
			acls, err := networks.DescribeNetworkAcls(t.Context(), &ec2.DescribeNetworkAclsInput{Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{aws.ToString(vpcID)}}}})
			if err != nil {
				t.Fatal(err)
			}
			aclID := acls.NetworkAcls[0].NetworkAclId
			if _, err := networks.CreateNetworkAclEntry(t.Context(), &ec2.CreateNetworkAclEntryInput{NetworkAclId: aclID, RuleNumber: aws.Int32(10), Egress: aws.Bool(true), Protocol: aws.String("6"), RuleAction: ec2types.RuleActionDeny, CidrBlock: aws.String("0.0.0.0/0"), PortRange: &ec2types.PortRange{From: aws.Int32(443), To: aws.Int32(443)}}); err != nil {
				t.Fatal(err)
			}
			invoke("sqs", "network-acl-blocked", false, false, "")
			receive("")
			if _, err := networks.DeleteNetworkAclEntry(t.Context(), &ec2.DeleteNetworkAclEntryInput{NetworkAclId: aclID, RuleNumber: aws.Int32(10), Egress: aws.Bool(true)}); err != nil {
				t.Fatal(err)
			}
			invoke("sqs", "nat-route-absent", true, false, "")
			receive("")
			igw, err := networks.CreateInternetGateway(t.Context(), &ec2.CreateInternetGatewayInput{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := networks.AttachInternetGateway(t.Context(), &ec2.AttachInternetGatewayInput{InternetGatewayId: igw.InternetGateway.InternetGatewayId, VpcId: vpcID}); err != nil {
				t.Fatal(err)
			}
			tables, err := networks.DescribeRouteTables(t.Context(), &ec2.DescribeRouteTablesInput{Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{aws.ToString(vpcID)}}}})
			if err != nil {
				t.Fatal(err)
			}
			var mainTable *string
			for _, table := range tables.RouteTables {
				for _, association := range table.Associations {
					if aws.ToBool(association.Main) {
						mainTable = table.RouteTableId
					}
				}
			}
			if _, err := networks.CreateRoute(t.Context(), &ec2.CreateRouteInput{RouteTableId: mainTable, DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: igw.InternetGateway.InternetGatewayId}); err != nil {
				t.Fatal(err)
			}
			eip, err := networks.AllocateAddress(t.Context(), &ec2.AllocateAddressInput{Domain: ec2types.DomainTypeVpc})
			if err != nil {
				t.Fatal(err)
			}
			nat, err := networks.CreateNatGateway(t.Context(), &ec2.CreateNatGatewayInput{SubnetId: publicSubnet, AllocationId: eip.AllocationId})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := networks.CreateRoute(t.Context(), &ec2.CreateRouteInput{RouteTableId: privateTable.RouteTable.RouteTableId, DestinationCidrBlock: aws.String("0.0.0.0/0"), NatGatewayId: nat.NatGateway.NatGatewayId}); err != nil {
				t.Fatal(err)
			}
			invoke("sqs", "real-private-nat", true, true, "")
			receive("real-private-nat")
			if _, err := networks.DeleteRoute(t.Context(), &ec2.DeleteRouteInput{RouteTableId: privateTable.RouteTable.RouteTableId, DestinationCidrBlock: aws.String("0.0.0.0/0")}); err != nil {
				t.Fatal(err)
			}
			invoke("sqs", "withdrawn-nat-route", true, false, "")
			receive("")
			invoke("sqs", "restored-private-endpoint", false, true, "")
			receive("restored-private-endpoint")
			if _, err := functions.DeleteFunction(t.Context(), &lambda.DeleteFunctionInput{FunctionName: name}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
