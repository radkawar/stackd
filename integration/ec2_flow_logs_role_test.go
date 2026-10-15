package stackd_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"stackd"
)

func TestEC2FlowLogsPassRoleAndConcreteSourceTrustSDK(t *testing.T) {
	const account = "718349256012"
	const group = "/flow-logs/current-role"
	c := clockCloud(t, stackd.Config{AccountID: account})
	client := func(key, secret string) *ec2.Client {
		return ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	}
	owner, roles, events := client("test", "test"), c.iam("test", "test", ""), logsClient(c, "test")
	vpc, err := owner.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.88.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"vpc-flow-logs.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":"%s"},"ArnLike":{"aws:SourceArn":"arn:aws:ec2:us-east-1:%s:vpc-flow-log/fl-*"}}}}`, account, account)
	role, err := roles.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("flow-writer"), AssumeRolePolicyDocument: aws.String(trust)})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, roles, "flow-writer", allow(`["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"]`, "*"))
	_, key, secret := c.user(t, "test", "flow-caller")
	putUserPolicy(t, roles, "flow-caller", allow(`["ec2:*"]`, "*"))
	caller := client(key, secret)
	input := &ec2.CreateFlowLogsInput{ResourceIds: []string{aws.ToString(vpc.Vpc.VpcId)}, ResourceType: ec2types.FlowLogsResourceTypeVpc, TrafficType: ec2types.TrafficTypeAll, LogGroupName: aws.String(group), DeliverLogsPermissionArn: role.Role.Arn, ClientToken: aws.String("role-admission")}
	_, err = caller.CreateFlowLogs(t.Context(), input)
	assertAPIError(t, err, "UnauthorizedOperation")
	before, err := events.DescribeLogGroups(t.Context(), &cloudwatchlogs.DescribeLogGroupsInput{LogGroupNamePrefix: aws.String(group)})
	if err != nil || len(before.LogGroups) != 0 {
		t.Fatalf("denied PassRole created log destination: %+v %v", before, err)
	}
	permission := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Effect":"Allow","Action":"iam:PassRole","Resource":%q,"Condition":{"StringEquals":{"iam:PassedToService":"vpc-flow-logs.amazonaws.com"},"ArnLike":{"iam:AssociatedResourceArn":"arn:aws:ec2:us-east-1:%s:vpc-flow-log/fl-*"}}}]}`, aws.ToString(role.Role.Arn), account)
	putUserPolicy(t, roles, "flow-caller", permission)
	out, err := caller.CreateFlowLogs(t.Context(), input)
	if err != nil || len(out.FlowLogIds) != 1 || len(out.Unsuccessful) != 0 {
		t.Fatalf("concrete source ARN admission: %+v %v", out, err)
	}
	streams, err := events.DescribeLogStreams(t.Context(), &cloudwatchlogs.DescribeLogStreamsInput{LogGroupName: aws.String(group)})
	if err != nil || len(streams.LogStreams) != 0 {
		t.Fatalf("empty VPC created fictitious ENI streams: %+v %v", streams, err)
	}
	// Later admission must use current trust, not an earlier successful session.
	changedTrust := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"vpc-flow-logs.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":"918349256013"}}}}`
	if _, err := roles.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{RoleName: aws.String("flow-writer"), PolicyDocument: aws.String(changedTrust)}); err != nil {
		t.Fatal(err)
	}
	input.ClientToken = aws.String("changed-source-trust")
	input.TrafficType = ec2types.TrafficTypeReject
	_, err = caller.CreateFlowLogs(t.Context(), input)
	assertAPIError(t, err, "InvalidParameter")
}
