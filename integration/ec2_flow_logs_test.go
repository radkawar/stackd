package stackd_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"stackd"
)

func TestEC2FlowLogsS3CallerAuthorityAndPolicyPreservationSDK(t *testing.T) {
	const account = "718349256012"
	const bucket = "flow-log-policy-authority"
	c := clockCloud(t, stackd.Config{AccountID: account})
	client := func(key, secret string) *ec2.Client {
		return ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	}
	owner := client("test", "test")
	objects := s3NativeClient(c, "test", "test")
	vpc, err := owner.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.87.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objects.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	original := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"UnrelatedOwnerReadOnly","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/unrelated/*"}]}`, account, bucket)
	if _, err := objects.PutBucketPolicy(t.Context(), &s3.PutBucketPolicyInput{Bucket: aws.String(bucket), Policy: aws.String(original)}); err != nil {
		t.Fatal(err)
	}
	_, key, secret := c.user(t, "test", "flow-configurer")
	roles := c.iam("test", "test", "")
	putUserPolicy(t, roles, "flow-configurer", allow(`["ec2:*"]`, "*"))
	caller := client(key, secret)
	input := &ec2.CreateFlowLogsInput{ResourceIds: []string{aws.ToString(vpc.Vpc.VpcId)}, ResourceType: ec2types.FlowLogsResourceTypeVpc, TrafficType: ec2types.TrafficTypeAll, LogDestinationType: ec2types.LogDestinationTypeS3, LogDestination: aws.String("arn:aws:s3:::" + bucket), ClientToken: aws.String("first-admission")}
	_, err = caller.CreateFlowLogs(t.Context(), input)
	assertAPIError(t, err, "UnauthorizedOperation")
	before, err := objects.GetBucketPolicy(t.Context(), &s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
	if err != nil {
		t.Fatal(err)
	}
	var retained, expected map[string]any
	if err := json.Unmarshal([]byte(aws.ToString(before.Policy)), &retained); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(original), &expected); err != nil {
		t.Fatal(err)
	}
	if len(retained["Statement"].([]any)) != 1 {
		t.Fatalf("unauthorized configuration changed bucket policy: %s", aws.ToString(before.Policy))
	}
	putUserPolicy(t, roles, "flow-configurer", allow(`["ec2:*","s3:GetBucketPolicy","s3:PutBucketPolicy"]`, "*"))
	created, err := caller.CreateFlowLogs(t.Context(), input)
	if err != nil || len(created.FlowLogIds) != 1 || len(created.Unsuccessful) != 0 {
		t.Fatalf("authorized flow admission: %+v %v", created, err)
	}
	// A second prefix must retain the first destination grant and reuse the ACL
	// grant. The native reference is testdata/aws/ec2/flow_logs.json.
	input.ClientToken = aws.String("second-admission")
	input.LogDestination = aws.String("arn:aws:s3:::" + bucket + "/custom-prefix")
	input.LogFormat = aws.String("${interface-id}")
	input.DestinationOptions = &ec2types.DestinationOptionsRequest{FileFormat: ec2types.DestinationFileFormatPlainText, HiveCompatiblePartitions: aws.Bool(true), PerHourPartition: aws.Bool(true)}
	second, err := caller.CreateFlowLogs(t.Context(), input)
	if err != nil || len(second.FlowLogIds) != 1 || len(second.Unsuccessful) != 0 {
		t.Fatalf("second destination admission: %+v %v", second, err)
	}
	after, err := objects.GetBucketPolicy(t.Context(), &s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(aws.ToString(after.Policy)), &retained); err != nil {
		t.Fatal(err)
	}
	statements := retained["Statement"].([]any)
	if len(statements) != 4 {
		t.Fatalf("destination grants or ACL reuse differ from native: %s", aws.ToString(after.Policy))
	}
	originalJSON, _ := json.Marshal(expected["Statement"].([]any)[0])
	retainedJSON, _ := json.Marshal(statements[0])
	if string(originalJSON) != string(retainedJSON) {
		t.Fatalf("unrelated policy statement changed: %s", retainedJSON)
	}
	aclGrants, writes := 0, map[string]bool{}
	for _, raw := range statements[1:] {
		statement := raw.(map[string]any)
		if statement["Action"] == "s3:GetBucketAcl" {
			aclGrants++
		}
		if statement["Action"] == "s3:PutObject" {
			writes[statement["Resource"].(string)] = true
		}
		condition := statement["Condition"].(map[string]any)
		if condition["StringEquals"].(map[string]any)["aws:SourceAccount"] != account || condition["ArnLike"].(map[string]any)["aws:SourceArn"] != "arn:aws:logs:us-east-1:"+account+":*" {
			t.Fatalf("delivery permission lost source constraints: %+v", statement)
		}
	}
	if aclGrants != 1 || !writes["arn:aws:s3:::"+bucket+"/AWSLogs/"+account+"/*"] || !writes["arn:aws:s3:::"+bucket+"/custom-prefix/AWSLogs/aws-account-id="+account+"/*"] {
		t.Fatalf("incorrect destination permissions: %s", aws.ToString(after.Policy))
	}
	start := make(chan struct{})
	results := make(chan error, 4)
	for n := range 4 {
		go func() {
			<-start
			request := *input
			request.ClientToken = aws.String(fmt.Sprintf("parallel-%d", n))
			request.LogDestination = aws.String(fmt.Sprintf("arn:aws:s3:::%s/parallel-%d", bucket, n))
			out, err := caller.CreateFlowLogs(t.Context(), &request)
			if err == nil && (len(out.FlowLogIds) != 1 || len(out.Unsuccessful) != 0) {
				err = fmt.Errorf("parallel admission: %+v", out)
			}
			results <- err
		}()
	}
	close(start)
	for range 4 {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	final, err := objects.GetBucketPolicy(t.Context(), &s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(aws.ToString(final.Policy)), &retained); err != nil {
		t.Fatal(err)
	}
	for _, raw := range retained["Statement"].([]any) {
		statement := raw.(map[string]any)
		if statement["Action"] == "s3:PutObject" {
			writes[statement["Resource"].(string)] = true
		}
	}
	for n := range 4 {
		resource := fmt.Sprintf("arn:aws:s3:::%s/parallel-%d/AWSLogs/aws-account-id=%s/*", bucket, n, account)
		if !writes[resource] {
			t.Fatalf("concurrent admission lost delivery permission for %s: %s", resource, aws.ToString(final.Policy))
		}
	}
}
