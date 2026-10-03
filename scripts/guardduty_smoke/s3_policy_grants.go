package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func s3PolicyGrantDetection(ctx context.Context, endpoint string, detectorClient *gd.Client, roles *iam.Client, detector *string) func() {
	const account = "123456789012"
	bucket, key, body := "guardduty-policy-grants", "proof/observed-object", "anonymous policy grant: actual owned object bytes"
	owner := s3.NewFromConfig(config(account, "us-east-1"), func(o *s3.Options) { o.BaseEndpoint = &endpoint; o.UsePathStyle = true })
	unsignedConfig := config(account, "us-east-1")
	unsignedConfig.Credentials = aws.AnonymousCredentials{}
	anonymous := s3.NewFromConfig(unsignedConfig, func(o *s3.Options) { o.BaseEndpoint = &endpoint; o.UsePathStyle = true })
	_, err := owner.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	must(err)
	_, err = owner.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: strings.NewReader(body)})
	must(err)
	// Detection concerns the admitted grant, but actual unsigned access also
	// requires disabling the owned bucket's request-time public-access masks.
	_, err = owner.DeletePublicAccessBlock(ctx, &s3.DeletePublicAccessBlockInput{Bucket: &bucket})
	must(err)
	readAnonymous := func(allowed bool) {
		out, e := anonymous.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
		if !allowed {
			if e == nil {
				must(out.Body.Close())
			}
			code(e, "AccessDenied")
			return
		}
		must(e)
		actual, e := io.ReadAll(out.Body)
		must(e)
		must(out.Body.Close())
		check(string(actual) == body, "unsigned S3 request did not return exact owned object bytes")
	}
	findings := func() []gt.Finding {
		page, e := detectorClient.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: detector, FindingCriteria: &gt.FindingCriteria{Criterion: map[string]gt.Condition{
			"type":                                {Equals: []string{"Policy:S3/BucketAnonymousAccessGranted"}},
			"service.action.awsApiCallAction.api": {Equals: []string{"PutBucketPolicy"}},
		}}})
		must(e)
		if len(page.FindingIds) == 0 {
			return nil
		}
		out, e := detectorClient.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: detector, FindingIds: page.FindingIds})
		must(e)
		return out.Findings
	}
	findingID := ""
	checkCount := func(want int32) {
		got := findings()
		if want == 0 {
			check(len(got) == 0, "non-grant or rejected bucket policy generated an anonymous grant finding")
			return
		}
		check(len(got) == 1 && aws.ToInt32(got[0].Service.Count) == want, "bucket policy anonymous grant count changed")
		finding := got[0]
		check(aws.ToString(finding.Type) == "Policy:S3/BucketAnonymousAccessGranted" && aws.ToString(finding.AccountId) == account && aws.ToString(finding.Region) == "us-east-1", "bucket policy finding lost its type or admitted scope")
		action := finding.Service.Action.AwsApiCallAction
		check(aws.ToString(action.Api) == "PutBucketPolicy" && aws.ToString(action.ServiceName) == "s3.amazonaws.com" && aws.ToString(action.ErrorCode) == "" && action.AffectedResources["AWS::S3::Bucket"] == bucket, "bucket policy finding lost successful admitted API/bucket identity")
		check(aws.ToString(finding.Resource.ResourceType) == "AccessKey" && aws.ToString(finding.Resource.AccessKeyDetails.UserType) == "Root" && aws.ToFloat64(finding.Severity) == 8, "bucket policy finding lost its actual caller/severity")
		if findingID == "" {
			findingID = aws.ToString(finding.Id)
		} else {
			check(aws.ToString(finding.Id) == findingID, "bucket policy finding identity changed across replacement/restart")
		}
	}
	put := func(document string) {
		_, e := owner.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &document})
		must(e)
	}
	policyState := func() string {
		out, e := owner.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
		must(e)
		return aws.ToString(out.Policy)
	}
	readAnonymous(false)
	checkCount(0)
	resource := "arn:aws:s3:::" + bucket + "/" + key
	public := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":%q}]}`, resource)
	private := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":%q}]}`, resource)
	put(private)
	readAnonymous(false)
	checkCount(0)

	// A real IAM user without S3 permission cannot replace admitted policy.
	name := aws.String("guardduty-policy-denied")
	_, err = roles.CreateUser(ctx, &iam.CreateUserInput{UserName: name})
	must(err)
	defer func() { _, e := roles.DeleteUser(ctx, &iam.DeleteUserInput{UserName: name}); must(e) }()
	access, err := roles.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: name})
	must(err)
	defer func() {
		_, e := roles.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: name, AccessKeyId: access.AccessKey.AccessKeyId})
		must(e)
	}()
	deniedConfig := config(account, "us-east-1")
	deniedConfig.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(access.AccessKey.AccessKeyId), aws.ToString(access.AccessKey.SecretAccessKey), "")
	denied := s3.NewFromConfig(deniedConfig, func(o *s3.Options) { o.BaseEndpoint = &endpoint; o.UsePathStyle = true })
	before := policyState()
	_, err = denied.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &public})
	code(err, "AccessDenied")
	check(policyState() == before, "IAM-denied PutBucketPolicy changed admitted policy")
	readAnonymous(false)
	checkCount(0)

	// Unconditional deny coverage must subtract the entire allowed action/resource
	// set, not merely reject a guessed representative object key.
	coveredAction := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":%q},{"Effect":"Deny","Principal":"*","Action":"s3:Get*","Resource":%q}]}`, resource, resource)
	coveredResource := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/proof/*"},{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}`, bucket, bucket)
	for _, document := range []string{coveredAction, coveredResource} {
		put(document)
		readAnonymous(false)
		checkCount(0)
	}
	put(public)
	readAnonymous(true)
	checkCount(1)
	put(coveredResource)
	readAnonymous(false)
	checkCount(1)

	// These are actual unsigned HTTP reads. Finding admission must keep each
	// transport branch consistent; this smoke does not send HTTPS requests.
	httpOnly := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":%q,"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, resource)
	put(httpOnly)
	readAnonymous(true)
	checkCount(2)
	httpCovered := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":%q,"Condition":{"Bool":{"aws:SecureTransport":"false"}}},{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":%q,"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, resource, resource)
	put(httpCovered)
	readAnonymous(false)
	checkCount(2)
	bothTransportsCovered := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":%q},{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":%q,"Condition":{"Bool":{"aws:SecureTransport":"false"}}},{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":%q,"Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`, resource, resource, resource)
	put(bothTransportsCovered)
	readAnonymous(false)
	checkCount(2)

	// Anonymous principal context differs from the signed policy writer:
	// PrincipalAccount is "anonymous"; PrincipalIsAWSService is absent, not false.
	principalStatement := func(effect, condition string) string {
		return fmt.Sprintf(`{"Effect":%q,"Principal":"*","Action":"s3:GetObject","Resource":%q,"Condition":%s}`, effect, resource, condition)
	}
	allow := fmt.Sprintf(`{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":%q}`, resource)
	count := int32(2)
	for _, scenario := range []struct {
		statements string
		allowed    bool
	}{
		{principalStatement("Allow", `{"StringEquals":{"aws:PrincipalAccount":"anonymous"}}`), true},
		{principalStatement("Allow", `{"StringEquals":{"aws:PrincipalAccount":"123456789012"}}`), false},
		{allow + "," + principalStatement("Deny", `{"StringEquals":{"aws:PrincipalAccount":"anonymous"}}`), false},
		{principalStatement("Allow", `{"Null":{"aws:PrincipalIsAWSService":"true"}}`), true},
		{principalStatement("Allow", `{"Bool":{"aws:PrincipalIsAWSService":"false"}}`), false},
		{allow + "," + principalStatement("Deny", `{"Bool":{"aws:PrincipalIsAWSService":"false"}}`), true},
		{allow + "," + principalStatement("Deny", `{"BoolIfExists":{"aws:PrincipalIsAWSService":"false"}}`), false},
		{principalStatement("Allow", `{"StringEquals":{"aws:PrincipalAccount":"anonymous"},"Bool":{"aws:SecureTransport":"false"},"Null":{"aws:PrincipalIsAWSService":"true"}}`), true},
	} {
		put(`{"Version":"2012-10-17","Statement":[` + scenario.statements + `]}`)
		readAnonymous(scenario.allowed)
		if scenario.allowed {
			count++
		}
		checkCount(count)
	}

	put(private)
	readAnonymous(false)
	checkCount(count)
	retainedPolicy := policyState()
	return func() {
		check(policyState() == retainedPolicy, "SQLite restart changed admitted private bucket policy")
		readAnonymous(false)
		checkCount(count)
		_, e := owner.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
		must(e)
		_, e = owner.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
		must(e)
		_, e = owner.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
		must(e)
		checkCount(count)
		fmt.Println("GuardDuty admitted bucket policy: unsigned private denial/public exact bytes, HTTP transport-conditioned allow exact bytes/matching deny/split-transport denies, anonymous PrincipalAccount and absent PrincipalIsAWSService with Bool/BoolIfExists/Null, signed finding API/bucket identity, IAM-denied unchanged state, covered action/resource denies, fixed-principal exclusion, private replacement and SQLite restart evidence: PASS")
	}
}
