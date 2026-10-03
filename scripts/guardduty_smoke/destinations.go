package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	st "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// publishingDestinations uses the executable's shared SQLite database and saved
// manual clock. Its callback belongs immediately after the existing restart.
func publishingDestinations(ctx context.Context, endpoint string, features []gt.DetectorFeatureConfiguration) func() {
	const account = "123456789012"
	const region = "us-west-2"
	const rootType = "Policy:IAMUser/RootCredentialUsage"
	const sampleType = "Backdoor:EC2/DenialOfService.Tcp"
	c := client(endpoint, account, region)
	objects := s3.NewFromConfig(config(account, region), func(o *s3.Options) { o.BaseEndpoint = &endpoint; o.UsePathStyle = true })
	keys := kms.NewFromConfig(config(account, region), func(o *kms.Options) { o.BaseEndpoint = &endpoint })
	created, err := c.CreateDetector(ctx, &gd.CreateDetectorInput{Enable: aws.Bool(false), Features: features, FindingPublishingFrequency: gt.FindingPublishingFrequencyFifteenMinutes})
	must(err)
	detector := created.DetectorId
	sourceARN := "arn:aws:guardduty:" + region + ":" + account + ":detector/" + aws.ToString(detector)
	bucket := "guardduty-destinations-" + aws.ToString(detector)
	bucketARN := "arn:aws:s3:::" + bucket
	_, err = objects.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket, CreateBucketConfiguration: &st.CreateBucketConfiguration{LocationConstraint: st.BucketLocationConstraint(region)}})
	must(err)
	keyPolicy := func(source string) string {
		return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"Service":"guardduty.amazonaws.com"},"Action":"kms:GenerateDataKey","Resource":"*","Condition":{"StringEquals":{"aws:SourceAccount":%q,"aws:SourceArn":%q}}}]}`, account, account, source)
	}
	key, err := keys.CreateKey(ctx, &kms.CreateKeyInput{Description: aws.String("Owned GuardDuty destination executable smoke key"), Policy: aws.String(keyPolicy(sourceARN))})
	must(err)
	keyARN := key.KeyMetadata.Arn
	putKeyPolicy := func(source string) {
		_, e := keys.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{KeyId: keyARN, PolicyName: aws.String("default"), Policy: aws.String(keyPolicy(source))})
		must(e)
	}
	putBucketPolicy := func(source string) {
		policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"guardduty.amazonaws.com"},"Action":"s3:GetBucketLocation","Resource":%q,"Condition":{"StringEquals":{"aws:SourceAccount":%q,"aws:SourceArn":%q}}},{"Effect":"Allow","Principal":{"Service":"guardduty.amazonaws.com"},"Action":"s3:PutObject","Resource":%q,"Condition":{"StringEquals":{"aws:SourceAccount":%q,"aws:SourceArn":%q,"s3:x-amz-server-side-encryption":"aws:kms","s3:x-amz-server-side-encryption-aws-kms-key-id":%q}}},{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":%q,"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, bucketARN, account, source, bucketARN+"/AWSLogs/*", account, source, aws.ToString(keyARN), bucketARN+"/*")
		_, e := objects.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &policy})
		must(e)
	}
	properties := &gt.DestinationProperties{DestinationArn: &bucketARN, KmsKeyArn: keyARN}
	create := func(token string) (*gd.CreatePublishingDestinationOutput, error) {
		return c.CreatePublishingDestination(ctx, &gd.CreatePublishingDestinationInput{DetectorId: detector, DestinationType: gt.DestinationTypeS3, DestinationProperties: properties, ClientToken: &token, Tags: map[string]string{"owner": "destination-smoke"}})
	}
	list := func() []gt.Destination {
		var result []gt.Destination
		input := &gd.ListPublishingDestinationsInput{DetectorId: detector, MaxResults: aws.Int32(1)}
		for {
			out, e := c.ListPublishingDestinations(ctx, input)
			must(e)
			result = append(result, out.Destinations...)
			if aws.ToString(out.NextToken) == "" {
				return result
			}
			check(aws.ToString(input.NextToken) != aws.ToString(out.NextToken), "destination pagination repeated its cursor")
			input.NextToken = out.NextToken
		}
	}
	objectKeys := func() []string {
		var result []string
		pages := s3.NewListObjectsV2Paginator(objects, &s3.ListObjectsV2Input{Bucket: &bucket})
		for pages.HasMorePages() {
			page, e := pages.NextPage(ctx)
			must(e)
			for _, object := range page.Contents {
				result = append(result, aws.ToString(object.Key))
			}
		}
		return result
	}
	putBucketPolicy(sourceARN + "-wrong")
	_, err = create("destination-denied")
	code(err, "BadRequestException")
	check(len(list()) == 0 && len(objectKeys()) == 0, "source-policy rejection left a destination or marker")
	putBucketPolicy(sourceARN)
	destination, err := create("destination-owned")
	must(err)
	id := destination.DestinationId
	resourceARN := sourceARN + "/publishingdestination/" + aws.ToString(id)
	replay, err := create("destination-owned")
	must(err)
	check(aws.ToString(replay.DestinationId) == aws.ToString(id), "destination token replay changed identity")
	inventory := list()
	check(len(inventory) == 1 && aws.ToString(inventory[0].DestinationId) == aws.ToString(id), "destination list lost owned destination")
	describe := func() *gd.DescribePublishingDestinationOutput {
		out, e := c.DescribePublishingDestination(ctx, &gd.DescribePublishingDestinationInput{DetectorId: detector, DestinationId: id})
		must(e)
		check(out.DestinationType == gt.DestinationTypeS3 && aws.ToString(out.DestinationId) == aws.ToString(id), "destination describe changed identity/type")
		check(out.DestinationProperties != nil && aws.ToString(out.DestinationProperties.DestinationArn) == bucketARN && aws.ToString(out.DestinationProperties.KmsKeyArn) == aws.ToString(keyARN), "destination properties changed")
		return out
	}
	check(describe().Status == gt.PublishingStatusPublishing, "validated destination is not publishing")
	_, err = c.UpdatePublishingDestination(ctx, &gd.UpdatePublishingDestinationInput{DetectorId: detector, DestinationId: id, DestinationProperties: properties})
	must(err)
	_, err = c.TagResource(ctx, &gd.TagResourceInput{ResourceArn: &resourceARN, Tags: map[string]string{"owner": "destination-updated", "temporary": "remove"}})
	must(err)
	_, err = c.UntagResource(ctx, &gd.UntagResourceInput{ResourceArn: &resourceARN, TagKeys: []string{"temporary"}})
	must(err)
	verifyTags := func() {
		out, e := c.ListTagsForResource(ctx, &gd.ListTagsForResourceInput{ResourceArn: &resourceARN})
		must(e)
		check(len(out.Tags) == 1 && out.Tags["owner"] == "destination-updated", "destination tags were not retained")
		check(describe().Tags["owner"] == "destination-updated", "describe lost destination tags")
	}
	verifyTags()
	marker, err := objects.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: aws.String("AWSLogs/")})
	must(err)
	markerBytes, err := io.ReadAll(marker.Body)
	must(err)
	must(marker.Body.Close())
	check(len(markerBytes) == 0 && marker.ServerSideEncryption == st.ServerSideEncryptionAwsKms && aws.ToString(marker.SSEKMSKeyId) == aws.ToString(keyARN), "destination marker was not empty and encrypted with the owned KMS key")
	// The public endpoint is plain HTTP. This write must fail while trusted
	// GuardDuty service delivery succeeds under the same SecureTransport deny.
	_, err = objects.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: aws.String("AWSLogs/insecure-caller"), Body: strings.NewReader("not service delivery"), ServerSideEncryption: st.ServerSideEncryptionAwsKms, SSEKMSKeyId: keyARN})
	code(err, "AccessDenied")

	// Use a named controller so enabling detection does not itself introduce a
	// second root-use finding. Only the intentional KMS calls use root identity.
	users := iam.NewFromConfig(config(account, region), func(o *iam.Options) { o.BaseEndpoint = &endpoint })
	user := aws.String("guardduty-export-" + aws.ToString(detector))
	_, err = users.CreateUser(ctx, &iam.CreateUserInput{UserName: user})
	must(err)
	credential, err := users.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: user})
	must(err)
	policyName := aws.String("guardduty-control")
	_, err = users.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: user, PolicyName: policyName, PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"guardduty:*","Resource":"*"}]}`)})
	must(err)
	controller := config(account, region)
	controller.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(credential.AccessKey.AccessKeyId), aws.ToString(credential.AccessKey.SecretAccessKey), "")
	c = gd.NewFromConfig(controller, func(o *gd.Options) { o.BaseEndpoint = &endpoint })

	clock := func(advance time.Duration) time.Time {
		method, body := http.MethodGet, ""
		if advance > 0 {
			method, body = http.MethodPost, fmt.Sprintf(`{"advance":%q}`, advance.String())
		}
		req, e := http.NewRequestWithContext(ctx, method, endpoint+"/_stackd/clock", strings.NewReader(body))
		must(e)
		req.Header.Set("Content-Type", "application/json")
		response, e := http.DefaultClient.Do(req)
		must(e)
		check(response.StatusCode == http.StatusOK, "destination clock request failed")
		var out struct {
			Time time.Time `json:"time"`
		}
		must(json.NewDecoder(response.Body).Decode(&out))
		must(response.Body.Close())
		return out.Time
	}
	drain := func() {
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/_stackd/jobs/drain?limit=1024", nil)
		must(e)
		response, e := http.DefaultClient.Do(req)
		must(e)
		must(response.Body.Close())
		check(response.StatusCode == http.StatusOK, "destination job drain failed")
	}
	observe := func(count int) {
		_, e := c.UpdateDetector(ctx, &gd.UpdateDetectorInput{DetectorId: detector, Enable: aws.Bool(true)})
		must(e)
		for range count {
			_, e = keys.ListKeys(ctx, &kms.ListKeysInput{})
			must(e)
		}
		_, e = c.UpdateDetector(ctx, &gd.UpdateDetectorInput{DetectorId: detector, Enable: aws.Bool(false)})
		must(e)
	}
	observe(2)
	_, err = c.CreateSampleFindings(ctx, &gd.CreateSampleFindingsInput{DetectorId: detector, FindingTypes: []string{sampleType}})
	must(err)
	findings, err := c.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: detector})
	must(err)
	check(len(findings.FindingIds) == 2, "destination detector did not isolate observed and sample sources")
	initial, err := c.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: detector, FindingIds: findings.FindingIds})
	must(err)
	var root, sample gt.Finding
	for _, finding := range initial.Findings {
		switch aws.ToString(finding.Type) {
		case rootType:
			root = finding
		case sampleType:
			sample = finding
		}
	}
	check(root.Id != nil && sample.Id != nil && root.Service != nil && root.Resource != nil && root.Resource.AccessKeyDetails != nil, "missing real root or separate sample finding")
	check(aws.ToInt32(root.Service.Count) == 2 && aws.ToString(root.Resource.AccessKeyDetails.UserType) == "Root", "actual ListKeys calls did not aggregate root identity")
	check(root.Service.Action != nil && root.Service.Action.AwsApiCallAction != nil && aws.ToString(root.Service.Action.AwsApiCallAction.Api) == "ListKeys" && aws.ToString(root.Service.Action.AwsApiCallAction.ServiceName) == "kms.amazonaws.com", "observed source is not the regional KMS ListKeys operation")
	rootID, sampleID := aws.ToString(root.Id), aws.ToString(sample.Id)
	// Every export is obtained through signed S3 List/Get, not through SQLite
	// inspection. JSONL records must preserve the SDK-visible finding identity.
	verifyExports := func(rootCounts ...int32) {
		want := map[string]map[int32]bool{rootID: {}, sampleID: {1: true}}
		for _, count := range rootCounts {
			want[rootID][count] = true
		}
		seen := map[string]map[int32]bool{rootID: {}, sampleID: {}}
		keys := objectKeys()
		check(len(keys) == len(rootCounts)+2, fmt.Sprintf("destination object count: %d, want marker plus %d exports", len(keys), len(rootCounts)+1))
		for _, objectKey := range keys {
			if objectKey == "AWSLogs/" {
				continue
			}
			check(strings.HasPrefix(objectKey, "AWSLogs/"+account+"/GuardDuty/"+region+"/") && strings.HasSuffix(objectKey, ".jsonl.gz"), "export object key escaped owned detector scope")
			out, e := objects.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &objectKey})
			must(e)
			check(out.ServerSideEncryption == st.ServerSideEncryptionAwsKms && aws.ToString(out.SSEKMSKeyId) == aws.ToString(keyARN), "finding object lost SSE-KMS key")
			compressed, e := gzip.NewReader(out.Body)
			must(e)
			scanner := bufio.NewScanner(compressed)
			scanner.Buffer(make([]byte, 4096), 1024*1024)
			rows := 0
			for scanner.Scan() {
				var finding gt.Finding
				must(json.Unmarshal(scanner.Bytes(), &finding))
				findingID := aws.ToString(finding.Id)
				check(finding.Service != nil, "export has no service metadata")
				count := aws.ToInt32(finding.Service.Count)
				check(want[findingID][count] && !seen[findingID][count], "export duplicated or changed finding ID/count")
				seen[findingID][count] = true
				check(aws.ToString(finding.AccountId) == account && aws.ToString(finding.Region) == region && aws.ToString(finding.Service.DetectorId) == aws.ToString(detector) && !aws.ToBool(finding.Service.Archived), "export changed scope or included archived finding")
				if findingID == rootID {
					check(aws.ToString(finding.Type) == rootType && aws.ToString(finding.Arn) == aws.ToString(root.Arn), "observed export changed type/ARN")
					check(finding.Service.Action != nil && finding.Service.Action.AwsApiCallAction != nil && aws.ToString(finding.Service.Action.AwsApiCallAction.Api) == "ListKeys" && aws.ToString(finding.Service.Action.AwsApiCallAction.ServiceName) == "kms.amazonaws.com", "observed export lost actual API source")
					check(finding.Resource != nil && finding.Resource.AccessKeyDetails != nil, "observed export lost access-key identity")
					identity := finding.Resource.AccessKeyDetails
					check(aws.ToString(identity.AccessKeyId) == aws.ToString(root.Resource.AccessKeyDetails.AccessKeyId) && aws.ToString(identity.PrincipalId) == aws.ToString(root.Resource.AccessKeyDetails.PrincipalId) && aws.ToString(identity.UserName) == aws.ToString(root.Resource.AccessKeyDetails.UserName) && aws.ToString(identity.UserType) == "Root", "observed export substituted caller identity")
				} else {
					check(aws.ToString(finding.Type) == sampleType && aws.ToString(finding.Arn) == aws.ToString(sample.Arn), "sample export was confused with observed activity")
				}
				rows++
			}
			must(scanner.Err())
			must(compressed.Close())
			must(out.Body.Close())
			check(rows == 1, "export object is not one finding JSONL record")
		}
		for findingID, counts := range want {
			for count := range counts {
				check(seen[findingID][count], "expected finding version missing from S3")
			}
		}
	}
	drain()
	check(len(objectKeys()) == 1, "finding exported before initial five-minute deadline")
	clock(5*time.Minute - time.Second)
	drain()
	check(len(objectKeys()) == 1, "finding exported before initial deadline boundary")
	clock(time.Second)
	drain()
	verifyExports(2)

	observe(1)
	_, err = c.ArchiveFindings(ctx, &gd.ArchiveFindingsInput{DetectorId: detector, FindingIds: []string{rootID}})
	must(err)
	clock(15 * time.Minute)
	drain()
	verifyExports(2)
	_, err = c.UnarchiveFindings(ctx, &gd.UnarchiveFindingsInput{DetectorId: detector, FindingIds: []string{rootID}})
	must(err)
	drain()
	verifyExports(2, 3)

	observe(1)
	// Keep S3 and its exact detector SourceArn policy unchanged. Revoking only
	// the current KMS service grant must block an already queued real export.
	putKeyPolicy(sourceARN + "-wrong")
	failedAt := clock(15 * time.Minute)
	drain()
	failed := describe()
	check(string(failed.Status) == "UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY" && aws.ToInt64(failed.PublishingFailureStartTimestamp) == failedAt.UnixMilli(), "current KMS denial did not record destination failure at delivery time")
	verifyExports(2, 3)
	putKeyPolicy(sourceARN)
	clock(5*time.Minute - time.Second)
	drain()
	verifyExports(2, 3)
	clock(time.Second)
	drain()
	verifyExports(2, 3, 4)
	recovered := describe()
	check(recovered.Status == gt.PublishingStatusPublishing && aws.ToInt64(recovered.PublishingFailureStartTimestamp) == 0, "restored key policy did not recover and clear publication failure")
	observe(1)
	drain()
	verifyExports(2, 3, 4)
	savedClock := clock(0)

	return func() {
		check(clock(0).Equal(savedClock), "SQLite restart lost saved destination clock")
		verifyTags()
		check(describe().Status == gt.PublishingStatusPublishing && len(list()) == 1, "SQLite restart lost destination config/status")
		drain()
		verifyExports(2, 3, 4)
		clock(15*time.Minute - time.Second)
		drain()
		verifyExports(2, 3, 4)
		clock(time.Second)
		drain()
		verifyExports(2, 3, 4, 5)
		drain()
		verifyExports(2, 3, 4, 5)
		prefixReadPolicy := aws.String("prefix-read")
		denyStorage := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:*","kms:*"],"Resource":"*"}]}`
		_, err = users.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: user, PolicyName: prefixReadPolicy, PolicyDocument: &denyStorage})
		must(err)
		_, err = c.UpdatePublishingDestination(ctx, &gd.UpdatePublishingDestinationInput{DetectorId: detector, DestinationId: id, DestinationProperties: properties})
		must(err)
		// Prefix discovery requires the controller's current List/Get grants,
		// independently of the service's existing bucket/KMS delivery grants.
		prefixARN := bucketARN + "/explicit-prefix"
		prefixPolicy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"guardduty.amazonaws.com"},"Action":["s3:GetBucketLocation","s3:PutObject"],"Resource":[%q,%q],"Condition":{"StringEquals":{"aws:SourceAccount":%q,"aws:SourceArn":%q}}}]}`, bucketARN, prefixARN+"/*", account, sourceARN)
		_, err = objects.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &prefixPolicy})
		must(err)
		_, err = objects.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: aws.String("explicit-prefix/"), Body: strings.NewReader("")})
		must(err)
		updatePrefix := func() error {
			_, e := c.UpdatePublishingDestination(ctx, &gd.UpdatePublishingDestinationInput{DetectorId: detector, DestinationId: id, DestinationProperties: &gt.DestinationProperties{DestinationArn: &prefixARN}})
			return e
		}
		deniedPrefix := func() {
			err := updatePrefix()
			code(err, "BadRequestException")
			var response *smithyhttp.ResponseError
			check(errors.As(err, &response) && response.HTTPStatusCode() == 400, "prefix permission failure did not match native HTTP 400")
		}
		deniedPrefix()
		check(describe().Status == gt.PublishingStatusPublishing, "denied prefix update changed retained destination")
		listOnly := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":%q}]}`, bucketARN)
		_, err = users.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: user, PolicyName: prefixReadPolicy, PolicyDocument: &listOnly})
		must(err)
		deniedPrefix()
		readGrant := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":%q},{"Effect":"Allow","Action":"s3:GetObject","Resource":%q}]}`, bucketARN, prefixARN+"/*")
		_, err = users.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: user, PolicyName: prefixReadPolicy, PolicyDocument: &readGrant})
		must(err)
		must(updatePrefix())
		prefixed, e := c.DescribePublishingDestination(ctx, &gd.DescribePublishingDestinationInput{DetectorId: detector, DestinationId: id})
		must(e)
		check(aws.ToString(prefixed.DestinationProperties.DestinationArn) == prefixARN, "authorized prefix update was not retained")
		prefixMarker, e := objects.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: aws.String("explicit-prefix/AWSLogs/")})
		must(e)
		check(aws.ToInt64(prefixMarker.ContentLength) == 0 && prefixMarker.ServerSideEncryption == st.ServerSideEncryptionAwsKms && aws.ToString(prefixMarker.SSEKMSKeyId) == aws.ToString(keyARN), "authorized prefix lost encrypted permission marker")
		_, err = users.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: user, PolicyName: prefixReadPolicy})
		must(err)
		deniedPrefix()
		_, e = c.DeletePublishingDestination(ctx, &gd.DeletePublishingDestinationInput{DetectorId: detector, DestinationId: id})
		must(e)
		check(len(list()) == 0, "destination cleanup left owned config")
		_, e = c.DescribePublishingDestination(ctx, &gd.DescribePublishingDestinationInput{DetectorId: detector, DestinationId: id})
		code(e, "BadRequestException")
		_, e = c.DeleteDetector(ctx, &gd.DeleteDetectorInput{DetectorId: detector})
		must(e)
		detectors, e := c.ListDetectors(ctx, &gd.ListDetectorsInput{})
		must(e)
		check(len(detectors.DetectorIds) == 0, "destination detector cleanup failed")
		for _, objectKey := range objectKeys() {
			_, e = objects.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &objectKey})
			must(e)
		}
		check(len(objectKeys()) == 0, "owned destination bucket not empty before deletion")
		_, e = objects.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
		must(e)
		deletion, e := keys.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: keyARN, PendingWindowInDays: aws.Int32(7)})
		must(e)
		check(deletion.DeletionDate != nil, "owned destination KMS key deletion was not scheduled")
		_, e = users.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: user, PolicyName: policyName})
		must(e)
		_, e = users.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: user, AccessKeyId: credential.AccessKey.AccessKeyId})
		must(e)
		_, e = users.DeleteUser(ctx, &iam.DeleteUserInput{UserName: user})
		must(e)
		fmt.Println("GuardDuty signed destination CRUD/tags, source-policy denial, trusted encrypted marker, observed/sample gzip S3 exports, archive exclusion, current KMS denial/retry, prefix IAM grant/revocation, SQLite cursor restart and owned cleanup: PASS")
	}
}
