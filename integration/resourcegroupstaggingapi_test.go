package stackd_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	tagtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type taggingFixture struct {
	Identity struct{ Account string }
	Owned    struct {
		Name     string
		ARNs     []string `json:"arns"`
		NeverARN string   `json:"never_arn"`
		QueueURL string   `json:"queue_url"`
	}
	Observations []struct {
		Case, Code, Operation string
		Input, Output         json.RawMessage
	}
}

func (f taggingFixture) input(t *testing.T, name string) json.RawMessage {
	t.Helper()
	for _, row := range f.Observations {
		if row.Case == name {
			return row.Input
		}
	}
	t.Fatalf("missing fixture case %s", name)
	return nil
}
func taggingClient(c cloudClients, region, key, secret string) *resourcegroupstaggingapi.Client {
	return resourcegroupstaggingapi.New(resourcegroupstaggingapi.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}
func taggingMappings(rows []tagtypes.ResourceTagMapping) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, row := range rows {
		tags := map[string]string{}
		for _, tag := range row.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		out[aws.ToString(row.ResourceARN)] = tags
	}
	return out
}

func TestResourceGroupsTaggingNativeOwners(t *testing.T) {
	var fixture taggingFixture
	awsReadFixture(t, "resourcegroupstaggingapi/controls.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Identity.Account, Clock: source})
			ec := ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			parameters := ssm.New(ssm.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			var createKey ec2.CreateKeyPairInput
			if err := json.Unmarshal(fixture.input(t, "create-key-pair"), &createKey); err != nil {
				t.Fatal(err)
			}
			pair, err := ec.CreateKeyPair(t.Context(), &createKey)
			if err != nil {
				t.Fatal(err)
			}
			var createQueue sqs.CreateQueueInput
			if err := json.Unmarshal(fixture.input(t, "create-queue"), &createQueue); err != nil {
				t.Fatal(err)
			}
			queue, err := clients.sqs("test", "test", "").CreateQueue(t.Context(), &createQueue)
			if err != nil {
				t.Fatal(err)
			}
			for _, label := range []string{"create-tagged", "create-never-tagged"} {
				var input ssm.PutParameterInput
				if err := json.Unmarshal(fixture.input(t, label), &input); err != nil {
					t.Fatal(err)
				}
				if _, err := parameters.PutParameter(t.Context(), &input); err != nil {
					t.Fatal(err)
				}
			}
			keyARN := "arn:aws:ec2:us-east-1:" + fixture.Identity.Account + ":key-pair/" + aws.ToString(pair.KeyPairId)
			replacements := strings.NewReplacer(fixture.Owned.ARNs[0], keyARN, fixture.Owned.QueueURL, aws.ToString(queue.QueueUrl))
			arnList := []string{keyARN, fixture.Owned.ARNs[1], fixture.Owned.ARNs[2]}
			tags := taggingClient(clients, "us-east-1", "test", "test")
			for _, row := range fixture.Observations {
				switch row.Case {
				case "explicit-including-never-tagged", "arn-list-pagination-conflict", "arn-list-tag-filter-conflict", "arn-list-type-filter-conflict", "exclude-without-details", "mixed-native-mutations", "reserved-tag":
				default:
					continue
				}
				out, err := awstest.CallSDK(t.Context(), tags, row.Operation, json.RawMessage(replacements.Replace(string(row.Input))))
				if row.Code != "Success" {
					assertAPIError(t, err, row.Code)
					continue
				}
				if err != nil {
					t.Fatalf("%s: %v", row.Case, err)
				}
				switch actual := out.(type) {
				case *resourcegroupstaggingapi.GetResourcesOutput:
					var expected resourcegroupstaggingapi.GetResourcesOutput
					if err := json.Unmarshal([]byte(replacements.Replace(string(row.Output))), &expected); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(taggingMappings(actual.ResourceTagMappingList), taggingMappings(expected.ResourceTagMappingList)) {
						t.Fatalf("%s mappings got %v want %v", row.Case, taggingMappings(actual.ResourceTagMappingList), taggingMappings(expected.ResourceTagMappingList))
					}
				case *resourcegroupstaggingapi.TagResourcesOutput:
					var expected resourcegroupstaggingapi.TagResourcesOutput
					if err := json.Unmarshal(row.Output, &expected); err != nil {
						t.Fatal(err)
					}
					if len(actual.FailedResourcesMap) != len(expected.FailedResourcesMap) {
						t.Fatalf("mixed success got %+v want %+v", actual.FailedResourcesMap, expected.FailedResourcesMap)
					}
					for arn, want := range expected.FailedResourcesMap {
						got, ok := actual.FailedResourcesMap[arn]
						if !ok || got.ErrorCode != want.ErrorCode || got.StatusCode != want.StatusCode {
							t.Fatalf("mixed failure %s got %+v want %+v", arn, got, want)
						}
					}
				}
			}
			pairs, err := ec.DescribeKeyPairs(t.Context(), &ec2.DescribeKeyPairsInput{KeyPairIds: []string{aws.ToString(pair.KeyPairId)}})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(pairs.KeyPairs[0].Tags, func(tag ec2types.Tag) bool {
				return aws.ToString(tag.Key) == "owner-roundtrip" && aws.ToString(tag.Value) == "updated"
			}) {
				t.Fatal("EC2 owner did not observe TagResources mutation")
			}
			queueTags, err := clients.sqs("test", "test", "").ListQueueTags(t.Context(), &sqs.ListQueueTagsInput{QueueUrl: queue.QueueUrl})
			if err != nil || queueTags.Tags["owner-roundtrip"] != "updated" {
				t.Fatalf("SQS owner tags %+v %v", queueTags, err)
			}
			parameterTags, err := parameters.ListTagsForResource(t.Context(), &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingParameter, ResourceId: aws.String("/" + fixture.Owned.Name)})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(parameterTags.TagList, func(tag ssmtypes.Tag) bool {
				return aws.ToString(tag.Key) == "owner-roundtrip" && aws.ToString(tag.Value) == "updated"
			}) {
				t.Fatal("SSM owner did not observe TagResources mutation")
			}

			query := &resourcegroupstaggingapi.GetResourcesInput{ResourcesPerPage: aws.Int32(1), TagFilters: []tagtypes.TagFilter{{Key: aws.String("stackd-probe"), Values: []string{fixture.Owned.Name}}, {Key: aws.String("owner-roundtrip"), Values: []string{"updated", "alternative"}}}}
			first, err := tags.GetResources(t.Context(), query)
			if err != nil {
				t.Fatal(err)
			}
			if len(first.ResourceTagMappingList) != 1 || aws.ToString(first.PaginationToken) == "" {
				t.Fatalf("first page %+v", first)
			}
			seen := []string{aws.ToString(first.ResourceTagMappingList[0].ResourceARN)}
			query.PaginationToken = first.PaginationToken
			for aws.ToString(query.PaginationToken) != "" {
				page, err := tags.GetResources(t.Context(), query)
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range page.ResourceTagMappingList {
					seen = append(seen, aws.ToString(r.ResourceARN))
				}
				query.PaginationToken = page.PaginationToken
			}
			slices.Sort(seen)
			slices.Sort(arnList)
			if !slices.Equal(seen, arnList) {
				t.Fatalf("pagination got %v want %v", seen, arnList)
			}
			query.PaginationToken = first.PaginationToken
			query.TagFilters[0].Values = []string{"changed"}
			_, err = tags.GetResources(t.Context(), query)
			assertAPIError(t, err, "InvalidParameterException")
			_, err = taggingClient(clients, "us-west-2", "test", "test").GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{PaginationToken: first.PaginationToken})
			assertAPIError(t, err, "InvalidParameterException")
			for _, isolated := range []*resourcegroupstaggingapi.Client{taggingClient(clients, "us-west-2", "test", "test"), taggingClient(clients, "us-east-1", "222222222222", "test")} {
				result, err := isolated.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: arnList})
				if err != nil || len(result.ResourceTagMappingList) != 0 {
					t.Fatalf("scope isolation %+v %v", result, err)
				}
			}
			source.Advance(15 * time.Minute)
			query.TagFilters[0].Values = []string{fixture.Owned.Name}
			_, err = tags.GetResources(t.Context(), query)
			assertAPIError(t, err, "PaginationTokenExpiredException")

			var remove ssm.RemoveTagsFromResourceInput
			if err := json.Unmarshal(fixture.input(t, "native-remove-last-tags"), &remove); err != nil {
				t.Fatal(err)
			}
			if _, err := parameters.RemoveTagsFromResource(t.Context(), &remove); err != nil {
				t.Fatal(err)
			}
			// No inventory read intervenes between last native untag and durable reopen.
			clients = reopen()
			tags = taggingClient(clients, "us-east-1", "test", "test")
			out, err := tags.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: []string{fixture.Owned.ARNs[2], fixture.Owned.NeverARN}, IncludeComplianceDetails: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			if got := taggingMappings(out.ResourceTagMappingList); !reflect.DeepEqual(got, map[string]map[string]string{fixture.Owned.ARNs[2]: {}}) {
				t.Fatalf("previously/never tagged after reopen %+v", got)
			}
			if !aws.ToBool(out.ResourceTagMappingList[0].ComplianceDetails.ComplianceStatus) {
				t.Fatal("no effective policy should not mark existing empty tags noncompliant")
			}
			keys, err := tags.GetTagKeys(t.Context(), &resourcegroupstaggingapi.GetTagKeysInput{})
			if err != nil || !slices.Equal(keys.TagKeys, []string{"owner-roundtrip", "stackd-probe"}) {
				t.Fatalf("current tag keys %+v %v", keys, err)
			}
			values, err := tags.GetTagValues(t.Context(), &resourcegroupstaggingapi.GetTagValuesInput{Key: aws.String("stackd-probe")})
			if err != nil || !slices.Equal(values.TagValues, []string{fixture.Owned.Name}) {
				t.Fatalf("current tag values %+v %v", values, err)
			}
			parameters = ssm.New(ssm.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			if _, err := parameters.DeleteParameter(t.Context(), &ssm.DeleteParameterInput{Name: aws.String("/" + fixture.Owned.Name)}); err != nil {
				t.Fatal(err)
			}
			if _, err := parameters.PutParameter(t.Context(), &ssm.PutParameterInput{Name: aws.String("/" + fixture.Owned.Name), Type: ssmtypes.ParameterTypeString, Value: aws.String("new incarnation")}); err != nil {
				t.Fatal(err)
			}
			out, err = tags.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: []string{fixture.Owned.ARNs[2]}})
			if err != nil || len(out.ResourceTagMappingList) != 0 {
				t.Fatalf("deleted membership leaked to recreated untagged parameter %+v %v", out, err)
			}
		})
	}
}

func TestResourceGroupsTaggingCurrentAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{})
			queue, err := clients.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("tag-authority"), Tags: map[string]string{"source": "native"}})
			if err != nil {
				t.Fatal(err)
			}
			arn := "arn:aws:sqs:us-east-1:000000000000:tag-authority"
			_, key, secret := clients.user(t, "test", "tagger")
			root := clients.iam("test", "test", "")
			putUserPolicy(t, root, "tagger", `{"Statement":{"Effect":"Allow","Action":"tag:*","Resource":"*"}}`)
			caller := taggingClient(clients, "us-east-1", key, secret)
			listed, err := caller.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: []string{arn}})
			if err != nil || len(listed.ResourceTagMappingList) != 1 {
				t.Fatalf("tag:GetResources must not require sqs list authority %+v %v", listed, err)
			}
			request := &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{arn}, Tags: map[string]string{"caller": "allowed"}}
			denied, err := caller.TagResources(t.Context(), request)
			if err != nil || len(denied.FailedResourcesMap) != 1 || !strings.Contains(string(denied.FailedResourcesMap[arn].ErrorCode), "AccessDenied") {
				t.Fatalf("dependent native denial %+v %v", denied, err)
			}
			putUserPolicy(t, root, "tagger", `{"Statement":{"Effect":"Allow","Action":["tag:*","sqs:TagQueue","sqs:UntagQueue"],"Resource":"*"}}`)
			allowed, err := caller.TagResources(t.Context(), request)
			if err != nil || len(allowed.FailedResourcesMap) != 0 {
				t.Fatalf("native authority granted %+v %v", allowed, err)
			}
			putUserPolicy(t, root, "tagger", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"sqs:TagQueue","Resource":"*"}]}`)
			clients = reopen()
			caller = taggingClient(clients, "us-east-1", key, secret)
			request.Tags["caller"] = "forbidden"
			denied, err = caller.TagResources(t.Context(), request)
			if err != nil || len(denied.FailedResourcesMap) != 1 {
				t.Fatalf("current native deny after reopen %+v %v", denied, err)
			}
			current, err := clients.sqs("test", "test", "").ListQueueTags(t.Context(), &sqs.ListQueueTagsInput{QueueUrl: queue.QueueUrl})
			if err != nil || current.Tags["caller"] != "allowed" {
				t.Fatalf("denied mutation changed native state %+v %v", current, err)
			}
			putUserPolicy(t, clients.iam("test", "test", ""), "tagger", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"tag:GetResources","Resource":"*"}]}`)
			_, err = caller.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{})
			assertAPIError(t, err, "AccessDenied")
		})
	}
}

func TestResourceGroupsTaggingNativeAdmission(t *testing.T) {
	var fixture taggingFixture
	awsReadFixture(t, "resourcegroupstaggingapi/boundaries.json", &fixture)
	clients := newCloudClients(t)
	tags := taggingClient(clients, "us-east-1", "test", "test")
	for _, row := range fixture.Observations {
		if strings.Contains(row.Case, "governance") {
			continue
		}
		t.Run(row.Case, func(t *testing.T) {
			out, err := awstest.CallSDK(t.Context(), tags, row.Operation, row.Input)
			if row.Code != "Success" {
				assertAPIError(t, err, row.Code)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := out.(*resourcegroupstaggingapi.GetResourcesOutput); ok && len(got.ResourceTagMappingList) != 0 {
				t.Fatalf("absent/unknown resources returned %+v", got)
			}
		})
	}
}

func TestResourceGroupsTaggingGlobalDashboardAndKMSHistory(t *testing.T) {
	var fixture struct {
		Name, ARN    string
		Observations []struct {
			Case, Code string
			Output     json.RawMessage
		}
	}
	awsReadFixture(t, "resourcegroupstaggingapi/dashboard.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000"})
			cloudwatchClient := cloudwatch.New(cloudwatch.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			_, err := cloudwatchClient.PutDashboard(t.Context(), &cloudwatch.PutDashboardInput{DashboardName: aws.String(fixture.Name), DashboardBody: aws.String(`{"widgets":[]}`)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = cloudwatchClient.TagResource(t.Context(), &cloudwatch.TagResourceInput{ResourceARN: aws.String(fixture.ARN), Tags: []cloudwatchtypes.Tag{{Key: aws.String("stackd-tagging-dashboard"), Value: aws.String(fixture.Name)}}})
			if err != nil {
				t.Fatal(err)
			}
			tags := taggingClient(clients, "us-east-1", "test", "test")
			got, err := tags.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: []string{fixture.ARN}})
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range fixture.Observations {
				if row.Case == "direct-discovery" {
					var expected resourcegroupstaggingapi.GetResourcesOutput
					if err := json.Unmarshal(row.Output, &expected); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(taggingMappings(got.ResourceTagMappingList), taggingMappings(expected.ResourceTagMappingList)) {
						t.Fatalf("dashboard discovery %+v", got)
					}
				}
			}
			_, err = tags.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{fixture.ARN}, Tags: map[string]string{"roundtrip": "rgta"}})
			assertAPIError(t, err, "InvalidParameterException")
			_, err = cloudwatchClient.UntagResource(t.Context(), &cloudwatch.UntagResourceInput{ResourceARN: aws.String(fixture.ARN), TagKeys: []string{"stackd-tagging-dashboard"}})
			if err != nil {
				t.Fatal(err)
			}
			keys := kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			key, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{Tags: []kmstypes.Tag{{TagKey: aws.String("history"), TagValue: aws.String("created-natively")}}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = keys.UntagResource(t.Context(), &kms.UntagResourceInput{KeyId: key.KeyMetadata.KeyId, TagKeys: []string{"history"}})
			if err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			// Global dashboard history must not fragment by endpoint Region. The KMS
			// owner must publish its membership only after flushing native tag writes.
			global, err := taggingClient(clients, "us-west-2", "test", "test").GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: []string{fixture.ARN}})
			if err != nil || !reflect.DeepEqual(taggingMappings(global.ResourceTagMappingList), map[string]map[string]string{fixture.ARN: {}}) {
				t.Fatalf("global dashboard history %+v %v", global, err)
			}
			retained, err := taggingClient(clients, "us-east-1", "test", "test").GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: []string{aws.ToString(key.KeyMetadata.Arn)}})
			if err != nil || !reflect.DeepEqual(taggingMappings(retained.ResourceTagMappingList), map[string]map[string]string{aws.ToString(key.KeyMetadata.Arn): {}}) {
				t.Fatalf("native KMS create/untag history %+v %v", retained, err)
			}
		})
	}
}
