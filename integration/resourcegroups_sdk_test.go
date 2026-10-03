package stackd_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroups"
	rgtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroups/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type resourceGroupsNativeRow struct {
	Case, Operation, Code string
	Input                 json.RawMessage
}

func TestResourceGroupsNativeSelectionAndOwnerTransitions(t *testing.T) {
	var fixture struct {
		Region   string
		Identity struct{ Account string }
		Owned    struct {
			Prefix    string
			Resources []struct {
				ARN  string
				Tags map[string]string
			}
		}
		Observations []resourceGroupsNativeRow
		Selection    []struct {
			Case   string
			Actual []string
		}
		CleanupVerified bool `json:"cleanup_verified"`
	}
	awsReadFixture(t, "resourcegroups/native.json", &fixture)
	if !fixture.CleanupVerified {
		t.Fatal("native owned-resource cleanup was not verified")
	}
	var boundaries struct{ Observations []resourceGroupsNativeRow }
	awsReadFixture(t, "resourcegroups/native-query-boundaries.json", &boundaries)
	for _, row := range boundaries.Observations {
		switch row.Case {
		case "duplicate-resource-types", "lower-camel-query-fields", "mixed-query-fields":
			fixture.Observations = append(fixture.Observations, row)
		}
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Identity.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			config := func() aws.Config {
				return aws.Config{Region: fixture.Region, Credentials: credentials.NewStaticCredentialsProvider(fixture.Identity.Account, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1}
			}
			groups := func() *resourcegroups.Client {
				return resourcegroups.NewFromConfig(config(), func(o *resourcegroups.Options) { o.BaseEndpoint = new(c.server.URL) })
			}
			buckets := func() *s3.Client {
				return s3.NewFromConfig(config(), func(o *s3.Options) { o.BaseEndpoint = new(c.server.URL); o.UsePathStyle = true })
			}
			queues := func() *sqs.Client {
				return sqs.NewFromConfig(config(), func(o *sqs.Options) { o.BaseEndpoint = new(c.server.URL) })
			}
			known := map[string]bool{}
			urls := map[string]string{}
			for _, r := range fixture.Owned.Resources {
				known[r.ARN] = true
				if strings.HasPrefix(r.ARN, "arn:aws:s3:::") {
					name := strings.TrimPrefix(r.ARN, "arn:aws:s3:::")
					if _, err := buckets().CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: new(name)}); err != nil {
						t.Fatal(err)
					}
					tags := []s3types.Tag{}
					for k, v := range r.Tags {
						tags = append(tags, s3types.Tag{Key: new(k), Value: new(v)})
					}
					if _, err := buckets().PutBucketTagging(t.Context(), &s3.PutBucketTaggingInput{Bucket: new(name), Tagging: &s3types.Tagging{TagSet: tags}}); err != nil {
						t.Fatal(err)
					}
				} else {
					parts := strings.Split(r.ARN, ":")
					name := parts[len(parts)-1]
					out, err := queues().CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: new(name), Tags: r.Tags})
					if err != nil {
						t.Fatal(err)
					}
					urls[r.ARN] = aws.ToString(out.QueueUrl)
				}
			}
			var create resourcegroups.CreateGroupInput
			for _, row := range fixture.Observations {
				if row.Operation == "create_group" {
					var in resourcegroups.CreateGroupInput
					if err := json.Unmarshal(row.Input, &in); err != nil {
						t.Fatal(err)
					}
					if aws.ToString(in.Name) == fixture.Owned.Prefix+"-tag-query" {
						create = in
						break
					}
				}
			}
			made, err := groups().CreateGroup(t.Context(), &create)
			if err != nil {
				t.Fatal(err)
			}
			arn := aws.ToString(made.Group.GroupArn)
			known[arn] = true
			for _, row := range fixture.Observations {
				if row.Case == "index-readiness-0" {
					break
				}
				if row.Code == "Success" && (row.Operation == "tag" || row.Operation == "untag") {
					if _, err := awstest.CallSDK(t.Context(), groups(), row.Operation, row.Input); err != nil {
						t.Fatal(err)
					}
				}
			}
			t.Run("group-definition-filter", func(t *testing.T) {
				out, err := groups().ListGroups(t.Context(), &resourcegroups.ListGroupsInput{Filters: []rgtypes.GroupFilter{{Name: "resource-type", Values: []string{"AWS::SQS::Queue"}}}})
				if err != nil {
					t.Fatal(err)
				}
				if len(out.GroupIdentifiers) != 0 {
					t.Fatal("AllSupported definition incorrectly treated as an explicit SQS type filter")
				}
			})
			requests := map[string]resourcegroups.SearchResourcesInput{}
			for _, row := range fixture.Observations {
				if row.Operation == "search_resources" && strings.HasPrefix(row.Case, "selection-") && strings.HasSuffix(row.Case, "-page-0") {
					var in resourcegroups.SearchResourcesInput
					if err := json.Unmarshal(row.Input, &in); err != nil {
						t.Fatal(err)
					}
					requests[strings.TrimSuffix(row.Case, "-page-0")] = in
				}
			}
			search := func(in resourcegroups.SearchResourcesInput) []string {
				t.Helper()
				var arns []string
				for range 100 {
					out, err := groups().SearchResources(t.Context(), &in)
					if err != nil {
						t.Fatal(err)
					}
					for _, r := range out.ResourceIdentifiers {
						arns = append(arns, aws.ToString(r.ResourceArn))
					}
					if out.NextToken == nil {
						slices.Sort(arns)
						return arns
					}
					in.NextToken = out.NextToken
				}
				t.Fatal("pagination did not terminate")
				return nil
			}
			for _, selection := range fixture.Selection {
				t.Run(selection.Case, func(t *testing.T) {
					// Native also created specialized service-linked groups. Those owners are
					// unavailable locally, so compare exactly the real resources admitted here;
					// the ordinary group's native self-selection remains part of the assertion.
					expected := []string{}
					for _, id := range selection.Actual {
						if known[id] {
							expected = append(expected, id)
						}
					}
					slices.Sort(expected)
					if got := search(requests[selection.Case]); !slices.Equal(got, expected) {
						t.Fatalf("native selected %v; local %v", expected, got)
					}
				})
			}
			for _, row := range fixture.Observations {
				if row.Operation == "create_group" && (row.Code == "BadRequestException" || row.Code == "ForbiddenException") {
					_, err := awstest.CallSDK(t.Context(), groups(), "CreateGroup", row.Input)
					var rejected smithy.APIError
					if !errors.As(err, &rejected) || rejected.ErrorCode() != row.Code {
						t.Fatalf("%s native %s local %v", row.Case, row.Code, err)
					}
				}
			}
			ownerRequest := requests["selection-owner"]
			first, err := groups().SearchResources(t.Context(), &ownerRequest)
			if err != nil {
				t.Fatal(err)
			}
			altered := requests["selection-type-s3"]
			altered.NextToken = first.NextToken
			_, err = groups().SearchResources(t.Context(), &altered)
			var invalid *rgtypes.BadRequestException
			if !errors.As(err, &invalid) {
				t.Fatalf("query-bound cursor accepted: %v", err)
			}
			updated := requests["selection-duplicate-key-and"].ResourceQuery
			if _, err := groups().UpdateGroupQuery(t.Context(), &resourcegroups.UpdateGroupQueryInput{Group: new(arn), ResourceQuery: updated}); err != nil {
				t.Fatal(err)
			}
			_, err = groups().UpdateGroupQuery(t.Context(), &resourcegroups.UpdateGroupQueryInput{Group: new(arn), ResourceQuery: &rgtypes.ResourceQuery{Type: rgtypes.QueryTypeTagFilters10, Query: new("{")}})
			if !errors.As(err, &invalid) {
				t.Fatalf("invalid update admitted: %v", err)
			}
			c = reopen()
			query, err := groups().GetGroupQuery(t.Context(), &resourcegroups.GetGroupQueryInput{Group: new(arn)})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(query.GroupQuery.ResourceQuery.Query) != aws.ToString(updated.Query) {
				t.Fatal("failed query update changed retained query")
			}
			// Real owner deletion/recreation must not inherit the prior resource's tags.
			queueARN := fixture.Owned.Resources[2].ARN
			if _, err := queues().DeleteQueue(t.Context(), &sqs.DeleteQueueInput{QueueUrl: new(urls[queueARN])}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 61*time.Second)
			parts := strings.Split(queueARN, ":")
			name := parts[len(parts)-1]
			replacement, err := queues().CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: new(name)})
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(search(ownerRequest), queueARN) {
				t.Fatal("new untagged owner inherited deleted membership")
			}
			if _, err := queues().TagQueue(t.Context(), &sqs.TagQueueInput{QueueUrl: replacement.QueueUrl, Tags: map[string]string{"stackd-rg-probe": fixture.Owned.Prefix}}); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(search(ownerRequest), queueARN) {
				t.Fatal("current owner tag mutation did not change membership")
			}
			if _, err := groups().DeleteGroup(t.Context(), &resourcegroups.DeleteGroupInput{Group: new(arn)}); err != nil {
				t.Fatal(err)
			}
			_, err = groups().GetGroup(t.Context(), &resourcegroups.GetGroupInput{Group: new(arn)})
			var missing *rgtypes.NotFoundException
			if !errors.As(err, &missing) {
				t.Fatalf("deleted group visible: %v", err)
			}
			if slices.Contains(search(ownerRequest), arn) {
				t.Fatal("deleted group remained in owner discovery")
			}
		})
	}
}
