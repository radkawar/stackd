package sqs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go"
	"stackd/clock"
	"stackd/internal/awsctx"
)

var credentialScope = regexp.MustCompile(`Credential=([^/]+)/[^/]+/([^/]+)/`)

func newClock() *clock.Manual {
	return clock.NewManual(time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
}
func advance(t *testing.T, c *clock.Manual, d time.Duration) {
	t.Helper()
	if err := c.Advance(d); err != nil {
		t.Fatal(err)
	}
}
func testServer(t *testing.T, s *Service) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := credentialScope.FindStringSubmatch(r.Header.Get("Authorization"))
		if len(parts) != 3 {
			t.Error("SDK request was not signed")
			http.Error(w, "missing signature", 400)
			return
		}
		account, region := parts[1], parts[2]
		partition := "aws"
		if strings.HasPrefix(region, "cn-") {
			partition = "aws-cn"
		}
		if strings.HasPrefix(region, "us-gov-") {
			partition = "aws-us-gov"
		}
		scope := awsctx.Metadata{AccountID: account, Region: region, Partition: partition, PrincipalARN: "arn:" + partition + ":iam::" + account + ":root", PrincipalID: account, RequestID: "sdk-test-request"}
		s.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), scope)))
	}))
	t.Cleanup(func() { _ = s.Close(); server.Close() })
	return server
}
func testClient(server *httptest.Server, account, region string) *sdk.Client {
	return sdk.New(sdk.Options{Region: region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
}
func fixture(t *testing.T) (*Service, *sdk.Client, *clock.Manual, *httptest.Server) {
	t.Helper()
	clock := newClock()
	s := NewWithConfig(Config{Clock: clock})
	server := testServer(t, s)
	return s, testClient(server, "111111111111", "us-east-1"), clock, server
}
func create(t *testing.T, c *sdk.Client, name string, attrs map[string]string) string {
	t.Helper()
	out, err := c.CreateQueue(context.Background(), &sdk.CreateQueueInput{QueueName: aws.String(name), Attributes: attrs})
	if err != nil {
		t.Fatal(err)
	}
	return aws.ToString(out.QueueUrl)
}
func send(t *testing.T, c *sdk.Client, url, body string) *sdk.SendMessageOutput {
	t.Helper()
	out, err := c.SendMessage(context.Background(), &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String(body)})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func receive(t *testing.T, c *sdk.Client, url string, max int32) []types.Message {
	t.Helper()
	out, err := c.ReceiveMessage(context.Background(), &sdk.ReceiveMessageInput{QueueUrl: aws.String(url), MaxNumberOfMessages: max, MessageAttributeNames: []string{"All"}, MessageSystemAttributeNames: []types.MessageSystemAttributeName{types.MessageSystemAttributeNameAll}})
	if err != nil {
		t.Fatal(err)
	}
	return out.Messages
}
func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	var api smithy.APIError
	if !errors.As(err, &api) || api.ErrorCode() != want {
		t.Fatalf("error=%v, want code %s", err, want)
	}
}
func attributes(t *testing.T, c *sdk.Client, url string) map[string]string {
	t.Helper()
	out, err := c.GetQueueAttributes(context.Background(), &sdk.GetQueueAttributesInput{QueueUrl: aws.String(url), AttributeNames: []types.QueueAttributeName{types.QueueAttributeNameAll}})
	if err != nil {
		t.Fatal(err)
	}
	return out.Attributes
}

func TestQueueLifecycleAndScope(t *testing.T) {
	_, client, clock, server := fixture(t)
	ctx := context.Background()
	url := create(t, client, "jobs", map[string]string{"VisibilityTimeout": "5"})
	if url != server.URL+"/111111111111/jobs" {
		t.Fatalf("local URL=%q", url)
	}
	if got := create(t, client, "jobs", nil); got != url {
		t.Fatalf("idempotent URL=%q", got)
	}
	_, err := client.CreateQueue(ctx, &sdk.CreateQueueInput{QueueName: aws.String("jobs"), Attributes: map[string]string{"VisibilityTimeout": "9"}})
	requireCode(t, err, "QueueAlreadyExists")
	attrs := attributes(t, client, url)
	if attrs["VisibilityTimeout"] != "5" || attrs["MaximumMessageSize"] != "1048576" || attrs["SqsManagedSseEnabled"] != "true" {
		t.Fatalf("defaults=%v", attrs)
	}
	_, err = client.SetQueueAttributes(ctx, &sdk.SetQueueAttributesInput{QueueUrl: aws.String(url), Attributes: map[string]string{"VisibilityTimeout": "8", "MaximumMessageSize": "4"}})
	requireCode(t, err, "InvalidAttributeValue")
	if got := attributes(t, client, url)["VisibilityTimeout"]; got != "5" {
		t.Fatalf("failed update changed visibility=%s", got)
	}
	_, err = client.TagQueue(ctx, &sdk.TagQueueInput{QueueUrl: aws.String(url), Tags: map[string]string{"env": "test", "team": "core"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.UntagQueue(ctx, &sdk.UntagQueueInput{QueueUrl: aws.String(url), TagKeys: []string{"team", "absent"}})
	if err != nil {
		t.Fatal(err)
	}
	tags, err := client.ListQueueTags(ctx, &sdk.ListQueueTagsInput{QueueUrl: aws.String(url)})
	if err != nil || len(tags.Tags) != 1 || tags.Tags["env"] != "test" {
		t.Fatalf("tags=%v err=%v", tags, err)
	}
	for _, c := range []*sdk.Client{testClient(server, "222222222222", "us-east-1"), testClient(server, "111111111111", "us-west-2"), testClient(server, "111111111111", "cn-north-1")} {
		listing, err := c.ListQueues(ctx, &sdk.ListQueuesInput{})
		if err != nil || len(listing.QueueUrls) != 0 {
			t.Fatalf("scope leaked: %v %v", listing, err)
		}
		_, err = c.ReceiveMessage(ctx, &sdk.ReceiveMessageInput{QueueUrl: aws.String(url)})
		if err == nil {
			t.Fatal("cross-scope queue read succeeded")
		}
	}
	_, err = client.DeleteQueue(ctx, &sdk.DeleteQueueInput{QueueUrl: aws.String(url)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetQueueUrl(ctx, &sdk.GetQueueUrlInput{QueueName: aws.String("jobs")})
	requireCode(t, err, "AWS.SimpleQueueService.NonExistentQueue")
	_, err = client.CreateQueue(ctx, &sdk.CreateQueueInput{QueueName: aws.String("jobs")})
	requireCode(t, err, "AWS.SimpleQueueService.QueueDeletedRecently")
	advance(t, clock, time.Minute)
	create(t, client, "jobs", nil)
}
func TestQueuePaginationBindsScopeAndFilter(t *testing.T) {
	_, client, _, server := fixture(t)
	ctx := context.Background()
	for _, name := range []string{"p-c", "p-a", "p-b", "other"} {
		create(t, client, name, nil)
	}
	first, err := client.ListQueues(ctx, &sdk.ListQueuesInput{QueueNamePrefix: aws.String("p-"), MaxResults: aws.Int32(2)})
	if err != nil || len(first.QueueUrls) != 2 || first.NextToken == nil {
		t.Fatalf("page1=%v %v", first, err)
	}
	second, err := client.ListQueues(ctx, &sdk.ListQueuesInput{QueueNamePrefix: aws.String("p-"), MaxResults: aws.Int32(2), NextToken: first.NextToken})
	if err != nil || len(second.QueueUrls) != 1 || second.NextToken != nil || !strings.HasSuffix(second.QueueUrls[0], "p-c") {
		t.Fatalf("page2=%v %v", second, err)
	}
	_, err = client.ListQueues(ctx, &sdk.ListQueuesInput{MaxResults: aws.Int32(2), NextToken: first.NextToken})
	requireCode(t, err, "InvalidParameterValue")
	_, err = testClient(server, "222222222222", "us-east-1").ListQueues(ctx, &sdk.ListQueuesInput{QueueNamePrefix: aws.String("p-"), MaxResults: aws.Int32(2), NextToken: first.NextToken})
	requireCode(t, err, "InvalidParameterValue")
}
