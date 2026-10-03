package stackd_test

import (
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd/clock"
	"stackd/internal/awstest"
)

type firehoseNativeCall struct {
	Sequence                          int
	Label, Service, Operation, Caller string
	Input                             json.RawMessage
	RequestID                         string
	RequestIDs                        json.RawMessage
	Result                            struct {
		Code   string
		Output json.RawMessage
	}
}

type firehoseNativeFixture struct {
	Account, Region, Prefix string
	StartedAt               time.Time
	Calls                   []firehoseNativeCall
	CloudTrailProjections   []json.RawMessage
}

func (f firehoseNativeFixture) row(t *testing.T, label string) firehoseNativeCall {
	t.Helper()
	for _, row := range f.Calls {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("missing native Firehose observation %q", label)
	return firehoseNativeCall{}
}

func firehoseReplayCall(t *testing.T, client any, row firehoseNativeCall, prepare ...func(any)) any {
	t.Helper()
	out, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input, prepare...)
	if row.Result.Code == "Success" {
		if err != nil {
			t.Fatalf("%s: %v", row.Label, err)
		}
	} else {
		assertAPIError(t, err, row.Result.Code)
	}
	return out
}

func (c cloudClients) firehose(key, secret, token string) *firehose.Client {
	return firehose.New(firehose.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func awaitFirehoseActive(t *testing.T, source *clock.Manual, client *firehose.Client, name string) {
	t.Helper()
	for range 100 {
		out, err := client.DescribeDeliveryStream(t.Context(), &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: &name})
		if err != nil {
			t.Fatal(err)
		}
		if out.DeliveryStreamDescription.DeliveryStreamStatus == "ACTIVE" {
			return
		}
		advanceClock(t, source, time.Second)
	}
	t.Fatalf("delivery stream %q did not become ACTIVE", name)
}

// Read all actual objects; names, ordering, and packing are not native contracts.
func firehoseConsumerObjects(t *testing.T, client *s3.Client, bucket, prefix string) map[string][]byte {
	t.Helper()
	objects := map[string][]byte{}
	pages := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &prefix})
	for pages.HasMorePages() {
		page, err := pages.NextPage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, object := range page.Contents {
			out, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: object.Key})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(out.Body)
			closeErr := out.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			objects[aws.ToString(object.Key)] = body
		}
	}
	return objects
}
