package sqs

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func TestFairQueueNativeGroupDelivery(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/sqs/fairness.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Operation string
			Entries   []types.SendMessageBatchRequestEntry
			Maximum   int32
			Messages  []struct {
				Body       string
				Attributes map[string]string
			}
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	native := make(map[string]map[string]string)
	for _, observation := range capture.Observations {
		for _, m := range observation.Messages {
			native[m.Body] = m.Attributes
		}
	}
	_, c, _, _ := fixture(t)
	url := create(t, c, "native-fairness", map[string]string{"VisibilityTimeout": "600"})
	delivered := make(map[string]bool)
	for _, observation := range capture.Observations {
		switch observation.Operation {
		case "SendMessageBatch":
			out, err := c.SendMessageBatch(t.Context(), &sdk.SendMessageBatchInput{QueueUrl: aws.String(url), Entries: observation.Entries})
			if err != nil || len(out.Failed) != 0 || len(out.Successful) != len(observation.Entries) {
				t.Fatalf("native send sequence: %v %v", out, err)
			}
		case "ReceiveMessage":
			// AWS partitions return different body orders and can return short
			// batches. Compare per-message semantics across the captured run.
			for _, m := range receive(t, c, url, observation.Maximum) {
				body := aws.ToString(m.Body)
				attrs := make(map[string]string)
				for _, key := range []string{"MessageGroupId", "ApproximateReceiveCount", "MessageDeduplicationId", "SequenceNumber"} {
					if value, ok := m.Attributes[key]; ok {
						attrs[key] = value
					}
				}
				if !reflect.DeepEqual(attrs, native[body]) {
					t.Fatalf("body %q: attributes %v, AWS %v", body, attrs, native[body])
				}
				if delivered[body] {
					t.Fatalf("local delivery repeated in-flight body %q", body)
				}
				delivered[body] = true
			}
		default:
			t.Fatalf("unexpected captured operation %q", observation.Operation)
		}
	}
	if len(delivered) != 150 || len(delivered) != len(native) {
		t.Fatalf("local delivered %d, native delivered %d", len(delivered), len(native))
	}
}
