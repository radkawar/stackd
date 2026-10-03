package sqs

import (
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func sendTenant(t *testing.T, c *sdk.Client, url, group string, count int) {
	t.Helper()
	for offset := 0; offset < count; offset += 10 {
		var entries []types.SendMessageBatchRequestEntry
		for i := offset; i < min(offset+10, count); i++ {
			entry := types.SendMessageBatchRequestEntry{Id: aws.String(strconv.Itoa(i)), MessageBody: aws.String(group + "-" + strconv.Itoa(i))}
			if group != "" {
				entry.MessageGroupId = aws.String(group)
			}
			entries = append(entries, entry)
		}
		out, err := c.SendMessageBatch(t.Context(), &sdk.SendMessageBatchInput{QueueUrl: aws.String(url), Entries: entries})
		if err != nil || len(out.Successful) != len(entries) || len(out.Failed) != 0 {
			t.Fatalf("send tenant: %v %v", out, err)
		}
	}
}

func holdTenant(t *testing.T, c *sdk.Client, url, group string, count int) []types.Message {
	t.Helper()
	var held []types.Message
	for len(held) < count {
		want := min(10, count-len(held))
		got := receive(t, c, url, int32(want))
		if len(got) != want {
			t.Fatalf("received %d, want %d", len(got), want)
		}
		for _, m := range got {
			if m.Attributes["MessageGroupId"] != group {
				t.Fatalf("received %s in group %q, want %q", aws.ToString(m.Body), m.Attributes["MessageGroupId"], group)
			}
		}
		held = append(held, got...)
	}
	return held
}

func deleteFairMessages(t *testing.T, c *sdk.Client, url string, messages []types.Message) {
	t.Helper()
	for offset := 0; offset < len(messages); offset += 10 {
		var entries []types.DeleteMessageBatchRequestEntry
		for i := offset; i < min(offset+10, len(messages)); i++ {
			entries = append(entries, types.DeleteMessageBatchRequestEntry{Id: aws.String(strconv.Itoa(i)), ReceiptHandle: messages[i].ReceiptHandle})
		}
		out, err := c.DeleteMessageBatch(t.Context(), &sdk.DeleteMessageBatchInput{QueueUrl: aws.String(url), Entries: entries})
		if err != nil || len(out.Successful) != len(entries) || len(out.Failed) != 0 {
			t.Fatalf("delete tenant messages: %v %v", out, err)
		}
	}
}

func TestFairQueuePrioritizesQuietAndDistinctUngroupedTenants(t *testing.T) {
	_, c, _, _ := fixture(t)
	url := create(t, c, "fair", nil)
	sendTenant(t, c, url, "noisy", 120)
	holdTenant(t, c, url, "noisy", 60)
	sendTenant(t, c, url, "quiet", 20)
	sendTenant(t, c, url, "", 40)
	holdTenant(t, c, url, "quiet", 20)
	// Forty ungrouped deliveries must not become a single noisy tenant.
	holdTenant(t, c, url, "", 40)
	sendTenant(t, c, url, "", 1)
	holdTenant(t, c, url, "", 1)
	// Same-group in-flight work neither serializes standard delivery nor caps
	// throughput when quiet work is exhausted.
	holdTenant(t, c, url, "noisy", 60)
}

func TestFairQueueBalancesNoisyTenantsAtEachReceive(t *testing.T) {
	_, c, _, _ := fixture(t)
	url := create(t, c, "balanced", nil)
	sendTenant(t, c, url, "a", 40)
	holdTenant(t, c, url, "a", 40)
	sendTenant(t, c, url, "b", 30)
	holdTenant(t, c, url, "b", 30)
	sendTenant(t, c, url, "a", 10)
	sendTenant(t, c, url, "b", 10)
	holdTenant(t, c, url, "b", 10)
	holdTenant(t, c, url, "a", 10)
}

func TestFairQueueDoesNotCountBacklogAsConcurrency(t *testing.T) {
	_, c, _, _ := fixture(t)
	url := create(t, c, "backlog", nil)
	sendTenant(t, c, url, "a", 100)
	sendTenant(t, c, url, "b", 1)
	holdTenant(t, c, url, "a", 30)
	holdTenant(t, c, url, "b", 1)
}

func TestFairQueueConcurrencyShareIncludesUngroupedDeliveries(t *testing.T) {
	_, c, _, _ := fixture(t)
	url := create(t, c, "share", nil)
	sendTenant(t, c, url, "", 270)
	holdTenant(t, c, url, "", 270)
	sendTenant(t, c, url, "a", 40)
	holdTenant(t, c, url, "a", 30)
	sendTenant(t, c, url, "b", 1)
	// Exactly 30 of 300 is not more than 10%. The next A delivery crosses
	// the local concurrency threshold and makes B the preferred tenant.
	holdTenant(t, c, url, "a", 1)
	holdTenant(t, c, url, "b", 1)
}

func TestFairQueueFailedReceiveDoesNotCommitNoise(t *testing.T) {
	backend := &failingRepository{Repository: NewMemoryRepository(nil)}
	s := NewWithConfig(Config{Repository: backend, Clock: newClock()})
	c := testClient(testServer(t, s), "111111111111", "us-east-1")
	url := create(t, c, "atomic-fair", nil)
	sendTenant(t, c, url, "a", 32)
	holdTenant(t, c, url, "a", 29)
	backend.fail = true
	_, err := c.ReceiveMessage(t.Context(), &sdk.ReceiveMessageInput{QueueUrl: aws.String(url)})
	requireCode(t, err, "InternalError")
	// Inspect committed state before any retry can recompute classification.
	if err := backend.View(t.Context(), func(r Reader) error {
		q, err := r.Queue(QueueKey{Partition: "aws", Account: "111111111111", Region: "us-east-1", Name: "atomic-fair"})
		if err != nil {
			return err
		}
		messages, err := r.Messages(q.ID)
		if err != nil {
			return err
		}
		if len(messages.NoisyGroups) != 0 {
			t.Fatal("failed receive committed a noisy tenant")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	backend.fail = false
	holdTenant(t, c, url, "a", 1)
	sendTenant(t, c, url, "b", 1)
	holdTenant(t, c, url, "b", 1)
}

func TestFairQueueQuietRecoveryUsesDeliveryEndAndRetainedStorage(t *testing.T) {
	for _, ending := range []string{"expiry", "delete", "release", "extend"} {
		t.Run(ending, func(t *testing.T) {
			backend := NewMemoryRepository(nil)
			source := newClock()
			first := NewWithConfig(Config{Repository: backend, Clock: source})
			server := testServer(t, first)
			c := testClient(server, "111111111111", "us-east-1")
			url := create(t, c, "recover", map[string]string{"VisibilityTimeout": "60"})
			sendTenant(t, c, url, "a", 32)
			held := holdTenant(t, c, url, "a", 30)
			start := source.Now()
			advance(t, source, 10*time.Second)
			end := start.Add(time.Minute)
			switch ending {
			case "delete":
				deleteFairMessages(t, c, url, held)
				end = source.Now()
			case "release":
				for _, m := range held {
					_, err := c.ChangeMessageVisibility(t.Context(), &sdk.ChangeMessageVisibilityInput{QueueUrl: aws.String(url), ReceiptHandle: m.ReceiptHandle, VisibilityTimeout: 0})
					if err != nil {
						t.Fatal(err)
					}
				}
				end = source.Now()
			case "extend":
				deleteFairMessages(t, c, url, held[1:])
				_, err := c.ChangeMessageVisibility(t.Context(), &sdk.ChangeMessageVisibilityInput{QueueUrl: aws.String(url), ReceiptHandle: held[0].ReceiptHandle, VisibilityTimeout: 120})
				if err != nil {
					t.Fatal(err)
				}
				end = source.Now().Add(2 * time.Minute)
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			advance(t, source, end.Add(5*time.Minute-time.Second).Sub(source.Now()))
			second := NewWithConfig(Config{Repository: backend, Clock: source})
			server = testServer(t, second)
			c = testClient(server, "111111111111", "us-east-1")
			out, err := c.GetQueueUrl(t.Context(), &sdk.GetQueueUrlInput{QueueName: aws.String("recover")})
			if err != nil {
				t.Fatal(err)
			}
			url = aws.ToString(out.QueueUrl)
			sendTenant(t, c, url, "b", 1)
			holdTenant(t, c, url, "b", 1)
			advance(t, source, time.Second)
			holdTenant(t, c, url, "a", 1)
		})
	}
}

func TestFairQueueDrainedTenantAndPurgeForgetNoise(t *testing.T) {
	for _, purge := range []bool{false, true} {
		t.Run(strconv.FormatBool(purge), func(t *testing.T) {
			_, c, _, _ := fixture(t)
			url := create(t, c, "drain", nil)
			sendTenant(t, c, url, "a", 30)
			held := holdTenant(t, c, url, "a", 30)
			if purge {
				if _, err := c.PurgeQueue(t.Context(), &sdk.PurgeQueueInput{QueueUrl: aws.String(url)}); err != nil {
					t.Fatal(err)
				}
			} else {
				deleteFairMessages(t, c, url, held)
			}
			sendTenant(t, c, url, "a", 1)
			sendTenant(t, c, url, "b", 1)
			holdTenant(t, c, url, "a", 1)
		})
	}
}

func TestFairQueueDoesNotWaitForDelayedQuietWork(t *testing.T) {
	_, c, source, _ := fixture(t)
	url := create(t, c, "delayed-fair", nil)
	sendTenant(t, c, url, "a", 32)
	holdTenant(t, c, url, "a", 30)
	_, err := c.SendMessage(t.Context(), &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String("delayed"), MessageGroupId: aws.String("b"), DelaySeconds: 10})
	if err != nil {
		t.Fatal(err)
	}
	holdTenant(t, c, url, "a", 1)
	advance(t, source, 10*time.Second)
	holdTenant(t, c, url, "b", 1)
}

func TestFairQueueNoiseIsScopedToQueue(t *testing.T) {
	_, c, _, server := fixture(t)
	url := create(t, c, "scope", nil)
	sendTenant(t, c, url, "a", 40)
	holdTenant(t, c, url, "a", 30)
	for _, scope := range []struct{ account, region, name string }{
		{"111111111111", "us-east-1", "other"},
		{"222222222222", "us-east-1", "scope"},
		{"111111111111", "us-west-2", "scope"},
		{"111111111111", "cn-north-1", "scope"},
	} {
		other := testClient(server, scope.account, scope.region)
		otherURL := create(t, other, scope.name, nil)
		sendTenant(t, other, otherURL, "a", 1)
		sendTenant(t, other, otherURL, "b", 1)
		holdTenant(t, other, otherURL, "a", 1)
	}
}
