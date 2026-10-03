package sqs

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"stackd/internal/awswire"
)

// The gate pauses one actual dependency call while other requests use the same
// service and repository. It honors cancellation just as a network client must.
type gatedKMS struct {
	testKMS
	operation        string
	armed, paused    atomic.Bool
	entered, release chan struct{}
	released         sync.Once
}

func newGatedKMS(t *testing.T, operation string) *gatedKMS {
	t.Helper()
	k := &gatedKMS{operation: operation, entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(k.unblock)
	return k
}
func (k *gatedKMS) unblock() { k.released.Do(func() { close(k.release) }) }
func (k *gatedKMS) wait(ctx context.Context, operation string) *awswire.Error {
	if k.armed.Load() && operation == k.operation && k.paused.CompareAndSwap(false, true) {
		close(k.entered)
		select {
		case <-k.release:
		case <-ctx.Done():
			return &awswire.Error{Code: "DependencyUnavailable", Message: ctx.Err().Error(), StatusCode: 503}
		}
	}
	return nil
}
func (k *gatedKMS) GenerateDataKey(ctx context.Context, id string, ec map[string]string) ([]byte, []byte, string, *awswire.Error) {
	if err := k.wait(ctx, "generate"); err != nil {
		return nil, nil, "", err
	}
	return k.testKMS.GenerateDataKey(ctx, id, ec)
}
func (k *gatedKMS) Decrypt(ctx context.Context, data []byte, ec map[string]string) ([]byte, string, *awswire.Error) {
	if err := k.wait(ctx, "decrypt"); err != nil {
		return nil, "", err
	}
	return k.testKMS.Decrypt(ctx, data, ec)
}
func awaitKeyPreparation(t *testing.T, k *gatedKMS) {
	t.Helper()
	select {
	case <-k.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("dependency preparation did not begin")
	}
}
func keyRequestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestKeyPreparationReleasesRepositoryAndUsesCurrentConfiguration(t *testing.T) {
	manual := newClock()
	s := NewWithConfig(Config{Clock: manual})
	c := testClient(testServer(t, s), "111111111111", "us-east-1")
	k := newGatedKMS(t, "generate")
	s.kms = k
	encrypted := create(t, c, "encrypted", map[string]string{"KmsMasterKeyId": "key-a"})
	plain := create(t, c, "plain", nil)
	k.armed.Store(true)
	done := make(chan error, 1)
	go func() {
		_, err := c.SendMessage(t.Context(), &sdk.SendMessageInput{QueueUrl: &encrypted, MessageBody: aws.String("prepared")})
		done <- err
	}()
	awaitKeyPreparation(t, k)
	ctx := keyRequestContext(t)
	if err := s.repository.View(ctx, func(r Reader) error {
		q, err := r.Queue(QueueKey{"aws", "111111111111", "us-east-1", "encrypted"})
		if err != nil {
			return err
		}
		messages, err := r.Messages(q.ID)
		if len(messages.Messages) != 0 {
			t.Error("preparation published a provisional message")
		}
		return err
	}); err != nil {
		t.Fatal("KMS held the repository", err)
	}
	if _, err := c.SendMessage(ctx, &sdk.SendMessageInput{QueueUrl: &plain, MessageBody: aws.String("independent")}); err != nil {
		t.Fatal("KMS blocked another queue", err)
	}
	if _, err := c.SetQueueAttributes(ctx, &sdk.SetQueueAttributesInput{QueueUrl: &encrypted, Attributes: map[string]string{"KmsMasterKeyId": "key-b"}}); err != nil {
		t.Fatal("KMS blocked queue configuration", err)
	}
	k.unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		q, err := r.Queue(QueueKey{"aws", "111111111111", "us-east-1", "encrypted"})
		if err != nil {
			return err
		}
		messages, err := r.Messages(q.ID)
		if len(messages.Messages) != 1 || !strings.HasPrefix(string(messages.Messages[0].EncryptedDataKey), "encrypted:key-b:") {
			t.Errorf("stale encryption configuration committed: %v", messages.Messages)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, c, encrypted, 1); len(got) != 1 || aws.ToString(got[0].Body) != "prepared" {
		t.Fatalf("delivery=%v", got)
	}
}

func TestKeyPreparationRechecksPolicyAndQueueIncarnation(t *testing.T) {
	for _, change := range []string{"policy", "replacement"} {
		t.Run(change, func(t *testing.T) {
			manual := newClock()
			s := NewWithConfig(Config{Clock: manual})
			c := testClient(testServer(t, s), "111111111111", "us-east-1")
			k := newGatedKMS(t, "generate")
			s.kms = k
			url := create(t, c, "encrypted", map[string]string{"KmsMasterKeyId": "key"})
			k.armed.Store(true)
			done := make(chan error, 1)
			go func() {
				_, err := c.SendMessage(t.Context(), &sdk.SendMessageInput{QueueUrl: &url, MessageBody: aws.String("stale")})
				done <- err
			}()
			awaitKeyPreparation(t, k)
			ctx := keyRequestContext(t)
			want := "AccessDenied"
			if change == "policy" {
				doc := `{"Statement":{"Effect":"Deny","Principal":"*","Action":"sqs:SendMessage","Resource":"*"}}`
				if _, err := c.SetQueueAttributes(ctx, &sdk.SetQueueAttributesInput{QueueUrl: &url, Attributes: map[string]string{"Policy": doc}}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := c.DeleteQueue(ctx, &sdk.DeleteQueueInput{QueueUrl: &url}); err != nil {
					t.Fatal(err)
				}
				advance(t, manual, time.Minute)
				if _, err := c.CreateQueue(ctx, &sdk.CreateQueueInput{QueueName: aws.String("encrypted"), Attributes: map[string]string{"KmsMasterKeyId": "key"}}); err != nil {
					t.Fatal(err)
				}
				want = "AWS.SimpleQueueService.NonExistentQueue"
			}
			k.unblock()
			requireCode(t, <-done, want)
			if attributes(t, c, url)["ApproximateNumberOfMessages"] != "0" {
				t.Fatal("stale preparation sent a message")
			}
			if change == "policy" {
				if _, err := c.SetQueueAttributes(ctx, &sdk.SetQueueAttributesInput{QueueUrl: &url, Attributes: map[string]string{"Policy": ""}}); err != nil {
					t.Fatal(err)
				}
				send(t, c, url, "fresh")
				k.mu.Lock()
				if k.generated != 2 {
					t.Errorf("denied command published its key cache: %d generations", k.generated)
				}
				k.mu.Unlock()
			}
		})
	}
}

func TestKeyPreparationReselectsMessagesAfterConcurrentReceive(t *testing.T) {
	s := New()
	c := testClient(testServer(t, s), "111111111111", "us-east-1")
	k := newGatedKMS(t, "decrypt")
	s.kms = k
	url := create(t, c, "encrypted", map[string]string{"KmsMasterKeyId": "key", "VisibilityTimeout": "600"})
	send(t, c, url, "claimed elsewhere")
	k.armed.Store(true)
	type result struct {
		out *sdk.ReceiveMessageOutput
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := c.ReceiveMessage(t.Context(), &sdk.ReceiveMessageInput{QueueUrl: &url})
		done <- result{out, err}
	}()
	awaitKeyPreparation(t, k)
	other, err := c.ReceiveMessage(keyRequestContext(t), &sdk.ReceiveMessageInput{QueueUrl: &url})
	if err != nil || len(other.Messages) != 1 {
		t.Fatalf("competing receive=%v %v", other, err)
	}
	k.unblock()
	first := <-done
	if first.err != nil || len(first.out.Messages) != 0 {
		t.Fatalf("stale receive claimed an in-flight message: %v %v", first.out, first.err)
	}
	if _, err := c.DeleteMessage(t.Context(), &sdk.DeleteMessageInput{QueueUrl: &url, ReceiptHandle: other.Messages[0].ReceiptHandle}); err != nil {
		t.Fatal("competing receipt was invalidated", err)
	}
}

func TestKeyPreparationShutdownCancelsAndJoinsAPIDependencies(t *testing.T) {
	for _, operation := range []string{"generate", "decrypt", "ensure"} {
		t.Run(operation, func(t *testing.T) {
			s := New()
			c := testClient(testServer(t, s), "111111111111", "us-east-1")
			k := newGatedKMS(t, operation)
			s.kms = k
			keyID := "key"
			if operation == "ensure" {
				keyID = "alias/aws/sqs"
			}
			url := create(t, c, "encrypted", map[string]string{"KmsMasterKeyId": keyID})
			if operation == "decrypt" {
				send(t, c, url, "held")
			}
			k.armed.Store(true)
			done := make(chan error, 1)
			go func() {
				var err error
				if operation != "decrypt" {
					_, err = c.SendMessage(t.Context(), &sdk.SendMessageInput{QueueUrl: &url, MessageBody: aws.String("held")})
				} else {
					_, err = c.ReceiveMessage(t.Context(), &sdk.ReceiveMessageInput{QueueUrl: &url})
				}
				done <- err
			}()
			awaitKeyPreparation(t, k)
			closed := make(chan error, 1)
			go func() { closed <- s.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close did not cancel and join key preparation")
			}
			requireCode(t, <-done, "ServiceUnavailable")
		})
	}
}

func TestPreparedKeyCacheRequiresSuccessfulMessageCommit(t *testing.T) {
	backend := &failingRepository{Repository: NewMemoryRepository(nil)}
	k := &testKMS{}
	s := NewWithConfig(Config{Repository: backend, KMS: k})
	c := testClient(testServer(t, s), "111111111111", "us-east-1")
	url := create(t, c, "encrypted.fifo", map[string]string{"FifoQueue": "true", "KmsMasterKeyId": "key"})
	in := &sdk.SendMessageInput{QueueUrl: &url, MessageBody: aws.String("atomic"), MessageGroupId: aws.String("group"), MessageDeduplicationId: aws.String("token")}
	backend.fail = true
	if _, err := c.SendMessage(t.Context(), in); err == nil {
		t.Fatal("failed commit succeeded")
	}
	backend.fail = false
	if _, err := c.SendMessage(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	if k.generated != 2 {
		t.Errorf("failed commit cached the prepared key: %d generations", k.generated)
	}
	k.mu.Unlock()
	if got := receive(t, c, url, 10); len(got) != 1 || aws.ToString(got[0].Body) != "atomic" {
		t.Fatalf("commit retry lost or duplicated the message: %v", got)
	}
}

func (k *gatedKMS) EnsureServiceKey(ctx context.Context, service string) (string, *awswire.Error) {
	if err := k.wait(ctx, "ensure"); err != nil {
		return "", err
	}
	return k.testKMS.EnsureServiceKey(ctx, service)
}

func TestDeadLetterPreparationCannotResurrectDeletedSourceMessage(t *testing.T) {
	s := New()
	c := testClient(testServer(t, s), "111111111111", "us-east-1")
	k := newGatedKMS(t, "generate")
	s.kms = k
	source, dead, _ := deadLetterFixture(t, c)
	if _, err := c.SetQueueAttributes(t.Context(), &sdk.SetQueueAttributesInput{QueueUrl: &dead, Attributes: map[string]string{"KmsMasterKeyId": "key"}}); err != nil {
		t.Fatal(err)
	}
	send(t, c, source, "deleted during preparation")
	first := receive(t, c, source, 1)
	k.armed.Store(true)
	done := make(chan error, 1)
	go func() {
		_, err := c.ReceiveMessage(t.Context(), &sdk.ReceiveMessageInput{QueueUrl: &source})
		done <- err
	}()
	awaitKeyPreparation(t, k)
	if _, err := c.DeleteMessage(keyRequestContext(t), &sdk.DeleteMessageInput{QueueUrl: &source, ReceiptHandle: first[0].ReceiptHandle}); err != nil {
		t.Fatal(err)
	}
	k.unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{source, dead} {
		if attributes(t, c, url)["ApproximateNumberOfMessages"] != "0" {
			t.Fatal("preparation resurrected a deleted message")
		}
	}
}

func TestRedriveCancellationCanCommitDuringKeyPreparation(t *testing.T) {
	f := retainedRedrive(t, NewMemoryRepository(nil), 1, 1)
	k := newGatedKMS(t, "generate")
	f.s.kms = k
	if _, err := f.c.SetQueueAttributes(t.Context(), &sdk.SetQueueAttributesInput{QueueUrl: &f.destination, Attributes: map[string]string{"KmsMasterKeyId": "key"}}); err != nil {
		t.Fatal(err)
	}
	k.armed.Store(true)
	advance(t, f.clock, time.Second)
	done := make(chan error, 1)
	go func() { _, err := f.s.jobs.RunDue(t.Context(), 10); done <- err }()
	awaitKeyPreparation(t, k)
	if _, err := f.c.CancelMessageMoveTask(keyRequestContext(t), &sdk.CancelMessageMoveTaskInput{TaskHandle: &f.handle}); err != nil {
		t.Fatal("key preparation blocked cancellation", err)
	}
	k.unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	status := f.status(t)
	if aws.ToString(status.Status) != moveCancelled || status.ApproximateNumberOfMessagesMoved != 0 {
		t.Fatalf("canceled move used stale prepared work: %v", status)
	}
	if attributes(t, f.c, f.dlq)["ApproximateNumberOfMessages"] != "1" || attributes(t, f.c, f.destination)["ApproximateNumberOfMessages"] != "0" {
		t.Fatal("cancellation lost or delivered the source message")
	}
}

func TestKeyPreparationPreservesPerEntryBatchErrors(t *testing.T) {
	k := &testKMS{disabled: true}
	s := NewWithConfig(Config{KMS: k})
	c := testClient(testServer(t, s), "111111111111", "us-east-1")
	url := create(t, c, "encrypted", map[string]string{"KmsMasterKeyId": "key"})
	out, err := c.SendMessageBatch(keyRequestContext(t), &sdk.SendMessageBatchInput{QueueUrl: &url, Entries: []types.SendMessageBatchRequestEntry{
		{Id: aws.String("kms-one"), MessageBody: aws.String("one")},
		{Id: aws.String("invalid"), MessageBody: aws.String("invalid delay"), DelaySeconds: 901},
		{Id: aws.String("kms-two"), MessageBody: aws.String("two")},
	}})
	if err != nil || len(out.Successful) != 0 || len(out.Failed) != 3 {
		t.Fatalf("batch=%v %v", out, err)
	}
	want := map[string]string{"kms-one": "KmsDisabled", "invalid": "InvalidParameterValue", "kms-two": "KmsDisabled"}
	for _, failure := range out.Failed {
		if aws.ToString(failure.Code) != want[aws.ToString(failure.Id)] {
			t.Fatalf("batch failure=%v", failure)
		}
	}
	k.mu.Lock()
	if k.generated != 1 {
		t.Errorf("failed preparation repeated within the same command: %d", k.generated)
	}
	k.mu.Unlock()
	if attributes(t, c, url)["ApproximateNumberOfMessages"] != "0" {
		t.Fatal("failed batch published messages")
	}
}
