package sqs

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/journal"
	"stackd/storage/memory"
)

func TestMemoryRepositoryCopiesAndRollsBack(t *testing.T) {
	repository := NewMemoryRepository(nil)
	ctx := context.Background()
	key := QueueKey{Partition: "aws", Account: "111111111111", Region: "us-east-1", Name: "q"}
	record := QueueRecord{Key: key, ID: "id", Configuration: QueueConfiguration{PolicyPrincipals: map[string]string{"arn": "principal"}}, ManagedEncryptionKey: []byte{1, 2, 3}}
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutQueue(record); err != nil {
			return err
		}
		return tx.PutMessages("id", QueueMessages{Messages: []MessageRecord{{ID: "m", Data: []byte("body")}}})
	}); err != nil {
		t.Fatal(err)
	}
	record.Configuration.PolicyPrincipals["arn"] = "mutated"
	record.ManagedEncryptionKey[0] = 99
	if err := repository.View(ctx, func(reader Reader) error {
		q, err := reader.Queue(key)
		if err != nil {
			return err
		}
		if q.Configuration.PolicyPrincipals["arn"] != "principal" || q.ManagedEncryptionKey[0] != 1 {
			t.Fatal("Put retained caller-owned state")
		}
		q.ManagedEncryptionKey[0] = 44
		messages, err := reader.Messages("id")
		if err != nil {
			return err
		}
		messages.Messages[0].Data[0] = 'X'
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("rollback")
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.DeleteQueue(key); err != nil {
			return err
		}
		return failure
	}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	if err := repository.Update(cancelled, func(tx Transaction) error {
		if err := tx.DeleteQueue(key); err != nil {
			return err
		}
		cancel()
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
	if err := repository.View(ctx, func(reader Reader) error {
		q, err := reader.Queue(key)
		if err != nil {
			return err
		}
		messages, err := reader.Messages(q.ID)
		if err != nil {
			return err
		}
		if q.ManagedEncryptionKey[0] != 1 || string(messages.Messages[0].Data) != "body" {
			t.Fatal("Reader exposed mutable stored values")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type failingRepository struct {
	Repository
	fail bool
}

func (r *failingRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return r.Repository.Attempt(ctx, func(tx Transaction) error {
		if err := fn(tx); err != nil {
			return err
		}
		if r.fail {
			return errors.New("simulated commit failure")
		}
		return nil
	})
}
func TestRepositoryCommitFailurePreservesMessageTransitions(t *testing.T) {
	domain := memory.NewDomain()
	history := journal.NewMemory(domain)
	backend := &failingRepository{Repository: NewMemoryRepository(domain)}
	s := NewWithConfig(Config{Repository: backend, Journal: history})
	server := testServer(t, s)
	c := testClient(server, "111111111111", "us-east-1")
	ctx := context.Background()
	url := create(t, c, "commit", nil)
	// The flag is changed only while no request is active.
	backend.fail = true
	_, err := c.SendMessage(ctx, &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String("rollback send")})
	requireCode(t, err, "InternalError")
	backend.fail = false
	if len(receive(t, c, url, 1)) != 0 {
		t.Fatal("failed send committed a message")
	}
	if events, err := history.Read(ctx, 0, 100); err != nil || len(events) != 0 {
		t.Fatalf("failed send committed journal rows: %v, %v", events, err)
	}
	accepted := send(t, c, url, "kept")
	if events, err := history.Read(ctx, 0, 100); err != nil || len(events) != 1 || events[0].SQSMessageAccepted.MessageID != aws.ToString(accepted.MessageId) {
		t.Fatalf("accepted send lost its journal row: %v, %v", events, err)
	}
	backend.fail = true
	_, err = c.ReceiveMessage(ctx, &sdk.ReceiveMessageInput{QueueUrl: aws.String(url)})
	requireCode(t, err, "InternalError")
	backend.fail = false
	got := receive(t, c, url, 1)
	if len(got) != 1 || got[0].Attributes["ApproximateReceiveCount"] != "1" {
		t.Fatalf("failed receive changed state: %v", got)
	}
	backend.fail = true
	_, err = c.DeleteMessage(ctx, &sdk.DeleteMessageInput{QueueUrl: aws.String(url), ReceiptHandle: got[0].ReceiptHandle})
	requireCode(t, err, "InternalError")
	backend.fail = false
	if attributes(t, c, url)["ApproximateNumberOfMessagesNotVisible"] != "1" {
		t.Fatal("failed delete committed")
	}
}

type failingMessageJournal struct {
	MessageJournal
	fail bool
}

func (j *failingMessageJournal) AppendSQSMessageAccepted(ctx context.Context, envelope journal.Envelope, event journal.SQSMessageAccepted) error {
	if err := j.MessageJournal.AppendSQSMessageAccepted(ctx, envelope, event); err != nil {
		return err
	}
	if j.fail {
		return errors.New("simulated event append failure")
	}
	return nil
}

func TestJournalFailureRollsBackAcceptedSend(t *testing.T) {
	domain := memory.NewDomain()
	history := journal.NewMemory(domain)
	sink := &failingMessageJournal{MessageJournal: history, fail: true}
	s := NewWithConfig(Config{Repository: NewMemoryRepository(domain), Journal: sink})
	client := testClient(testServer(t, s), "111111111111", "us-east-1")
	url := create(t, client, "journal-failure.fifo", map[string]string{"FifoQueue": "true"})
	in := &sdk.SendMessageInput{QueueUrl: &url, MessageBody: aws.String("owned body"), MessageGroupId: aws.String("group"), MessageDeduplicationId: aws.String("dedup")}
	_, err := client.SendMessage(t.Context(), in)
	requireCode(t, err, "InternalError")
	if got := receive(t, client, url, 1); len(got) != 0 {
		t.Fatalf("failed append committed message: %v", got)
	}
	if events, err := history.Read(t.Context(), 0, 100); err != nil || len(events) != 0 {
		t.Fatalf("failed append retained history: %v, %v", events, err)
	}
	sink.fail = false
	accepted, err := client.SendMessage(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	if got := receive(t, client, url, 1); len(got) != 1 || aws.ToString(got[0].MessageId) != aws.ToString(accepted.MessageId) {
		t.Fatalf("failed append retained FIFO deduplication or lost retried send: %v", got)
	}
	if events, err := history.Read(t.Context(), 0, 100); err != nil || len(events) != 1 || events[0].SQSMessageAccepted.MessageID != aws.ToString(accepted.MessageId) {
		t.Fatalf("retried send journal: %v, %v", events, err)
	}
}
func TestRepositoryCanBeReusedByNewServiceWithoutLosingDeliveryState(t *testing.T) {
	backend := NewMemoryRepository(nil)
	first := NewWithRepository(backend, nil, nil)
	firstServer := testServer(t, first)
	c := testClient(firstServer, "111111111111", "us-east-1")
	ctx := context.Background()
	url := create(t, c, "restart.fifo", map[string]string{"FifoQueue": "true", "ContentBasedDeduplication": "true"})
	original := fifoSend(t, c, url, "persisted message", "group", "")
	got := receive(t, c, url, 1)
	if len(got) != 1 {
		t.Fatal("missing first delivery")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := NewWithRepository(backend, nil, nil)
	secondServer := testServer(t, second)
	other := testClient(secondServer, "111111111111", "us-east-1")
	looked, err := other.GetQueueUrl(ctx, &sdk.GetQueueUrlInput{QueueName: aws.String("restart.fifo")})
	if err != nil {
		t.Fatal(err)
	}
	url = aws.ToString(looked.QueueUrl)
	duplicate := fifoSend(t, other, url, "persisted message", "group", "")
	if aws.ToString(original.MessageId) != aws.ToString(duplicate.MessageId) {
		t.Fatal("dedup state lost when changing service instance")
	}
	if len(receive(t, other, url, 1)) != 0 {
		t.Fatal("in-flight message became visible when changing service instance")
	}
	_, err = other.ChangeMessageVisibility(ctx, &sdk.ChangeMessageVisibilityInput{QueueUrl: aws.String(url), ReceiptHandle: got[0].ReceiptHandle, VisibilityTimeout: 0})
	if err != nil {
		t.Fatal(err)
	}
	next := receive(t, other, url, 1)
	if len(next) != 1 || aws.ToString(next[0].Body) != "persisted message" || next[0].Attributes["ApproximateReceiveCount"] != "2" {
		t.Fatalf("restored delivery=%v", next)
	}
}
