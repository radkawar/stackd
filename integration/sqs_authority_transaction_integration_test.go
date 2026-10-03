package stackd_test

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/storage"
	sqsstore "stackd/storage/sqs"
)

// Delay acquiring queue storage while an independent IAM request changes the
// caller's permissions. Authorization must use the eventual write snapshot.
type gatedQueueRepository struct {
	sqsstore.Repository
	armed            atomic.Bool
	entered, release chan struct{}
	once             sync.Once
}

func (r *gatedQueueRepository) unblock() { r.once.Do(func() { close(r.release) }) }

func (r *gatedQueueRepository) Attempt(ctx context.Context, fn func(sqsstore.Transaction) error) error {
	if r.armed.CompareAndSwap(true, false) {
		close(r.entered)
		select {
		case <-r.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return r.Repository.Attempt(ctx, fn)
}

func TestSQSUsesIAMPermissionsAtQueueTransaction(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				var closeDatabase func()
				backends, closeDatabase = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
				t.Cleanup(closeDatabase)
			}
			repository := &gatedQueueRepository{Repository: backends.SQS, entered: make(chan struct{}), release: make(chan struct{})}
			backends.SQS = repository
			c := clockCloud(t, stackd.Config{Storage: backends})
			t.Cleanup(repository.unblock)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			root := c.iam("test", "test", "")
			_, access, secret := c.user(t, "test", "producer")
			putUserPolicy(t, root, "producer", allow(`"sqs:SendMessage"`, "*"))
			queues := c.sqs("test", "test", "")
			queue, err := queues.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("authority")})
			if err != nil {
				t.Fatal(err)
			}
			repository.armed.Store(true)
			done := make(chan error, 1)
			go func() {
				_, err := c.sqs(access, secret, "").SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("revoked")})
				done <- err
			}()
			select {
			case <-repository.entered:
			case <-ctx.Done():
				t.Fatal("queue request did not reach storage", ctx.Err())
			}
			if _, err := root.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: aws.String("producer"), PolicyName: aws.String("access")}); err != nil {
				t.Fatal(err)
			}
			repository.unblock()
			assertAPIError(t, <-done, "AccessDenied")
			messages, err := queues.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
			if err != nil || len(messages.Messages) != 0 {
				t.Fatal("revoked authorization published a message", messages, err)
			}
			putUserPolicy(t, root, "producer", allow(`"sqs:SendMessage"`, "*"))
			if _, err := c.sqs(access, secret, "").SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("restored")}); err != nil {
				t.Fatal("restored permission did not permit a new send", err)
			}
			messages, err = queues.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
			if err != nil || len(messages.Messages) != 1 || aws.ToString(messages.Messages[0].Body) != "restored" {
				t.Fatal("restored permission did not deliver the message", messages, err)
			}
		})
	}
}
