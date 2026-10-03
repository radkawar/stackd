package stackd_test

import (
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
	"stackd/storage/sqlite"
	sqlbackends "stackd/storage/sqlite/backends"
	sqsstore "stackd/storage/sqs"
)

func openSQLiteBackends(t *testing.T, path string) (*storage.Backends, func()) {
	t.Helper()
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	close := func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(close)
	backends, err := sqlbackends.New(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	return backends, close
}

func openSQLiteCloud(t *testing.T, path string, backends *storage.Backends, source clock.Clock) (cloudClients, func()) {
	t.Helper()
	persistent, closeDatabase := openSQLiteBackends(t, path)
	*backends = *persistent
	cloud, err := stackd.New(stackd.Config{Storage: backends, Clock: source})
	if err != nil {
		closeDatabase()
		t.Fatal(err)
	}
	server := httptest.NewServer(cloud)
	close := func() {
		if err := cloud.Close(); err != nil {
			t.Error(err)
		}
		server.Close()
		closeDatabase()
	}
	t.Cleanup(close)
	return cloudClients{server}, close
}

func TestSQLiteSQSRetainsFIFODeliveryAcrossDatabaseReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sqs.sqlite")
	backends := storage.NewMemory()
	manual := clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	c, close := openSQLiteCloud(t, path, backends, manual)
	client := c.sqs("test", "test", "")
	queue, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("retained.fifo"), Attributes: map[string]string{"FifoQueue": "true", "ContentBasedDeduplication": "true", "VisibilityTimeout": "30"}})
	if err != nil {
		t.Fatal(err)
	}
	sent, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("durable encrypted body"), MessageGroupId: aws.String("group")})
	if err != nil {
		t.Fatal(err)
	}
	received, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, ReceiveRequestAttemptId: aws.String("attempt")})
	if err != nil || len(received.Messages) != 1 {
		t.Fatal("initial receive", received, err)
	}
	close()
	c, _ = openSQLiteCloud(t, path, backends, manual)
	client = c.sqs("test", "test", "")
	reopened, err := client.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("retained.fifo")})
	if err != nil {
		t.Fatal(err)
	}
	url := reopened.QueueUrl
	duplicate, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: url, MessageBody: aws.String("durable encrypted body"), MessageGroupId: aws.String("group")})
	if err != nil || aws.ToString(duplicate.MessageId) != aws.ToString(sent.MessageId) || aws.ToString(duplicate.SequenceNumber) != aws.ToString(sent.SequenceNumber) {
		t.Fatal("deduplication was not recovered", duplicate, err)
	}
	if output, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: url}); err != nil || len(output.Messages) != 0 {
		t.Fatal("in-flight message lost visibility", output, err)
	}
	retry, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: url, ReceiveRequestAttemptId: aws.String("attempt")})
	if err != nil || len(retry.Messages) != 1 || aws.ToString(retry.Messages[0].ReceiptHandle) != aws.ToString(received.Messages[0].ReceiptHandle) || aws.ToString(retry.Messages[0].Body) != "durable encrypted body" {
		t.Fatal("receive attempt or encryption key was not recovered", retry, err)
	}
	if _, err := client.ChangeMessageVisibility(t.Context(), &sqs.ChangeMessageVisibilityInput{QueueUrl: url, ReceiptHandle: received.Messages[0].ReceiptHandle, VisibilityTimeout: 0}); err != nil {
		t.Fatal(err)
	}
	next, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: url, MessageSystemAttributeNames: []types.MessageSystemAttributeName{types.MessageSystemAttributeNameAll}})
	if err != nil || len(next.Messages) != 1 || next.Messages[0].Attributes["ApproximateReceiveCount"] != "2" {
		t.Fatal("receipt history was not recovered", next, err)
	}
	if _, err := client.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: url, ReceiptHandle: next.Messages[0].ReceiptHandle}); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteSQSRecoversAcceptedRedriveAfterDatabaseReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sqs.sqlite")
	backends := storage.NewMemory()
	manual := clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	c, close := openSQLiteCloud(t, path, backends, manual)
	client := c.sqs("test", "test", "")
	create := func(name string, attributes map[string]string) *string {
		t.Helper()
		out, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: &name, Attributes: attributes})
		if err != nil {
			t.Fatal(err)
		}
		return out.QueueUrl
	}
	dead := create("dead", nil)
	arn := "arn:aws:sqs:us-east-1:000000000000:dead"
	create("source", map[string]string{"RedrivePolicy": fmt.Sprintf(`{"deadLetterTargetArn":%q,"maxReceiveCount":1}`, arn)})
	create("destination", nil)
	for i := range 3 {
		if _, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: dead, MessageBody: aws.String(fmt.Sprint(i))}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := client.StartMessageMoveTask(t.Context(), &sqs.StartMessageMoveTaskInput{SourceArn: &arn, DestinationArn: aws.String("arn:aws:sqs:us-east-1:000000000000:destination"), MaxNumberOfMessagesPerSecond: aws.Int32(1)})
	if err != nil {
		t.Fatal(err)
	}
	close()
	advanceClock(t, manual, 3*time.Second)
	c, _ = openSQLiteCloud(t, path, backends, manual)
	client = c.sqs("test", "test", "")
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, err := client.ListMessageMoveTasks(t.Context(), &sqs.ListMessageMoveTasksInput{SourceArn: &arn})
		if err != nil || len(status.Results) != 1 {
			t.Fatal(status, err)
		}
		task := status.Results[0]
		if aws.ToString(task.Status) == "COMPLETED" {
			if task.ApproximateNumberOfMessagesMoved != 3 || task.StartedTimestamp != manual.Now().Add(-3*time.Second).UnixMilli() {
				t.Fatal("recovered task changed acceptance time or counts", task)
			}
			break
		}
		if aws.ToString(task.Status) != "RUNNING" || time.Now().After(deadline) {
			t.Fatal("redrive did not recover", task)
		}
		time.Sleep(time.Millisecond)
	}
	destination, err := client.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("destination")})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: destination.QueueUrl, MaxNumberOfMessages: 10})
	if err != nil || len(got.Messages) != 3 {
		t.Fatal("redrive lost destination messages", got, err)
	}
}

func TestSQLiteProcessExitRecoversKeysAndQueueState(t *testing.T) {
	if path := os.Getenv("STACKD_SQLITE_CRASH_PATH"); path != "" {
		backends := storage.NewMemory()
		c, _ := openSQLiteCloud(t, path, backends, nil)
		client := c.sqs("test", "test", "")
		owner := c.kms("test", "test", "")
		key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: aws.String("alias/recovery"), TargetKeyId: key.KeyMetadata.KeyId}); err != nil {
			t.Fatal(err)
		}
		queue, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("crash"), Attributes: map[string]string{"KmsMasterKeyId": "alias/recovery"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("committed before exit")}); err != nil {
			t.Fatal(err)
		}
		if err := backends.SQS.Update(t.Context(), func(tx sqsstore.Transaction) error {
			queue, err := tx.Queue(sqsstore.QueueKey{Partition: "aws", Account: "000000000000", Region: "us-east-1", Name: "crash"})
			if err != nil {
				return err
			}
			if err := tx.PutMessages(queue.ID, sqsstore.QueueMessages{}); err != nil {
				return err
			}
			os.Exit(0) // Terminate with an uncommitted deletion and no Close/checkpoint.
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "sqs.sqlite")
	child := exec.Command(os.Args[0], "-test.run=^TestSQLiteProcessExitRecoversKeysAndQueueState$")
	child.Env = append(os.Environ(), "STACKD_SQLITE_CRASH_PATH="+path)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("crash worker: %v\n%s", err, output)
	}
	c, _ := openSQLiteCloud(t, path, storage.NewMemory(), nil)
	client := c.sqs("test", "test", "")
	queue, err := client.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("crash")})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
	if err != nil || len(got.Messages) != 1 || aws.ToString(got.Messages[0].Body) != "committed before exit" {
		t.Fatal("process exit lost a committed message or committed the deletion", got, err)
	}
}
