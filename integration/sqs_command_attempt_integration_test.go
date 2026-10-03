package stackd_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	sqsservice "stackd/internal/services/sqs"
	"stackd/journal"
	"stackd/storage"
	kmsstore "stackd/storage/kms"
	sqsstore "stackd/storage/sqs"
)

type rejectedSQSMessageJournal struct{ journal.Storage }

func (j rejectedSQSMessageJournal) AppendSQSMessageAccepted(ctx context.Context, envelope journal.Envelope, message journal.SQSMessageAccepted) error {
	if err := j.Storage.AppendSQSMessageAccepted(ctx, envelope, message); err != nil {
		return err
	}
	return errors.New("reject after staging the accepted-message event")
}

func TestSQSCommandRejectionPreservesParentTransaction(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range []struct {
			name, action, code             string
			missing, denied, rejectJournal bool
		}{
			{name: "send-missing", action: "SendMessage", code: "QueueDoesNotExist", missing: true},
			{name: "send-denied", action: "SendMessage", code: "AccessDenied", denied: true},
			{name: "send-enqueue-rejected", action: "SendMessage", code: "InternalError", rejectJournal: true},
			{name: "lookup-missing", action: "GetQueueUrl", code: "QueueDoesNotExist", missing: true},
			{name: "lookup-denied", action: "GetQueueUrl", code: "AccessDenied", denied: true},
		} {
			t.Run(backend+"/"+scenario.name, func(t *testing.T) {
				backends := storage.NewMemory()
				if backend == "sqlite" {
					var closeDatabase func()
					backends, closeDatabase = openSQLiteBackends(t, filepath.Join(t.TempDir(), "commands.sqlite"))
					t.Cleanup(closeDatabase)
				}
				var messages sqsservice.MessageJournal = backends.Journal
				if scenario.rejectJournal {
					messages = rejectedSQSMessageJournal{backends.Journal}
				}
				service := sqsservice.NewWithConfig(sqsservice.Config{Repository: backends.SQS, Journal: messages, APIEvents: apievents.New(backends.Journal)})
				t.Cleanup(func() { _ = service.Close() })
				const account = "111111111111"
				ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: account, Region: "us-east-1", PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account, RequestID: "parent-command"})
				execute := func(ctx context.Context, action, input string) (any, *awswire.Error) {
					t.Helper()
					decoded, err := sqsapi.DecodeRequest(action, awsapi.Request{JSON: []byte(input)})
					if err != nil {
						t.Fatal(err)
					}
					return service.ExecuteCommand(ctx, decoded)
				}
				queue, wireErr := execute(ctx, "CreateQueue", `{"QueueName":"destination"}`)
				if wireErr != nil {
					t.Fatal(wireErr)
				}
				if scenario.denied {
					url := string(*queue.(*sqsapi.CreateQueueOutput).QueueUrl)
					policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["sqs:SendMessage","sqs:GetQueueUrl"],"Resource":"*"}]}`
					if _, wireErr := execute(ctx, "SetQueueAttributes", fmt.Sprintf(`{"QueueUrl":%q,"Attributes":{"Policy":%q}}`, url, policy)); wireErr != nil {
						t.Fatal(wireErr)
					}
				}
				name := "destination"
				if scenario.missing {
					name = "missing"
				}
				owner := kmsstore.KeyOwner{Partition: "aws", AccountID: account}
				err := backends.KMS.Transact(ctx, func(parent kmsstore.Transaction) error {
					if err := parent.PutKeySet(owner, kmsstore.KeySetRecord{ID: "before-child"}); err != nil {
						return err
					}
					var rejected *awswire.Error
					if scenario.action == "SendMessage" {
						body := sqsapi.String("not-published")
						_, rejected = service.SendToQueue(parent.Context(), "arn:aws:sqs:us-east-1:"+account+":"+name, &sqsapi.SendMessageInput{MessageBody: &body})
					} else {
						_, rejected = execute(parent.Context(), "GetQueueUrl", fmt.Sprintf(`{"QueueName":%q}`, name))
					}
					if rejected == nil || rejected.Code != scenario.code {
						t.Errorf("command rejection = %v, want %s", rejected, scenario.code)
					}
					return parent.PutKeySet(owner, kmsstore.KeySetRecord{ID: "after-handled-child"})
				})
				if err != nil {
					t.Errorf("handled child rejection prevented parent commit: %v", err)
				}
				if err := backends.KMS.Transact(ctx, func(tx kmsstore.Transaction) error {
					for _, id := range []string{"before-child", "after-handled-child"} {
						if _, err := tx.KeySet(owner, id); err != nil {
							t.Errorf("parent mutation %s did not survive: %v", id, err)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := backends.SQS.View(ctx, func(reader sqsstore.Reader) error {
					queue, err := reader.Queue(sqsstore.QueueKey{Partition: "aws", Account: account, Region: "us-east-1", Name: "destination"})
					if err != nil {
						return err
					}
					messages, err := reader.Messages(queue.ID)
					if err != nil {
						return err
					}
					if len(messages.Messages) != 0 || len(messages.Receipts) != 0 || len(messages.Deduplications) != 0 || queue.Sequence != 0 {
						t.Errorf("rejected command retained delivery changes: queue=%+v messages=%+v", queue, messages)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				rows, err := backends.Journal.Read(ctx, 0, 100)
				if err != nil {
					t.Fatal(err)
				}
				rejections := 0
				for _, row := range rows {
					if row.SQSMessageAccepted.MessageID != "" {
						t.Error("rejected command retained an accepted-message event")
					}
					if call := row.APICallCompleted; call != nil && call.EventSource == "sqs.amazonaws.com" && call.EventName == scenario.action {
						if call.ErrorCode != scenario.code {
							t.Errorf("rejected command recorded outcome %q, want %s", call.ErrorCode, scenario.code)
						}
						rejections++
					}
				}
				if rejections != 1 {
					t.Errorf("retained %d rejected API audits, want one", rejections)
				}
			})
		}
	}
}
