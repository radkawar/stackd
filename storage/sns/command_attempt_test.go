package sns_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
	service "stackd/internal/services/sns"
	"stackd/journal"
	"stackd/storage/memory"
	domain "stackd/storage/sns"
	"stackd/storage/sqlite"
	journaldb "stackd/storage/sqlite/journal"
	backend "stackd/storage/sqlite/sns"
)

func publicationRepositories(t *testing.T, fn func(*testing.T, domain.Repository, journal.Storage)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		d := memory.NewDomain()
		fn(t, domain.NewMemory(d), journal.NewMemory(d))
	})
	t.Run("sqlite", func(t *testing.T) {
		db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "sns.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		fn(t, backend.New(db), journaldb.New(db))
	})
}

func TestPublishHandledRejectionPreservesParentTransaction(t *testing.T) {
	for _, reason := range []struct {
		name, code, auditCode string
	}{
		{"deleted_topic", "NotFound", "NotFoundException"},
		{"current_deny", "AuthorizationError", "AccessDenied"},
		{"unavailable_delivery", "NotImplementedException", "NotImplementedException"},
	} {
		t.Run(reason.name, func(t *testing.T) {
			publicationRepositories(t, func(t *testing.T, repository domain.Repository, events journal.Storage) {
				now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
				scope := domain.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}
				ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::" + scope.AccountID + ":root", PrincipalID: scope.AccountID, RequestID: "publish-notification", ParentEventID: "parent-transition"})
				parent := domain.TopicRecord{Key: domain.TopicKey{Scope: scope, Name: "parent"}, ID: "parent-topic", Created: now, Updated: now, DisplayName: "pending"}
				target := domain.TopicRecord{Key: domain.TopicKey{Scope: scope, Name: "notifications.fifo"}, ID: "target-topic", Created: now, Updated: now, FIFO: true, Archive: &domain.ArchiveConfig{RetentionDays: 1, Beginning: now, MetricDue: now.Add(time.Hour)}}
				if err := repository.Update(ctx, func(tx domain.Transaction) error {
					if err := tx.PutTopic(parent); err != nil {
						return err
					}
					return tx.PutTopic(target)
				}); err != nil {
					t.Fatal(err)
				}
				s := service.New(service.Config{Repository: repository, APIEvents: apievents.New(events), Clock: clock.NewManual(now)})
				t.Cleanup(func() { _ = s.Close() })
				if rejected := s.CheckPublish(ctx, target.Key.ARN()); rejected != nil {
					t.Fatalf("initial destination admission: %v", rejected)
				}
				if err := repository.Update(ctx, func(tx domain.Transaction) error {
					switch reason.name {
					case "deleted_topic":
						return tx.DeleteTopic(target.Key)
					case "current_deny":
						target.Policy = authorization.BoundPolicy{Document: `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*","Action":"sns:Publish","Resource":"*"}}`}
						return tx.PutTopic(target)
					default:
						return tx.PutSubscription(domain.SubscriptionRecord{Key: domain.SubscriptionKey{Topic: target.Key, ID: "subscriber"}, TopicID: target.ID, Owner: scope.AccountID, Protocol: "sqs", Endpoint: "arn:aws:sqs:us-east-1:111122223333:consumer.fifo", Created: now})
					}
				}); err != nil {
					t.Fatal(err)
				}
				input := &api.PublishInput{TopicArn: new(api.TopicARN(target.Key.ARN())), Message: new(api.Message("lifecycle notification")), MessageGroupId: new(api.String("group")), MessageDeduplicationId: new(api.String("notification"))}
				if err := repository.Update(ctx, func(tx domain.Transaction) error {
					parent.DisplayName = "notification-attempted"
					if err := tx.PutTopic(parent); err != nil {
						return err
					}
					out, rejected := s.Publish(tx.Context(), input)
					if rejected == nil || rejected.Code != reason.code || out != nil {
						t.Errorf("Publish rejection: output=%+v error=%v, want %s", out, rejected, reason.code)
					}
					parent.DisplayName = "default-applied"
					return tx.PutTopic(parent)
				}); err != nil {
					t.Fatalf("handled Publish rejection aborted parent: %v", err)
				}
				var propagated error
				err := repository.Update(ctx, func(tx domain.Transaction) error {
					parent.DisplayName = "must-rollback"
					if err := tx.PutTopic(parent); err != nil {
						return err
					}
					_, rejected := s.Publish(tx.Context(), input)
					if rejected == nil || rejected.Code != reason.code {
						t.Fatalf("propagated Publish rejection: %v, want %s", rejected, reason.code)
					}
					propagated = rejected
					return rejected
				})
				if !errors.Is(err, propagated) || propagated == nil {
					t.Fatalf("caller-propagated rejection did not abort parent: %v", err)
				}
				if err := repository.View(ctx, func(r domain.Reader) error {
					stored, err := r.Topic(parent.Key)
					if err != nil {
						return err
					}
					if stored.DisplayName != "default-applied" {
						t.Fatalf("parent transition not committed: %+v", stored)
					}
					if _, found, err := r.NextDelivery(); err != nil || found {
						t.Fatalf("rejected notification retained delivery: found=%v err=%v", found, err)
					}
					if _, err := r.NextMetricPublication(); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("rejected notification retained publication metrics: %v", err)
					}
					if _, found, err := r.NextArchiveEntry(target.ID, now, 0); err != nil || found {
						t.Fatalf("rejected notification retained archived message: found=%v err=%v", found, err)
					}
					if _, err := r.Deduplication(domain.DeduplicationKey{TopicID: target.ID, ID: "notification"}); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("rejected notification retained deduplication receipt: %v", err)
					}
					if reason.name != "deleted_topic" {
						stored, err := r.Topic(target.Key)
						if err != nil {
							return err
						}
						if stored.Sequence != 0 {
							t.Fatalf("rejected notification consumed FIFO sequence: %d", stored.Sequence)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				retained, err := events.Read(ctx, 0, 100)
				if err != nil {
					t.Fatal(err)
				}
				if len(retained) != 1 || retained[0].APICallCompleted == nil {
					t.Fatalf("expected one retained rejected API outcome: %+v", retained)
				}
				call := retained[0].APICallCompleted
				if call.EventName != "Publish" || call.EventSource != "sns.amazonaws.com" || call.ErrorCode != reason.auditCode {
					t.Fatalf("wrong retained rejection: %+v", call)
				}
				if retained[0].ParentEventID != "parent-transition" || retained[0].RequestID != "publish-notification" {
					t.Fatalf("rejected Publish lost its caller correlation: %+v", retained[0].Envelope)
				}
			})
		})
	}
}

func TestPublishAcceptanceFollowsParentCommit(t *testing.T) {
	publicationRepositories(t, func(t *testing.T, repository domain.Repository, events journal.Storage) {
		now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
		scope := domain.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}
		ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::" + scope.AccountID + ":root", PrincipalID: scope.AccountID})
		topic := domain.TopicRecord{Key: domain.TopicKey{Scope: scope, Name: "notifications.fifo"}, ID: "target-topic", Created: now, Updated: now, FIFO: true, Archive: &domain.ArchiveConfig{RetentionDays: 1, Beginning: now, MetricDue: now.Add(time.Hour)}}
		if err := repository.Update(ctx, func(tx domain.Transaction) error { return tx.PutTopic(topic) }); err != nil {
			t.Fatal(err)
		}
		s := service.New(service.Config{Repository: repository, APIEvents: apievents.New(events), Clock: clock.NewManual(now)})
		t.Cleanup(func() { _ = s.Close() })
		input := &api.PublishInput{TopicArn: new(api.TopicARN(topic.Key.ARN())), Message: new(api.Message("retained notification")), MessageGroupId: new(api.String("group")), MessageDeduplicationId: new(api.String("notification"))}
		abort := errors.New("parent aborted")
		for _, commit := range []bool{false, true} {
			var message domain.MessageKey
			err := repository.Update(ctx, func(tx domain.Transaction) error {
				out, rejected := s.Publish(tx.Context(), input)
				if rejected != nil {
					return rejected
				}
				message.ID = string(*out.MessageId)
				stored, err := tx.Topic(topic.Key)
				if err != nil {
					return err
				}
				if stored.Sequence != 1 {
					t.Fatalf("parent did not observe accepted FIFO sequence: %d", stored.Sequence)
				}
				stored.DisplayName = "published"
				if err := tx.PutTopic(stored); err != nil {
					return err
				}
				if !commit {
					return abort
				}
				return nil
			})
			if commit && err != nil || !commit && !errors.Is(err, abort) {
				t.Fatalf("parent commit=%v: %v", commit, err)
			}
			retained, err := events.Read(ctx, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if err := repository.View(ctx, func(r domain.Reader) error {
				stored, err := r.Topic(topic.Key)
				if err != nil {
					return err
				}
				record, messageErr := r.Message(message)
				entry, archiveErr := r.ArchiveEntry(message)
				receipt, receiptErr := r.Deduplication(domain.DeduplicationKey{TopicID: topic.ID, ID: "notification"})
				if !commit {
					if stored.Sequence != 0 || stored.DisplayName != "" || !errors.Is(messageErr, domain.ErrNotFound) || !errors.Is(archiveErr, domain.ErrNotFound) || !errors.Is(receiptErr, domain.ErrNotFound) || len(retained) != 0 {
						t.Fatalf("parent rollback retained accepted publication: topic=%+v message=%v archive=%v receipt=%v events=%+v", stored, messageErr, archiveErr, receiptErr, retained)
					}
					return nil
				}
				if stored.Sequence != 1 || stored.DisplayName != "published" || messageErr != nil || archiveErr != nil || receiptErr != nil {
					t.Fatalf("parent commit lost accepted publication: topic=%+v message=%v archive=%v receipt=%v", stored, messageErr, archiveErr, receiptErr)
				}
				if record.Body != string(*input.Message) || entry.Message != message || receipt.MessageID != message.ID {
					t.Fatalf("accepted publication lost message identity: message=%+v archive=%+v receipt=%+v", record, entry, receipt)
				}
				if len(retained) != 1 || retained[0].APICallCompleted == nil {
					t.Fatalf("accepted publication lost API outcome: %+v", retained)
				}
				call := retained[0].APICallCompleted
				if call.EventName != "Publish" || call.ErrorCode != "" || record.ParentEventID != call.EventID {
					t.Fatalf("accepted publication lost atomic audit identity: message=%+v call=%+v", record, call)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	})
}
