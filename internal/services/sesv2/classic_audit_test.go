package sesv2_test

import (
	"context"
	"errors"
	"path/filepath"
	"stackd/internal/awsapi"
	classic "stackd/internal/awsapi/ses"
	"stackd/internal/awscatalog"
	service "stackd/internal/services/sesv2"
	"stackd/journal"
	"stackd/storage/sqlite"
	sqlrepo "stackd/storage/sqlite/sesv2"
	"testing"
)

type unavailableAudit struct{}

func (unavailableAudit) Record(context.Context, journal.Envelope, journal.APICallCompleted) error {
	return errors.New("audit storage unavailable")
}

func TestClassicAuditFailureRollsBackAcceptedMIME(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repository service.Repository = service.NewMemoryRepository(nil)
			if backend == "sqlite" {
				db, e := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
				if e != nil {
					t.Fatal(e)
				}
				defer db.Close()
				repository = sqlrepo.New(db)
			}
			owner := service.NewWithConfig(service.Config{Repository: repository, PublicEndpoint: "http://localhost"})
			verify(t, owner, repository, "sender@example.invalid")
			owner.Close()
			blocked := service.NewWithConfig(service.Config{Repository: repository, APIEvents: unavailableAudit{}, CaptureDirectory: t.TempDir()})
			defer blocked.Close()
			model, _ := awscatalog.LookupService("ses")
			operation, _ := model.Operation("SendRawEmail")
			raw := []byte("From: sender@example.invalid\r\nTo: success@simulator.amazonses.com\r\nSubject: Must roll back\r\n\r\nNever publish without audit.\r\n")
			_, rejected := blocked.Classic().ExecuteCommand(contextFor(t, scope), awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &classic.SendRawEmailInput{RawMessage: &classic.RawMessage{Data: raw}}})
			if rejected == nil || rejected.Code != "InternalFailure" {
				t.Fatalf("failed audit admitted send: %v", rejected)
			}
			if e := repository.View(t.Context(), func(r service.Reader) error {
				messages, e := r.Messages(scope)
				if e != nil {
					return e
				}
				for _, m := range messages {
					if m.ContentKind == "RAW" {
						t.Fatalf("failed audit committed outgoing MIME %s", m.Key.Name)
					}
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			recovered := service.NewWithConfig(service.Config{Repository: repository})
			defer recovered.Close()
			out := classicSuccess(t, recovered, "SendRawEmail", &classic.SendRawEmailInput{RawMessage: &classic.RawMessage{Data: raw}}).(*classic.SendRawEmailOutput)
			retainedMessage := retained(t, repository, string(*out.MessageId))
			if retainedMessage.Subject != "Must roll back" || retainedMessage.SourceIdentityARN != "arn:aws:ses:us-east-1:123456789012:identity/sender@example.invalid" {
				t.Fatal("recovery lost actual bytes or admitted identity owner")
			}
		})
	}
}
