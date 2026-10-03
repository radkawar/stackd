package ssmdocuments

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"stackd/clock"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/journal"
	"stackd/storage/memory"
)

const lifecycleContent = `{"schemaVersion":"2.2","mainSteps":[{"name":"shell","action":"aws:runShellScript","inputs":{"runCommand":["exit 0"]}}]}`

func TestDocumentVersionActivationAndIncarnation(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
	manual := clock.NewManual(time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC))
	domain := memory.NewDomain()
	repository := NewMemoryRepository(domain)
	history := journal.NewMemory(domain)
	s := New(Config{Repository: repository, Clock: manual, Recorder: apievents.New(history)})
	defer s.Close()
	name := api.DocumentName("LifecycleCommand")
	key := Key{Scope: scopeFor(ctx), Name: string(name)}
	// Drive the admission transaction directly to observe persisted pending state
	// before the scheduler is started. Public ExecuteCommand uses this same path.
	create := func() string {
		t.Helper()
		var id string
		if err := repository.Attempt(ctx, func(tx Transaction) error {
			in := &api.CreateDocumentRequest{Name: &name, Content: new(api.DocumentContent(lifecycleContent))}
			out, err := s.createDocument(tx, in)
			if err != nil {
				return err
			}
			if value(out.DocumentDescription.Status) != "Creating" {
				t.Fatalf("create status: %v", out.DocumentDescription.Status)
			}
			record, err := tx.Document(key)
			if err != nil {
				return err
			}
			id = record.DocumentID
			parsed, err := uuid.Parse(id)
			if err != nil || parsed.Version() != 4 {
				t.Fatalf("document identity: %q", id)
			}
			return s.recordSuccess(tx, "CreateDocument", in, out)
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	assertVersion := func(selector, status, content, defaultVersion, latest string) {
		t.Helper()
		if err := repository.Attempt(ctx, func(tx Transaction) error {
			get, err := s.getDocument(tx, &api.GetDocumentRequest{Name: new(api.DocumentARN(name)), DocumentVersion: new(api.DocumentVersion(selector))})
			if err != nil {
				return err
			}
			if value(get.Status) != status || value(get.Content) != content {
				t.Fatalf("get %s: status=%s content=%s", selector, value(get.Status), value(get.Content))
			}
			describe, err := s.describeDocument(tx, &api.DescribeDocumentRequest{Name: new(api.DocumentARN(name)), DocumentVersion: new(api.DocumentVersion(selector))})
			if err != nil {
				return err
			}
			d := describe.Document
			if value(d.Status) != status || value(d.DefaultVersion) != defaultVersion || value(d.LatestVersion) != latest {
				t.Fatalf("describe %s: %+v", selector, d)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	id := create()
	assertVersion("1", "Creating", lifecycleContent, "1", "1")
	if _, err := s.JobDriver().RunDue(ctx, 10); err != nil {
		t.Fatal(err)
	}
	assertVersion("1", "Active", lifecycleContent, "1", "1")
	updated := lifecycleContent + "\n"
	if err := repository.Attempt(ctx, func(tx Transaction) error {
		in := &api.UpdateDocumentRequest{Name: &name, Content: new(api.DocumentContent(updated)), DocumentVersion: new(api.DocumentVersion("$LATEST"))}
		out, err := s.updateDocument(tx, in)
		if err != nil {
			return err
		}
		if value(out.DocumentDescription.Status) != "Updating" || value(out.DocumentDescription.DocumentVersion) != "2" {
			t.Fatalf("update: %+v", out)
		}
		return s.recordSuccess(tx, "UpdateDocument", in, out)
	}); err != nil {
		t.Fatal(err)
	}
	assertVersion("$DEFAULT", "Active", lifecycleContent, "1", "2")
	assertVersion("$LATEST", "Updating", updated, "1", "2")
	if err := repository.Attempt(ctx, func(tx Transaction) error {
		_, err := s.updateDefault(tx, &api.UpdateDocumentDefaultVersionRequest{Name: &name, DocumentVersion: new(api.DocumentVersionNumber("2"))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	assertVersion("$DEFAULT", "Updating", updated, "2", "2")
	if _, err := s.JobDriver().RunDue(ctx, 10); err != nil {
		t.Fatal(err)
	}
	assertVersion("$DEFAULT", "Active", updated, "2", "2")
	entries, err := history.Read(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("accepted audit entries: %d", len(entries))
	}
	for i, status := range []string{"Creating", "Updating"} {
		var response struct {
			DocumentDescription struct{ DocumentID, Status string }
		}
		if err := json.Unmarshal(entries[i].APICallCompleted.ResponseElements, &response); err != nil {
			t.Fatal(err)
		}
		if response.DocumentDescription.DocumentID != id || response.DocumentDescription.Status != status {
			t.Fatalf("audit does not describe admission: %+v", response)
		}
	}
	// A selected job must not activate a same-name replacement with the same
	// version and admission instant. Its durable incarnation is the fence.
	if err := repository.Update(ctx, func(tx Transaction) error { return tx.DeleteDocument(key) }); err != nil {
		t.Fatal(err)
	}
	oldID := create()
	source := activationJobs{s}
	selected, found, err := source.Next(ctx)
	if err != nil || !found {
		t.Fatalf("pending create: %v %v", found, err)
	}
	if err := repository.Update(ctx, func(tx Transaction) error { return tx.DeleteDocument(key) }); err != nil {
		t.Fatal(err)
	}
	newID := create()
	if oldID == newID || id == newID {
		t.Fatal("recreation retained document incarnation")
	}
	if err := source.Run(context.Background(), selected); err != nil {
		t.Fatal(err)
	}
	assertVersion("1", "Creating", lifecycleContent, "1", "1")
	if _, err := s.JobDriver().RunDue(ctx, 10); err != nil {
		t.Fatal(err)
	}
	assertVersion("1", "Active", lifecycleContent, "1", "1")
}
