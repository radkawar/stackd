package rds_test

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/rds"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/rds"
	"stackd/journal"
	"stackd/storage/memory"
	domain "stackd/storage/rds"
	"stackd/storage/sqlite"
	journaldb "stackd/storage/sqlite/journal"
	backend "stackd/storage/sqlite/rds"
)

type failGlobalAudit struct {
	sink   apievents.Sink
	action string
}

func (f *failGlobalAudit) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := f.sink.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if call.EventName == f.action && call.ErrorCode == "" {
		return errors.New("injected global metadata journal failure")
	}
	return nil
}

func TestGlobalClusterResourceAndJournalRollback(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			memoryDomain := memory.NewDomain()
			var repo domain.Repository = domain.NewMemory(memoryDomain)
			var events journal.Storage = journal.NewMemory(memoryDomain)
			if kind == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "global.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo, events = backend.New(db), journaldb.New(db)
			}
			fault := &failGlobalAudit{sink: events}
			s := service.New(service.Config{Repository: repo, Recorder: apievents.New(fault)})
			t.Cleanup(func() { _ = s.Close() })
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root"})
			command := func(action string, values url.Values) *awswire.Error {
				t.Helper()
				request, err := api.DecodeRequest(action, awsapi.Request{Query: values})
				if err != nil {
					t.Fatal(err)
				}
				_, rejected := s.ExecuteCommand(ctx, request)
				return rejected
			}
			key := domain.GlobalKey{GlobalScope: domain.GlobalScope{Partition: "aws", AccountID: "111111111111"}, Name: "owned"}
			create := url.Values{"GlobalClusterIdentifier": {"owned"}, "Engine": {"docdb"}, "Tags.Tag.1.Key": {"owner"}, "Tags.Tag.1.Value": {"original"}}
			fault.action = "CreateGlobalCluster"
			if rejected := command("CreateGlobalCluster", create); rejected == nil || rejected.Code != "InternalFailure" {
				t.Fatalf("create ignored journal failure: %v", rejected)
			}
			if err := repo.View(ctx, func(r domain.Reader) error {
				_, err := r.GlobalCluster(key)
				if !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("failed journal created namespace: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			fault.action = ""
			if rejected := command("CreateGlobalCluster", create); rejected != nil {
				t.Fatal(rejected)
			}
			var original domain.GlobalCluster
			if err := repo.View(ctx, func(r domain.Reader) error {
				var err error
				original, err = r.GlobalCluster(key)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			for _, mutation := range []struct {
				action string
				values url.Values
			}{
				{"ModifyGlobalCluster", url.Values{"GlobalClusterIdentifier": {"owned"}, "NewGlobalClusterIdentifier": {"renamed"}, "DeletionProtection": {"true"}}},
				{"AddTagsToResource", url.Values{"ResourceName": {key.ARN()}, "Tags.Tag.1.Key": {"owner"}, "Tags.Tag.1.Value": {"changed"}}},
				{"DeleteGlobalCluster", url.Values{"GlobalClusterIdentifier": {"owned"}}},
			} {
				fault.action = mutation.action
				if rejected := command(mutation.action, mutation.values); rejected == nil || rejected.Code != "InternalFailure" {
					t.Fatalf("%s ignored journal failure: %v", mutation.action, rejected)
				}
				if err := repo.View(ctx, func(r domain.Reader) error {
					all, err := r.GlobalClusters(key.GlobalScope)
					if err != nil {
						return err
					}
					if len(all) != 1 || all[0].Key != key || all[0].ResourceID != original.ResourceID || all[0].DeletionProtection || all[0].Tags["owner"] != "original" {
						t.Fatalf("%s escaped command rollback: %#v", mutation.action, all)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			page, err := events.LookupAPICalls(ctx, journal.APICallQuery{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", Start: time.Unix(0, 0), End: time.Now().Add(time.Hour), Limit: 100})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Events) != 5 {
				t.Fatalf("journal retained rolled-back success or lost rejection: %d", len(page.Events))
			}
			successes := 0
			for _, event := range page.Events {
				call := event.APICallCompleted
				if call == nil {
					t.Fatal("missing completed API event")
				}
				if call.ErrorCode == "" {
					successes++
					if call.EventName != "CreateGlobalCluster" {
						t.Fatalf("failed mutation kept success event: %#v", call)
					}
				} else if call.ErrorCode != "InternalFailure" {
					t.Fatalf("wrong failure journal: %#v", call)
				}
			}
			if successes != 1 {
				t.Fatalf("successful lifecycle journal count: %d", successes)
			}
			fault.action = ""
			if rejected := command("DescribeGlobalClusters", url.Values{}); rejected != nil {
				t.Fatal(rejected)
			}
			if rejected := command("DeleteGlobalCluster", url.Values{"GlobalClusterIdentifier": {"owned"}}); rejected != nil {
				t.Fatal(rejected)
			}
		})
	}
}
