package dynamodb_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	api "stackd/internal/awsapi/dynamodb"
	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/dynamodb"
)

func TestUnfinishedNativeIndexesAndPendingIntentSurviveReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native-index.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repository := backend.New(db)
	scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	accepted := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := repository.Update(t.Context(), func(tx domain.Transaction) error {
		for i, status := range []api.IndexStatus{api.IndexStatusCREATING, api.IndexStatusUPDATING, api.IndexStatusDELETING, "", api.IndexStatusACTIVE} {
			name := fmt.Sprintf("retained-%d", i)
			index := api.GlobalSecondaryIndexDescription{IndexName: new(api.IndexName("by-group"))}
			if status != "" {
				index.IndexStatus = new(status)
			}
			record := domain.TableRecord{Key: domain.TableKey{Scope: scope, Name: name}, DatabaseID: "retained-database", PhysicalName: "table_" + name, Data: api.TableDescription{TableName: new(api.TableName(name)), TableStatus: new(api.TableStatusACTIVE), GlobalSecondaryIndexes: api.GlobalSecondaryIndexDescriptionList{index}}}
			if err := tx.PutTable(record); err != nil {
				return err
			}
		}
		pending := domain.TableRecord{Key: domain.TableKey{Scope: scope, Name: "pending"}, DatabaseID: "retained-database", PhysicalName: "table_pending", Data: api.TableDescription{TableStatus: new(api.TableStatusUPDATING)}, UpdateAcceptedAt: accepted, PendingUpdate: &api.UpdateTableInput{GlobalSecondaryIndexUpdates: api.GlobalSecondaryIndexUpdateList{{Create: &api.CreateGlobalSecondaryIndexAction{IndexName: new(api.IndexName("by-group"))}}}}}
		return tx.PutTable(pending)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repository = backend.New(db)
	if err := repository.View(t.Context(), func(reader domain.Reader) error {
		pending, err := reader.PendingTables()
		if err != nil {
			return err
		}
		if len(pending) != 5 {
			t.Fatalf("pending native tables = %d, want four unfinished indexes and one interrupted update", len(pending))
		}
		for _, record := range pending {
			if record.Key.Name == "retained-4" {
				t.Fatal("settled native ACTIVE index was scheduled")
			}
			if record.Key.Name == "pending" && (record.PendingUpdate == nil || !record.UpdateAcceptedAt.Equal(accepted) || *record.PendingUpdate.GlobalSecondaryIndexUpdates[0].Create.IndexName != "by-group") {
				t.Fatalf("interrupted native update lost on reopen: %+v", record)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(t.Context(), func(tx domain.Transaction) error {
		pending, err := tx.PendingTables()
		if err != nil {
			return err
		}
		for _, record := range pending {
			record.Data.TableStatus = new(api.TableStatusACTIVE)
			for i := range record.Data.GlobalSecondaryIndexes {
				record.Data.GlobalSecondaryIndexes[i].IndexStatus = new(api.IndexStatusACTIVE)
			}
			record.PendingUpdate = nil
			record.UpdateAcceptedAt = time.Time{}
			if err := tx.PutTable(record); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.New(db).View(t.Context(), func(reader domain.Reader) error {
		pending, err := reader.PendingTables()
		if err == nil && len(pending) != 0 {
			t.Fatalf("settled native index transition reappeared after reopen: %d", len(pending))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
