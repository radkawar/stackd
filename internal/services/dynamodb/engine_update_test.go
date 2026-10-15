package dynamodb

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	engine "stackd/engine/dynamodb"
	api "stackd/internal/awsapi/dynamodb"
)

// The protocol fixture exposes the same ACTIVE-table/CREATING-index interval
// observed from the real pinned DynamoDB Local engine. No worker runs here.
type indexTransitionDatabase struct {
	table   api.TableDescription
	updates int
}

func (d *indexTransitionDatabase) Close() error { return nil }
func (d *indexTransitionDatabase) Request(_ context.Context, target string, _ []byte) (engine.Response, error) {
	switch target {
	case "DynamoDB_20120810.DescribeTable":
		body, err := json.Marshal(api.DescribeTableOutput{Table: &d.table})
		return engine.Response{StatusCode: 200, Body: body}, err
	case "DynamoDB_20120810.UpdateTable":
		d.updates++
		d.table.GlobalSecondaryIndexes = api.GlobalSecondaryIndexDescriptionList{{IndexName: new(api.IndexName("by-group")), IndexStatus: new(api.IndexStatusCREATING)}}
		body, err := json.Marshal(api.UpdateTableOutput{TableDescription: &d.table})
		return engine.Response{StatusCode: 200, Body: body}, err
	default:
		return engine.Response{}, fmt.Errorf("unexpected native operation %s", target)
	}
}

func TestNativeIndexTransitionRetainsIntentAcrossReopenWithoutReplay(t *testing.T) {
	repository := NewMemoryRepository(nil)
	record := retainedTable(Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, "index-transition", api.TimeToLiveDescription{TimeToLiveStatus: new(api.TimeToLiveStatusDISABLED)})
	record.Data.TableStatus = new(api.TableStatusUPDATING)
	record.PendingUpdate = &api.UpdateTableInput{GlobalSecondaryIndexUpdates: api.GlobalSecondaryIndexUpdateList{{Create: &api.CreateGlobalSecondaryIndexAction{IndexName: new(api.IndexName("by-group"))}}}}
	if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.PutTable(record) }); err != nil {
		t.Fatal(err)
	}
	native := &indexTransitionDatabase{table: api.TableDescription{TableStatus: new(api.TableStatusACTIVE)}}
	open := func() *Service {
		service := New(Config{Repository: repository})
		service.engines.databases[record.DatabaseID] = native
		t.Cleanup(func() { _ = service.Close() })
		return service
	}
	service := open()
	read := func() TableRecord {
		var got TableRecord
		if err := repository.View(t.Context(), func(reader Reader) error { var err error; got, err = reader.Table(record.Key); return err }); err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, status := range []api.IndexStatus{api.IndexStatusCREATING, api.IndexStatusUPDATING, api.IndexStatusDELETING} {
		if native.updates != 0 {
			native.table.GlobalSecondaryIndexes[0].IndexStatus = new(status)
		}
		current := read()
		again, err := service.reconcileTable(t.Context(), &current)
		if err != nil || !again {
			t.Fatalf("%s transition completed early: again=%v err=%v", status, again, err)
		}
		current = read()
		if current.PendingUpdate == nil || value(current.Data.TableStatus) != "UPDATING" || native.updates != 1 {
			t.Fatalf("%s lost intent or repeated native mutation: pending=%v status=%s updates=%d", status, current.PendingUpdate != nil, value(current.Data.TableStatus), native.updates)
		}
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
		service = open()
	}
	native.table.GlobalSecondaryIndexes[0].IndexStatus = new(api.IndexStatusACTIVE)
	current := read()
	if again, err := service.reconcileTable(t.Context(), &current); err != nil || again {
		t.Fatalf("native ACTIVE did not settle: again=%v err=%v", again, err)
	}
	current = read()
	if current.PendingUpdate != nil || value(current.Data.TableStatus) != "ACTIVE" || value(current.Data.GlobalSecondaryIndexes[0].IndexStatus) != "ACTIVE" || native.updates != 1 {
		t.Fatalf("settled native state differs or mutation replayed: updates=%d record=%+v", native.updates, current)
	}
}

func TestPendingTablesRecoverUnfinishedNativeIndexes(t *testing.T) {
	for _, status := range []api.IndexStatus{api.IndexStatusCREATING, api.IndexStatusUPDATING, api.IndexStatusDELETING, "", api.IndexStatusACTIVE} {
		t.Run(string(status), func(t *testing.T) {
			repository := NewMemoryRepository(nil)
			record := retainedTable(Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, "retained-index", api.TimeToLiveDescription{})
			index := api.GlobalSecondaryIndexDescription{IndexName: new(api.IndexName("by-group"))}
			if status != "" {
				index.IndexStatus = new(status)
			}
			record.Data.GlobalSecondaryIndexes = api.GlobalSecondaryIndexDescriptionList{index}
			if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.PutTable(record) }); err != nil {
				t.Fatal(err)
			}
			if err := repository.View(t.Context(), func(reader Reader) error {
				pending, err := reader.PendingTables()
				if err != nil {
					return err
				}
				want := status != api.IndexStatusACTIVE
				if (len(pending) == 1) != want {
					t.Fatalf("pending=%d, want unfinished=%v", len(pending), want)
				}
				if engineTableReady(&record.Data) == want {
					t.Fatalf("native readiness ignored index %s", status)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
