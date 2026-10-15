package ec2_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awstest"
	domain "stackd/internal/services/ec2"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
	sqljournal "stackd/storage/sqlite/journal"
)

type flowStores struct {
	repo   domain.Repository
	events journal.Storage
	db     *sql.DB
	path   string
}

func openFlowStores(t *testing.T, backend string) *flowStores {
	t.Helper()
	stores := &flowStores{path: filepath.Join(t.TempDir(), "flow-logs.sqlite")}
	if backend == "memory" {
		shared := memory.NewDomain()
		stores.repo, stores.events = domain.NewMemoryRepository(shared), journal.NewMemory(shared)
		return stores
	}
	stores.reopen(t)
	t.Cleanup(func() {
		if err := stores.db.Close(); err != nil {
			t.Error(err)
		}
	})
	return stores
}

func (s *flowStores) reopen(t *testing.T) {
	t.Helper()
	if s.db != nil {
		if err := s.db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sqlite.Open(t.Context(), s.path)
	if err != nil {
		t.Fatal(err)
	}
	s.db, s.repo, s.events = db, sqlec2.New(db), sqljournal.New(db)
}

func flowRecords(scope domain.Scope) (domain.FlowLogRecord, domain.FlowLogTokenRecord, domain.FlowLogAggregateRecord, domain.FlowLogDeliveryRecord, domain.FlowLogCaptureState) {
	key := domain.ResourceKey{Scope: scope, ID: "fl-same"}
	start := time.Date(2026, 10, 4, 12, 59, 58, 123456789, time.UTC)
	record := domain.FlowLogRecord{
		Key: key, Incarnation: "subscription-incarnation", ResourceID: "vpc-source", ResourceType: "VPC", TrafficType: "ALL",
		DestinationType: "s3", Destination: "arn:aws:s3:::flow-destination/prefix", LogGroupName: "retained-group", PermissionARN: "arn:aws:iam::111111111111:role/flow-delivery",
		LogFormat: "${version} ${interface-id} ${packets}", FormatVersion: 7, AggregationSeconds: 600, HivePartitions: true, HourPartitions: true,
		Tags:      api.TagList{{Key: new(api.String("second")), Value: new(api.String("2"))}, {Key: new(api.String("first"))}},
		CreatedAt: start, Status: "ACTIVE", DeliveryStatus: "FAILED", DeliveryError: "access denied", CaptureError: "native capture unavailable", Version: ^uint64(0),
	}
	token := domain.FlowLogTokenRecord{Key: domain.FlowLogTokenKey{Scope: scope, Token: "retained-token"}, Fingerprint: "exact-admission-fingerprint", Results: []domain.FlowLogAdmissionResult{{ResourceID: record.ResourceID, FlowLogID: key.ID}, {ResourceID: "vpc-absent", ErrorCode: "InvalidVpcID.NotFound", ErrorMessage: "no VPC"}}}
	// Shared-subnet observations retain the participant's ENI identity rather
	// than borrowing the subscription owner's account.
	participantScope := scope
	participantScope.AccountID = "999999999999"
	aggregate := domain.FlowLogAggregateRecord{
		Key: domain.FlowLogAggregateKey{FlowLogKey: key, ID: "directional-tuple"}, Incarnation: record.Incarnation,
		Interface:     domain.FlowLogInterface{Key: domain.ResourceKey{Scope: participantScope, ID: "eni-source"}, Incarnation: "native-incarnation", NetworkID: "native-network", Address: "10.0.0.8", VPCID: record.ResourceID, SubnetID: "subnet-source", InstanceID: "i-source", AvailabilityZoneID: "use1-az2"},
		SourceAddress: "2001:db8::1", DestinationAddress: "2001:db8::2", SourcePort: 65535, DestinationPort: 443, Protocol: 255, Action: "REJECT", Direction: "egress",
		Packets: ^uint64(0), Bytes: uint64(1)<<63 + 123, Start: start, End: start.Add(599 * time.Second), Due: start.Add(600 * time.Second), TCPFlags: 255, Lost: true,
	}
	delivery := domain.FlowLogDeliveryRecord{
		Key: domain.ResourceKey{Scope: scope, ID: "batch-stable"}, FlowLogKey: key, Incarnation: record.Incarnation,
		DestinationType: record.DestinationType, Destination: record.Destination, LogGroupName: record.LogGroupName, PermissionARN: record.PermissionARN,
		HivePartitions: true, HourPartitions: true, Header: "version interface-id packets", WindowStart: aggregate.End.UTC().Truncate(5 * time.Minute),
		Lines: []domain.FlowLogLine{{Start: start.Add(time.Second), InterfaceID: "eni-b", Message: "7 eni-b 17"}, {Start: start, InterfaceID: "eni-a", Message: "7 eni-a 19"}}, Due: start.Add(5 * time.Minute), Version: ^uint64(0),
	}
	return record, token, aggregate, delivery, domain.FlowLogCaptureState{Cursor: "native:opaque:retained", Due: start.Add(time.Minute), Version: ^uint64(0)}
}

func putFlowRecords(tx domain.Transaction, record domain.FlowLogRecord, token domain.FlowLogTokenRecord, aggregate domain.FlowLogAggregateRecord, delivery domain.FlowLogDeliveryRecord, capture domain.FlowLogCaptureState) error {
	if err := tx.PutFlowLog(record); err != nil {
		return err
	}
	if err := tx.PutFlowLogToken(token); err != nil {
		return err
	}
	if err := tx.PutFlowLogAggregate(aggregate); err != nil {
		return err
	}
	if err := tx.PutFlowLogDelivery(delivery); err != nil {
		return err
	}
	return tx.PutFlowLogCaptureState(capture)
}

func TestFlowLogDurableRoundtripScopingAndRetainedCursor(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			stores := openFlowStores(t, backend)
			scopes := []domain.Scope{{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, {Partition: "aws", AccountID: "222222222222", Region: "us-east-1"}, {Partition: "aws", AccountID: "111111111111", Region: "us-west-2"}, {Partition: "aws-cn", AccountID: "111111111111", Region: "us-east-1"}}
			for _, scope := range scopes {
				record, token, aggregate, delivery, capture := flowRecords(scope)
				if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error {
					return putFlowRecords(tx, record, token, aggregate, delivery, capture)
				}); err != nil {
					t.Fatal(err)
				}
			}
			if backend == "sqlite" {
				stores.reopen(t)
			}
			if err := stores.repo.View(t.Context(), func(r domain.Reader) error {
				all, err := r.InternalFlowLogs()
				if err != nil {
					return err
				}
				if len(all) != len(scopes) {
					t.Fatalf("internal subscriptions: %d", len(all))
				}
				deliveries, err := r.FlowLogDeliveries()
				if err != nil {
					return err
				}
				if len(deliveries) != len(scopes) {
					t.Fatalf("internal deliveries: %d", len(deliveries))
				}
				for _, scope := range scopes {
					record, token, aggregate, delivery, capture := flowRecords(scope)
					got, err := r.FlowLog(record.Key)
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(got, record) {
						t.Fatalf("subscription roundtrip:\n%+v\nwant %+v", got, record)
					}
					listed, err := r.FlowLogs(scope)
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(listed, []domain.FlowLogRecord{record}) {
						t.Fatalf("scope leaked subscriptions: %+v", listed)
					}
					admitted, err := r.FlowLogToken(token.Key)
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(admitted, token) {
						t.Fatalf("admission order/fields: %+v", admitted)
					}
					aggregates, err := r.FlowLogAggregates(record.Key)
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(aggregates, []domain.FlowLogAggregateRecord{aggregate}) {
						t.Fatalf("tuple/metrics/clocks/loss: %+v", aggregates)
					}
					found := false
					for _, row := range deliveries {
						if row.Key == delivery.Key {
							found = true
							if !reflect.DeepEqual(row, delivery) {
								t.Fatalf("sealed delivery roundtrip: %+v", row)
							}
						}
					}
					if !found {
						t.Fatal("delivery missing")
					}
					checkpoint, err := r.FlowLogCaptureState()
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(checkpoint, capture) {
						t.Fatalf("global checkpoint changed: %+v", checkpoint)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			record, token, _, delivery, capture := flowRecords(scopes[0])
			// A retry may change scheduling, but must never rewrite the sealed payload.
			retry := delivery
			retry.Due, retry.Version = retry.Due.Add(time.Minute), 3
			retry.Destination, retry.Header, retry.Lines = "changed", "changed", nil
			retry.WindowStart = retry.WindowStart.Add(time.Hour)
			if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutFlowLogDelivery(retry) }); err != nil {
				t.Fatal(err)
			}
			if err := stores.repo.View(t.Context(), func(r domain.Reader) error {
				rows, err := r.FlowLogDeliveries()
				if err != nil {
					return err
				}
				delivery.Due, delivery.Version = retry.Due, retry.Version
				for _, row := range rows {
					if row.Key == delivery.Key && !reflect.DeepEqual(row, delivery) {
						t.Fatalf("retry changed immutable batch: %+v", row)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.DeleteFlowLog(record.Key) }); err != nil {
				t.Fatal(err)
			}
			if backend == "sqlite" {
				stores.reopen(t)
			}
			if err := stores.repo.View(t.Context(), func(r domain.Reader) error {
				if _, err := r.FlowLog(record.Key); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("deleted subscription: %v", err)
				}
				aggregates, err := r.FlowLogAggregates(record.Key)
				if err != nil {
					return err
				}
				if len(aggregates) != 0 {
					t.Fatal("deleted subscription retained aggregates")
				}
				rows, err := r.FlowLogDeliveries()
				if err != nil {
					return err
				}
				if len(rows) != len(scopes)-1 {
					t.Fatalf("delete crossed scopes or retained work: %+v", rows)
				}
				got, err := r.FlowLogToken(token.Key)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(got, token) {
					t.Fatal("subscription deletion changed admission")
				}
				checkpoint, err := r.FlowLogCaptureState()
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(checkpoint, capture) {
					t.Fatal("deletion rewound global cursor")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFlowLogStateWorkAndOutboxRollbackTogether(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			stores := openFlowStores(t, backend)
			scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			record, token, aggregate, delivery, capture := flowRecords(scope)
			rollback := errors.New("reject transaction")
			appendEvent := func(tx domain.Transaction, id string) error {
				return stores.events.AppendAPICallCompleted(tx.Context(), journal.Envelope{At: record.CreatedAt, Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, RequestID: id}, journal.APICallCompleted{EventID: id, EventSource: "ec2.amazonaws.com", EventName: "CreateFlowLogs", Category: journal.CategoryManagement, RequestParameters: json.RawMessage(`{}`), ResponseElements: json.RawMessage(`{}`)})
			}
			err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := putFlowRecords(tx, record, token, aggregate, delivery, capture); err != nil {
					return err
				}
				if err := appendEvent(tx, "rolled-back"); err != nil {
					return err
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatalf("rollback error: %v", err)
			}
			if err := stores.repo.View(t.Context(), func(r domain.Reader) error {
				if _, err := r.FlowLog(record.Key); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("subscription escaped rollback: %v", err)
				}
				if _, err := r.FlowLogToken(token.Key); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("admission escaped rollback: %v", err)
				}
				if _, err := r.FlowLogCaptureState(); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("cursor escaped rollback: %v", err)
				}
				aggregates, err := r.FlowLogAggregates(record.Key)
				if err != nil {
					return err
				}
				deliveries, err := r.FlowLogDeliveries()
				if err != nil {
					return err
				}
				if len(aggregates)+len(deliveries) != 0 {
					t.Fatal("work escaped rollback")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			events, err := stores.events.Read(t.Context(), 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 0 {
				t.Fatal("outbox escaped rollback")
			}
			if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := putFlowRecords(tx, record, token, aggregate, delivery, capture); err != nil {
					return err
				}
				return appendEvent(tx, "committed")
			}); err != nil {
				t.Fatal(err)
			}
			// Cursor advance, aggregate retirement and batch completion share one commit.
			err = stores.repo.Update(t.Context(), func(tx domain.Transaction) error {
				next := capture
				next.Cursor, next.Version = "uncommitted-cursor", 7
				if err := tx.PutFlowLogCaptureState(next); err != nil {
					return err
				}
				if err := tx.DeleteFlowLogAggregate(aggregate.Key); err != nil {
					return err
				}
				if err := tx.DeleteFlowLogDelivery(delivery.Key); err != nil {
					return err
				}
				if err := appendEvent(tx, "uncommitted-completion"); err != nil {
					return err
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatalf("completion rollback: %v", err)
			}
			if backend == "sqlite" {
				stores.reopen(t)
			}
			if err := stores.repo.View(t.Context(), func(r domain.Reader) error {
				got, err := r.FlowLogCaptureState()
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(got, capture) {
					t.Fatal("cursor committed without work")
				}
				aggregates, err := r.FlowLogAggregates(record.Key)
				if err != nil {
					return err
				}
				deliveries, err := r.FlowLogDeliveries()
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(aggregates, []domain.FlowLogAggregateRecord{aggregate}) || !reflect.DeepEqual(deliveries, []domain.FlowLogDeliveryRecord{delivery}) {
					t.Fatal("completion escaped rollback")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			events, err = stores.events.Read(t.Context(), 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 1 || events[0].APICallCompleted.EventID != "committed" {
				t.Fatalf("outbox atomicity: %+v", events)
			}
		})
	}
}

func TestFlowLogMigrationPreservesRetainedEC2State(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retained.sqlite")
	db := awstest.HistoricalSQLite(t, path, "../schema", 427, "", nil)
	scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO ec2_sequences (partition, account_id, region, prefix, sequence) VALUES (?, ?, ?, ?, ?)`, scope.Partition, scope.AccountID, scope.Region, "fl", sqlite.Uint64(41)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := sqlec2.New(db)
	record, token, aggregate, delivery, capture := flowRecords(scope)
	if err := repository.Update(t.Context(), func(tx domain.Transaction) error {
		id, err := tx.NextID(scope, "fl")
		if err != nil {
			return err
		}
		expected, err := domain.FormatResourceID(scope, "fl", 42)
		if err != nil {
			return err
		}
		if id != expected {
			t.Fatalf("migration rewound retained sequence: %s, want %s", id, expected)
		}
		if _, err := tx.FlowLogCaptureState(); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("upgrade invented capture cursor: %v", err)
		}
		return putFlowRecords(tx, record, token, aggregate, delivery, capture)
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(t.Context(), func(r domain.Reader) error {
		got, err := r.FlowLog(record.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, record) {
			t.Fatal("retained database cannot persist flow logs")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFlowLogOrderedChildrenReplacementAndCompletion(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			stores := openFlowStores(t, backend)
			scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			record, token, aggregate, delivery, capture := flowRecords(scope)
			if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error {
				return putFlowRecords(tx, record, token, aggregate, delivery, capture)
			}); err != nil {
				t.Fatal(err)
			}
			for _, empty := range []bool{true, false} {
				record.Tags, token.Results = nil, nil
				if empty {
					record.Tags, token.Results = api.TagList{}, []domain.FlowLogAdmissionResult{}
				}
				if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error {
					if err := tx.PutFlowLog(record); err != nil {
						return err
					}
					return tx.PutFlowLogToken(token)
				}); err != nil {
					t.Fatal(err)
				}
				if backend == "sqlite" {
					stores.reopen(t)
				}
				if err := stores.repo.View(t.Context(), func(r domain.Reader) error {
					got, err := r.FlowLog(record.Key)
					if err != nil {
						return err
					}
					admitted, err := r.FlowLogToken(token.Key)
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(got.Tags, record.Tags) || !reflect.DeepEqual(admitted.Results, token.Results) {
						t.Fatalf("nil/empty replacement retained stale children: %+v %+v", got.Tags, admitted.Results)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			// Completion removes only the named scoped aggregate and batch, and does
			// not require rewinding the globally committed native checkpoint.
			if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.DeleteFlowLogAggregate(aggregate.Key); err != nil {
					return err
				}
				if err := tx.DeleteFlowLogDelivery(delivery.Key); err != nil {
					return err
				}
				return tx.DeleteFlowLog(record.Key)
			}); err != nil {
				t.Fatal(err)
			}
			if backend == "sqlite" {
				stores.reopen(t)
			}
			if err := stores.repo.View(t.Context(), func(r domain.Reader) error {
				logs, err := r.InternalFlowLogs()
				if err != nil {
					return err
				}
				work, err := r.FlowLogDeliveries()
				if err != nil {
					return err
				}
				checkpoint, err := r.FlowLogCaptureState()
				if err != nil {
					return err
				}
				if len(logs)+len(work) != 0 || !reflect.DeepEqual(checkpoint, capture) {
					t.Fatalf("last subscription deletion lost retained checkpoint: %+v", checkpoint)
				}
				admitted, err := r.FlowLogToken(token.Key)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(admitted, token) {
					t.Fatal("last subscription deletion erased token")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for _, remove := range []func(domain.Transaction) error{
				func(tx domain.Transaction) error { return tx.DeleteFlowLog(record.Key) },
				func(tx domain.Transaction) error { return tx.DeleteFlowLogAggregate(aggregate.Key) },
				func(tx domain.Transaction) error { return tx.DeleteFlowLogDelivery(delivery.Key) },
			} {
				if err := stores.repo.Update(t.Context(), remove); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("missing deletion: %v", err)
				}
			}
		})
	}
}
