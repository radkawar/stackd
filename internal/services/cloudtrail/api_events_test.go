package cloudtrail_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/services/cloudtrail"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlitetrail "stackd/storage/sqlite/cloudtrail"
	sqlitejournal "stackd/storage/sqlite/journal"
)

type deliveryWakeCounter struct{ calls int }

func (w *deliveryWakeCounter) Wake() { w.calls++ }

type failedAuditPublisher struct{}

func (failedAuditPublisher) PublishAPICall(context.Context, journal.Event) error {
	return errors.New("injected publication failure after delivery admission")
}

type deliveryOrganizationView struct{ deniedRegion string }

func (deliveryOrganizationView) Organization(context.Context, string, string) (cloudtrail.Organization, error) {
	return cloudtrail.Organization{ID: "o-example", ManagementAccountID: "example-account", AllFeatures: true, TrustedAccess: true}, nil
}

func (v deliveryOrganizationView) RegionEnabled(_ context.Context, _, _, region string) (bool, error) {
	return region != v.deniedRegion, nil
}

func (deliveryOrganizationView) DigestScopes(context.Context, cloudtrail.TrailRecord) ([]cloudtrail.Scope, error) {
	return nil, nil
}

func TestAPIEventsWakeOnlyAdmittedDeliveries(t *testing.T) {
	epoch := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
	cases := []struct {
		name         string
		noTrail      bool
		configure    func(*cloudtrail.TrailRecord, *journal.Envelope, *journal.APICallCompleted)
		failure      string
		wantS3       bool
		wantLogs     bool
		deniedRegion string
		rollback     bool
	}{
		{name: "no_trails", noTrail: true},
		{name: "stopped", configure: func(trail *cloudtrail.TrailRecord, _ *journal.Envelope, _ *journal.APICallCompleted) {
			trail.Logging = false
		}},
		{name: "unmatched_selector", configure: func(trail *cloudtrail.TrailRecord, _ *journal.Envelope, _ *journal.APICallCompleted) {
			trail.Selection.Basic[0].DataResources[0].ARNPrefixes = []string{"arn:aws:s3:::other-bucket/"}
		}},
		{name: "unmatched_region", configure: func(_ *cloudtrail.TrailRecord, envelope *journal.Envelope, _ *journal.APICallCompleted) {
			envelope.Region = "us-west-2"
		}},
		{name: "recursive_delivery", configure: func(_ *cloudtrail.TrailRecord, envelope *journal.Envelope, call *journal.APICallCompleted) {
			envelope.ActorService = "cloudtrail.amazonaws.com"
			call.EventName = "PutObject"
			call.ReadOnly = false
		}},
		{name: "organization_region_enabled", wantS3: true, configure: func(trail *cloudtrail.TrailRecord, _ *journal.Envelope, _ *journal.APICallCompleted) {
			trail.OrganizationID = "o-example"
		}},
		{name: "organization_home_region_disabled", deniedRegion: "us-east-1", configure: func(trail *cloudtrail.TrailRecord, _ *journal.Envelope, _ *journal.APICallCompleted) {
			trail.OrganizationID = "o-example"
		}},
		{name: "organization_event_region_disabled", deniedRegion: "us-west-2", configure: func(trail *cloudtrail.TrailRecord, envelope *journal.Envelope, _ *journal.APICallCompleted) {
			trail.OrganizationID = "o-example"
			trail.MultiRegion = true
			envelope.Region = "us-west-2"
		}},
		{name: "borrowed_outer_rollback", rollback: true},
		{name: "active", wantS3: true},
		{name: "stop_propagating", wantS3: true, configure: func(trail *cloudtrail.TrailRecord, _ *journal.Envelope, _ *journal.APICallCompleted) {
			trail.Logging = false
			deadline := epoch.Add(time.Minute)
			trail.StopAfter = &deadline
		}},
		{name: "stop_effective", configure: func(trail *cloudtrail.TrailRecord, _ *journal.Envelope, _ *journal.APICallCompleted) {
			trail.Logging = false
			trail.StopAfter = &epoch
		}},
		{name: "multiple_destinations", wantS3: true, wantLogs: true, configure: func(trail *cloudtrail.TrailRecord, _ *journal.Envelope, _ *journal.APICallCompleted) {
			trail.LogsGroupARN = "arn:aws:logs:us-east-1:example-account:log-group:trail"
			trail.LogsRoleARN = "arn:aws:iam::example-account:role/trail"
		}},
		{name: "journal_failure", failure: "journal"},
		{name: "publication_failure", failure: "publication"},
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					domain := memory.NewDomain()
					var repository cloudtrail.Repository = cloudtrail.NewMemoryRepository(domain)
					events := journal.NewMemory(domain)
					if backend == "sqlite" {
						db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.sqlite"))
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = db.Close() })
						repository = sqlitetrail.New(db)
						events = sqlitejournal.New(db)
					}
					scope := cloudtrail.Scope{Partition: "aws", AccountID: "example-account", Region: "us-east-1"}
					trail := cloudtrail.TrailRecord{
						Key: cloudtrail.TrailKey{Scope: scope, Name: "delivery"}, ID: "trail-id",
						Bucket: "trail-logs", Logging: true, Created: epoch, Modified: epoch,
						Selection: cloudtrail.Selection{Basic: []cloudtrail.BasicSelector{{
							DataResources: []cloudtrail.DataResource{{Type: "AWS::S3::Object", ARNPrefixes: []string{"arn:aws:s3:::data-bucket/"}}},
						}}},
					}
					envelope := journal.Envelope{At: epoch, Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}
					call := journal.APICallCompleted{
						EventID: "object-read", EventSource: "s3.amazonaws.com", EventName: "GetObject", Category: "Data", ReadOnly: true,
						EventResources: []journal.APIEventResource{{AccountID: scope.AccountID, Type: "AWS::S3::Object", ARN: "arn:aws:s3:::data-bucket/key"}},
					}
					if tc.configure != nil {
						tc.configure(&trail, &envelope, &call)
					}
					if !tc.noTrail {
						if err := repository.Update(t.Context(), func(tx cloudtrail.Transaction) error { return tx.PutTrail(trail) }); err != nil {
							t.Fatal(err)
						}
					}
					waker := &deliveryWakeCounter{}
					var sink apievents.Sink = events
					if tc.failure == "journal" {
						sink = failedAudit{events}
					}
					observer := cloudtrail.APIEvents{Repository: repository, Journal: sink, Clock: clock.NewManual(epoch), Jobs: waker}
					observer.Organizations = deliveryOrganizationView{deniedRegion: tc.deniedRegion}
					if tc.failure == "publication" {
						observer.Publisher = failedAuditPublisher{}
					}
					var err error
					if tc.rollback {
						abort := errors.New("reject outer command after admission")
						err = repository.Update(t.Context(), func(tx cloudtrail.Transaction) error {
							if err := observer.AppendAPICallCompleted(tx.Context(), envelope, call); err != nil {
								return err
							}
							if _, found, err := tx.NextDelivery(); err != nil || !found {
								t.Fatalf("borrowed admission was not staged: found=%v err=%v", found, err)
							}
							rows, err := events.ReadAPICalls(tx.Context(), []string{call.EventID})
							if err != nil || len(rows) != 1 {
								t.Fatalf("borrowed journal was not staged: rows=%v err=%v", rows, err)
							}
							return abort
						})
						if !errors.Is(err, abort) {
							t.Fatalf("outer rollback error = %v, want %v", err, abort)
						}
						err = nil
					} else {
						err = observer.AppendAPICallCompleted(t.Context(), envelope, call)
					}
					if (err != nil) != (tc.failure != "") {
						t.Fatalf("append error = %v, failure = %q", err, tc.failure)
					}
					wantWakes := 0
					// A borrowed admission may wake before its owner rolls back.
					// The wake is only a hint: no journal/delivery may survive it.
					if tc.wantS3 || tc.wantLogs || tc.rollback {
						wantWakes = 1
					}
					if waker.calls != wantWakes {
						t.Fatalf("scheduler wakes = %d, want %d", waker.calls, wantWakes)
					}
					rows, err := events.ReadAPICalls(t.Context(), []string{call.EventID})
					if err != nil {
						t.Fatal(err)
					}
					if tc.failure != "" || tc.rollback {
						if len(rows) != 0 {
							t.Fatal("failed admission retained its journal event")
						}
					} else if len(rows) != 1 || rows[0].APICallCompleted.EventID != call.EventID || rows[0].APICallCompleted.ReadOnly != call.ReadOnly {
						t.Fatalf("immutable journal outcome not retained: %+v", rows)
					}
					if err := repository.View(t.Context(), func(reader cloudtrail.Reader) error {
						_, found, err := reader.NextDelivery()
						if err != nil {
							return err
						}
						if found != (tc.wantS3 || tc.wantLogs) {
							t.Fatalf("pending delivery = %v, want %v", found, tc.wantS3 || tc.wantLogs)
						}
						for _, destination := range []struct {
							kind cloudtrail.DestinationKind
							want bool
						}{
							{cloudtrail.DestinationS3, tc.wantS3},
							{cloudtrail.DestinationLogs, tc.wantLogs},
						} {
							delivery, err := reader.OpenDelivery(trail.ID, envelope.AccountID, envelope.Region, destination.kind)
							if !destination.want {
								if !errors.Is(err, cloudtrail.ErrNotFound) {
									t.Fatalf("unexpected %s delivery: %+v, %v", destination.kind, delivery, err)
								}
								continue
							}
							if err != nil {
								return err
							}
							ids, err := reader.DeliveryEventIDs(delivery.ID)
							if err != nil {
								return err
							}
							if delivery.EventCount != 1 || len(ids) != 1 || ids[0] != call.EventID {
								t.Fatalf("%s delivery lost its journal reference: %+v, %v", destination.kind, delivery, ids)
							}
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}
