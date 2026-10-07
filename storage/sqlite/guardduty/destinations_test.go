package guardduty_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	domain "stackd/storage/guardduty"
)

func destinationRecords(sc domain.Scope, id, finding string) (domain.PublishingDestination, domain.FindingExport) {
	d, _, _ := records(sc)
	v := domain.PublishingDestination{CFNOwnership: domain.CloudFormationOwnership{Owner: "destination-owner", Token: "destination-incarnation"}, Scope: sc, DetectorID: d.ID, ID: id, ARN: d.ARN + "/publishingdestination/" + id, Type: "S3", ClientToken: "token-" + id, DestinationARN: "arn:aws:s3:::findings/prefix", KMSKeyARN: "arn:aws:kms:us-east-1:111111111111:key/key", Status: "UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY", Version: 7, Created: d.Created, Updated: d.Updated, FailureStarted: d.Updated.Add(time.Minute), Tags: map[string]string{"owner": "security"}}
	e := domain.FindingExport{Scope: sc, DetectorID: d.ID, DestinationID: id, FindingID: finding, ID: "export-" + finding, ObjectKey: "AWSLogs/" + finding, DestinationVersion: 7, Version: 9, Created: d.Created, Due: d.Updated.Add(time.Hour), LastPublished: d.Created.Add(-time.Hour), Payload: []byte(`{"id":"` + finding + `"}`)}
	e.ParentEventID = "source-" + finding
	return v, e
}

func TestPublishingDestinationDurabilityIsolationRollbackAndCascades(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			repo, reopen := repository(t, kind)
			scopes := []domain.Scope{
				{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"},
				{Partition: "aws-cn", AccountID: "111111111111", Region: "us-east-1"},
				{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"},
				{Partition: "aws", AccountID: "111111111111", Region: "us-west-2"},
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			seed := func(tx domain.Transaction, sc domain.Scope) error {
				d, f, _ := records(sc)
				if err := tx.PutDetector(d); err != nil {
					return err
				}
				for _, fid := range []string{"z", "a"} {
					f.ID = fid
					if err := tx.PutFinding(f); err != nil {
						return err
					}
				}
				for _, id := range []string{"z", "a"} {
					v, _ := destinationRecords(sc, id, "a")
					if err := tx.PutPublishingDestination(v); err != nil {
						return err
					}
					v.Tags["owner"] = "mutated"
					for _, fid := range []string{"z", "a"} {
						_, e := destinationRecords(sc, id, fid)
						if err := tx.PutFindingExport(e); err != nil {
							return err
						}
						e.Payload[0] = '!'
					}
				}
				return nil
			}
			must(repo.Update(t.Context(), func(tx domain.Transaction) error {
				for _, sc := range scopes {
					if err := seed(tx, sc); err != nil {
						return err
					}
				}
				return nil
			}))
			repo = reopen()
			assertScope := func(sc domain.Scope) {
				t.Helper()
				must(repo.View(t.Context(), func(r domain.Reader) error {
					all, err := r.PublishingDestinations(sc, "detector")
					if err != nil {
						return err
					}
					a, _ := destinationRecords(sc, "a", "a")
					z, _ := destinationRecords(sc, "z", "a")
					if !reflect.DeepEqual(all, []domain.PublishingDestination{a, z}) {
						t.Fatalf("destinations = %#v", all)
					}
					all[0].Tags["owner"] = "mutated"
					got, err := r.PublishingDestination(sc, "detector", "a")
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(got, a) {
						t.Fatalf("destination read isolation: %#v", got)
					}
					got.Tags["owner"] = "mutated"
					for _, id := range []string{"a", "z"} {
						exports, err := r.FindingExports(sc, "detector", id)
						if err != nil {
							return err
						}
						_, ea := destinationRecords(sc, id, "a")
						_, ez := destinationRecords(sc, id, "z")
						if !reflect.DeepEqual(exports, []domain.FindingExport{ea, ez}) {
							t.Fatalf("exports = %#v", exports)
						}
						exports[0].Payload[0] = '!'
						e, err := r.FindingExport(sc, "detector", id, "a")
						if err != nil {
							return err
						}
						if !reflect.DeepEqual(e, ea) {
							t.Fatalf("export read isolation: %#v", e)
						}
						e.Payload[0] = '!'
					}
					return nil
				}))
			}
			for _, sc := range scopes {
				assertScope(sc)
				assertScope(sc)
			}
			rollback := errors.New("rollback")
			err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				v, e := destinationRecords(scopes[0], "a", "a")
				v.Tags = nil
				v.Status = "PUBLISHING"
				v.FailureStarted = time.Time{}
				e.Payload = nil
				e.Due = time.Time{}
				if err := tx.PutPublishingDestination(v); err != nil {
					return err
				}
				if err := tx.PutFindingExport(e); err != nil {
					return err
				}
				if err := tx.DeletePublishingDestination(scopes[0], "detector", "z"); err != nil {
					return err
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			assertScope(scopes[0])
			// Replacement retains caller-supplied health and completed cursor state.
			v, e := destinationRecords(scopes[0], "a", "a")
			v.Tags = map[string]string{}
			v.Status = "PUBLISHING"
			v.Version++
			v.FailureStarted = time.Time{}
			e.Payload = nil
			e.Due = time.Time{}
			e.LastPublished = e.Created.Add(time.Hour)
			must(repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutPublishingDestination(v); err != nil {
					return err
				}
				return tx.PutFindingExport(e)
			}))
			repo = reopen()
			must(repo.View(t.Context(), func(r domain.Reader) error {
				got, err := r.PublishingDestination(v.Scope, v.DetectorID, v.ID)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(got, v) {
					t.Fatalf("replacement = %#v", got)
				}
				cursor, err := r.FindingExport(e.Scope, e.DetectorID, e.DestinationID, e.FindingID)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(cursor, e) {
					t.Fatalf("completed cursor = %#v", cursor)
				}
				return nil
			}))
			must(repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.DeleteFinding(scopes[0], "detector", "a"); err != nil {
					return err
				}
				if err := tx.DeletePublishingDestination(scopes[1], "detector", "a"); err != nil {
					return err
				}
				if err := tx.DeleteDetector(scopes[2], "detector"); err != nil {
					return err
				}
				return tx.DeleteDestinationExports(scopes[3], "detector", "a")
			}))
			repo = reopen()
			must(repo.View(t.Context(), func(r domain.Reader) error {
				for i, sc := range scopes {
					destinations, err := r.PublishingDestinations(sc, "detector")
					if err != nil {
						return err
					}
					want := 2
					if i == 1 {
						want = 1
					}
					if i == 2 {
						want = 0
					}
					if len(destinations) != want {
						t.Fatalf("scope %d destinations: %#v", i, destinations)
					}
					for _, id := range []string{"a", "z"} {
						exports, err := r.FindingExports(sc, "detector", id)
						if err != nil {
							return err
						}
						wantIDs := []string{"a", "z"}
						if i == 0 {
							wantIDs = []string{"z"}
						}
						if i == 2 || ((i == 1 || i == 3) && id == "a") {
							wantIDs = nil
						}
						var ids []string
						for _, export := range exports {
							ids = append(ids, export.FindingID)
						}
						if !reflect.DeepEqual(ids, wantIDs) {
							t.Fatalf("scope %d destination %s exports = %v", i, id, ids)
						}
					}
				}
				return nil
			}))
			must(repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.DeleteFindingExport(scopes[3], "detector", "z", "a") }))
			must(repo.View(t.Context(), func(r domain.Reader) error {
				if _, err := r.FindingExport(scopes[3], "detector", "z", "a"); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("deleted export: %v", err)
				}
				_, err := r.FindingExport(scopes[3], "detector", "z", "z")
				return err
			}))
		})
	}
}

func TestPublishingDestinationOrphansAndExpiredMemoryTransactions(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			repo, _ := repository(t, kind)
			sc := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			v, e := destinationRecords(sc, "destination", "finding")
			var retained domain.Transaction
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				retained = tx
				if err := tx.PutPublishingDestination(v); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("orphan destination: %v", err)
				}
				d, f, _ := records(sc)
				if err := tx.PutDetector(d); err != nil {
					return err
				}
				if err := tx.PutFindingExport(e); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("orphan export: %v", err)
				}
				if err := tx.PutPublishingDestination(v); err != nil {
					return err
				}
				if err := tx.PutFindingExport(e); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("missing finding: %v", err)
				}
				if err := tx.PutFinding(f); err != nil {
					return err
				}
				return tx.PutFindingExport(e)
			}); err != nil {
				t.Fatal(err)
			}
			if kind != "memory" {
				return
			}
			checks := []func() error{
				func() error { _, err := retained.PublishingDestination(sc, "detector", v.ID); return err },
				func() error { _, err := retained.PublishingDestinations(sc, "detector"); return err },
				func() error { _, err := retained.FindingExport(sc, "detector", v.ID, e.FindingID); return err },
				func() error { _, err := retained.FindingExports(sc, "detector", v.ID); return err },
				func() error { _, err := retained.NextFindingExport(sc, "detector", v.ID); return err },
				func() error { return retained.PutPublishingDestination(v) },
				func() error { return retained.PutFindingExport(e) },
				func() error { return retained.DeletePublishingDestination(sc, "detector", v.ID) },
				func() error { return retained.DeleteFindingExport(sc, "detector", v.ID, e.FindingID) },
				func() error { return retained.DeleteDestinationExports(sc, "detector", v.ID) },
			}
			for i, check := range checks {
				if err := check(); err == nil {
					t.Fatalf("expired operation %d succeeded", i)
				}
			}
		})
	}
}

func TestFindingExportDeadlinesOrderAndCompletion(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			repo, reopen := repository(t, kind)
			sc := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			d, f, _ := records(sc)
			destination, base := destinationRecords(sc, "destination", "a")
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutDetector(d); err != nil {
					return err
				}
				if err := tx.PutPublishingDestination(destination); err != nil {
					return err
				}
				for _, id := range []string{"z", "later", "completed", "a"} {
					f.ID = id
					if err := tx.PutFinding(f); err != nil {
						return err
					}
					row := base
					row.FindingID, row.ID = id, "export-"+id
					if id == "completed" {
						row.Due = time.Time{}
					}
					if id == "later" {
						row.Due = row.Due.Add(time.Second)
					}
					if err := tx.PutFindingExport(row); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			repo = reopen()
			for _, want := range []string{"a", "z", "later"} {
				if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
					next, err := tx.NextFindingExport(sc, d.ID, destination.ID)
					if err != nil {
						return err
					}
					if next.FindingID != want || next.ID != "export-"+want || next.Version != base.Version {
						t.Fatalf("next deadline = %+v; want finding %s", next, want)
					}
					row, err := tx.FindingExport(sc, d.ID, destination.ID, want)
					if err != nil {
						return err
					}
					if !next.Due.Equal(row.Due) {
						t.Fatalf("deadline changed: %v != %v", next.Due, row.Due)
					}
					row.Due, row.Payload = time.Time{}, nil
					return tx.PutFindingExport(row)
				}); err != nil {
					t.Fatal(err)
				}
			}
			if err := repo.View(t.Context(), func(r domain.Reader) error {
				if _, err := r.NextFindingExport(sc, d.ID, destination.ID); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("completed publications remained scheduled: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
