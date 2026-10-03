package guardduty_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	domain "stackd/storage/guardduty"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/guardduty"
)

func TestThreatEvidenceIsolationReplacementAndRollback(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			repo, reopen := repository(t, kind)
			scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			detector, base, _ := records(scope)
			base.SampleType, base.SampleRevision = "", ""
			base.Observation = domain.Observation{Type: "Recon:IAMUser/MaliciousIPCaller.Custom", EventID: "original", API: "ListBuckets", SourceIP: "192.0.2.10"}
			want := make([]domain.Finding, 3)
			for i, id := range []string{"a", "b", "c"} {
				want[i] = base
				want[i].ID = id
			}
			want[0].Observation.ThreatListNames = []string{"second-feed", "first-feed"}
			want[2].Observation.ThreatListNames = []string{"third-feed"}
			want[2].Observation.ResourceType = "AWS::S3::Bucket"
			want[2].Observation.ResourceName = "actual-bucket"
			want[2].Observation.ResourceARN = "arn:aws:s3:::actual-bucket"
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutDetector(detector); err != nil {
					return err
				}
				for _, v := range want {
					v.Observation.ThreatListNames = slices.Clone(v.Observation.ThreatListNames)
					if err := tx.PutFinding(v); err != nil {
						return err
					}
					if len(v.Observation.ThreatListNames) > 0 {
						v.Observation.ThreatListNames[0] = "caller mutation"
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			assertEvidence := func() {
				t.Helper()
				if err := repo.View(t.Context(), func(r domain.Reader) error {
					all, err := r.Findings(scope, detector.ID)
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(all, want) {
						t.Fatalf("bulk findings = %#v, want %#v", all, want)
					}
					for _, expected := range want {
						got, err := r.Finding(scope, detector.ID, expected.ID)
						if err != nil {
							return err
						}
						if !reflect.DeepEqual(got, expected) {
							t.Fatalf("finding %s = %#v, want %#v", expected.ID, got, expected)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			assertEvidence()
			var snapshot domain.Finding
			if err := repo.View(t.Context(), func(r domain.Reader) error {
				var err error
				snapshot, err = r.Finding(scope, detector.ID, "a")
				if err != nil {
					return err
				}
				single, err := r.Finding(scope, detector.ID, "a")
				if err != nil {
					return err
				}
				single.Observation.ThreatListNames[0] = "single read mutation"
				all, err := r.Findings(scope, detector.ID)
				if err != nil {
					return err
				}
				all[2].Observation.ThreatListNames[0] = "bulk read mutation"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			assertEvidence()
			rejected := errors.New("reject evidence replacement")
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				v, err := tx.Finding(scope, detector.ID, "a")
				if err != nil {
					return err
				}
				v.Observation.ThreatListNames[0] = "rolled back feed"
				v.Observation.EventID = "rolled back event"
				if err := tx.PutFinding(v); err != nil {
					return err
				}
				if err := tx.DeleteFinding(scope, detector.ID, "c"); err != nil {
					return err
				}
				return rejected
			}); !errors.Is(err, rejected) {
				t.Fatalf("rollback error = %v", err)
			}
			repo = reopen()
			assertEvidence()
			want[0].Observation.ThreatListNames = []string{"replacement-feed"}
			want[0].Observation.EventID = "latest event"
			want[2].Observation.ThreatListNames = nil
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutFinding(want[0]); err != nil {
					return err
				}
				return tx.PutFinding(want[2])
			}); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(snapshot.Observation.ThreatListNames, []string{"second-feed", "first-feed"}) {
				t.Fatalf("old snapshot changed: %#v", snapshot.Observation)
			}
			repo = reopen()
			assertEvidence()
			// Sample replacement discards real occurrence evidence, even when the
			// caller reuses a previously observed finding value.
			sample := want[0]
			sample.SampleType, sample.SampleRevision = "Recon:EC2/PortProbeUnprotectedPort", "immutable-corpus-v1"
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutFinding(sample) }); err != nil {
				t.Fatal(err)
			}
			want[0] = sample
			want[0].Observation = domain.Observation{}
			repo = reopen()
			assertEvidence()
			// Returning to an observation without names must not revive old rows.
			want[0].SampleType, want[0].SampleRevision = "", ""
			want[0].Observation = base.Observation
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutFinding(want[0]) }); err != nil {
				t.Fatal(err)
			}
			assertEvidence()
		})
	}
}

func TestThreatEvidenceSQLiteCascade(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "evidence.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	detector, finding, _ := records(scope)
	finding.SampleType, finding.SampleRevision = "", ""
	finding.Observation = domain.Observation{Type: "Recon:IAMUser/MaliciousIPCaller.Custom", ThreatListNames: []string{"feed-a", "feed-b"}}
	for _, deletion := range []string{"observation", "sample", "finding", "detector"} {
		t.Run(deletion, func(t *testing.T) {
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutDetector(detector); err != nil {
					return err
				}
				return tx.PutFinding(finding)
			}); err != nil {
				t.Fatal(err)
			}
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				switch deletion {
				case "observation":
					v := finding
					v.Observation = domain.Observation{}
					return tx.PutFinding(v)
				case "sample":
					v := finding
					v.SampleRevision = "immutable-corpus-v1"
					return tx.PutFinding(v)
				case "finding":
					return tx.DeleteFinding(scope, detector.ID, finding.ID)
				default:
					return tx.DeleteDetector(scope, detector.ID)
				}
			}); err != nil {
				t.Fatal(err)
			}
			var remaining int
			if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM guardduty_observation_threat_lists").Scan(&remaining); err != nil {
				t.Fatal(err)
			}
			if remaining != 0 {
				t.Fatalf("%s deletion left %d orphaned threat-list names", deletion, remaining)
			}
		})
	}
}
