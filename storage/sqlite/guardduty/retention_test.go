package guardduty_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/guardduty"
	service "stackd/internal/services/guardduty"
	domain "stackd/storage/guardduty"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/guardduty"
)

const retentionWindow = 90 * 24 * time.Hour

func retentionRecords() (domain.Detector, domain.Finding) {
	detector, finding, _ := records(domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	finding.SampleType, finding.SampleRevision = "", ""
	finding.Updated, finding.Count = finding.Created, 1
	finding.Archived, finding.Feedback = false, ""
	finding.Observation = domain.Observation{
		Type: "Stealth:IAMUser/CloudTrailLoggingDisabled", Title: "CloudTrail logging disabled",
		Description: "Observed successful StopLogging API call", Severity: 8.5,
		EventID: "retained-event", API: "StopLogging", ServiceName: "cloudtrail.amazonaws.com",
		UserType: "IAMUser", PrincipalID: "principal", ResourceType: "AWS::CloudTrail::Trail", ResourceName: "trail",
	}
	return detector, finding
}

func seedRetention(t *testing.T, repo domain.Repository, detector domain.Detector, findings ...domain.Finding) {
	t.Helper()
	if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutDetector(detector); err != nil {
			return err
		}
		for _, finding := range findings {
			if err := tx.PutFinding(finding); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertRetainedFinding(t *testing.T, repo domain.Repository, want domain.Finding, retained bool) {
	t.Helper()
	if err := repo.View(t.Context(), func(r domain.Reader) error {
		got, err := r.Finding(want.Scope, want.DetectorID, want.ID)
		if !retained {
			if !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("expired finding %q still retained: %+v, error %v", want.ID, got, err)
			}
			all, err := r.Findings(want.Scope, want.DetectorID)
			if err != nil {
				return err
			}
			for _, finding := range all {
				if finding.ID == want.ID {
					t.Fatalf("expired finding %q remains in repository listing", want.ID)
				}
			}
			return nil
		}
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("retained finding = %+v, want %+v", got, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func advanceRetention(t *testing.T, manual *clock.Manual, elapsed time.Duration) {
	t.Helper()
	if err := manual.Advance(elapsed); err != nil {
		t.Fatal(err)
	}
}

func drainRetention(t *testing.T, s *service.Service) {
	t.Helper()
	result, err := s.JobDriver().RunDue(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.More {
		t.Fatal("retention drain left due work")
	}
}

func TestRetentionCreatedDeadlineIncludesArchivedSuppressedAndSamples(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			repo, reopen := repository(t, kind)
			detector, base := retentionRecords()
			findings := []domain.Finding{base, base, base, base}
			findings[0].ID = "active"
			findings[1].ID = "archived"
			findings[2].ID, findings[2].Archived, findings[2].Suppressed = "suppressed", true, true
			_, sample, _ := records(detector.Scope)
			findings[3] = sample
			findings[3].ID = "sample"
			seedRetention(t, repo, detector, findings...)
			manual := clock.NewManual(base.Created)
			s := service.New(service.Config{Repository: repo, Clock: manual})
			t.Cleanup(func() { _ = s.Close() })
			drainRetention(t, s)
			advanceRetention(t, manual, retentionWindow-time.Nanosecond)
			// Recent occurrences, archival and analyst feedback must not move the
			// creation-based cap, even though their retained fields change.
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				for i := range findings {
					findings[i].Updated = manual.Now()
					findings[i].Count++
					findings[i].Feedback = "USEFUL"
					if findings[i].ID == "archived" {
						findings[i].Archived = true
					}
					if err := tx.PutFinding(findings[i]); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			drainRetention(t, s)
			for _, finding := range findings {
				assertRetainedFinding(t, repo, finding, true)
			}
			advanceRetention(t, manual, time.Nanosecond)
			drainRetention(t, s)
			for _, finding := range findings {
				assertRetainedFinding(t, repo, finding, false)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			repo = reopen()
			for _, finding := range findings {
				assertRetainedFinding(t, repo, finding, false)
			}
		})
	}
}

type retentionPublisher struct{ published []domain.Finding }

func (p *retentionPublisher) PublishFinding(_ context.Context, finding domain.Finding, _ api.Finding) error {
	p.published = append(p.published, finding)
	return nil
}

func TestRetentionNeverPublishesOverdueOccurrence(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		for _, offset := range []time.Duration{-time.Hour, 0, time.Hour} {
			t.Run(kind+"/"+offset.String(), func(t *testing.T) {
				repo, _ := repository(t, kind)
				detector, finding := retentionRecords()
				finding.PublishDue = finding.Created
				seedRetention(t, repo, detector, finding)
				manual := clock.NewManual(finding.Created)
				publisher := &retentionPublisher{}
				s := service.New(service.Config{Repository: repo, Clock: manual, Findings: publisher})
				t.Cleanup(func() { _ = s.Close() })
				drainRetention(t, s)
				if len(publisher.published) != 1 || publisher.published[0].Observation.EventID != "retained-event" {
					t.Fatalf("initial publication = %+v", publisher.published)
				}
				if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
					current, err := tx.Finding(finding.Scope, finding.DetectorID, finding.ID)
					if err != nil {
						return err
					}
					current.Updated = finding.Created.Add(retentionWindow - time.Hour)
					current.Count++
					current.Observation.EventID = "overdue-occurrence"
					current.PublishDue = finding.Created.Add(retentionWindow + offset)
					return tx.PutFinding(current)
				}); err != nil {
					t.Fatal(err)
				}
				advanceRetention(t, manual, retentionWindow)
				drainRetention(t, s)
				assertRetainedFinding(t, repo, finding, false)
				advanceRetention(t, manual, time.Hour)
				drainRetention(t, s)
				if len(publisher.published) != 1 {
					t.Fatalf("expired occurrence was published: %+v", publisher.published)
				}
			})
		}
	}
}

func TestRetentionSQLiteRestartDeletesObservationChildren(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retention.sqlite")
	var db *sql.DB
	open := func() domain.Repository {
		var err error
		db, err = sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		return backend.New(db)
	}
	repo := open()
	t.Cleanup(func() { _ = db.Close() })
	detector, finding := retentionRecords()
	finding.Archived, finding.Suppressed = true, true
	seedRetention(t, repo, detector, finding)
	manual := clock.NewManual(finding.Created)
	s := service.New(service.Config{Repository: repo, Clock: manual})
	drainRetention(t, s)
	assertObservationCount := func(want int) {
		t.Helper()
		var got int
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM guardduty_observations").Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("observation child rows = %d, want %d", got, want)
		}
	}
	assertObservationCount(1)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	advanceRetention(t, manual, retentionWindow-time.Nanosecond)
	repo = open()
	s = service.New(service.Config{Repository: repo, Clock: manual})
	t.Cleanup(func() { _ = s.Close() })
	drainRetention(t, s)
	assertRetainedFinding(t, repo, finding, true)
	assertObservationCount(1)
	advanceRetention(t, manual, time.Nanosecond)
	drainRetention(t, s)
	assertRetainedFinding(t, repo, finding, false)
	assertObservationCount(0)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	repo = open()
	assertRetainedFinding(t, repo, finding, false)
	assertObservationCount(0)
}

// Commit a competing replacement after selection releases its read snapshot,
// but before the public driver's RunDue executes that selected job.
type retentionReplacementRepository struct {
	domain.Repository
	afterView func() error
}

func (r *retentionReplacementRepository) View(ctx context.Context, f func(domain.Reader) error) error {
	if err := r.Repository.View(ctx, f); err != nil {
		return err
	}
	if replace := r.afterView; replace != nil {
		r.afterView = nil
		return replace()
	}
	return nil
}

func TestRetentionStaleSelectionPreservesReplacement(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			repo, _ := repository(t, kind)
			detector, old := retentionRecords()
			seedRetention(t, repo, detector, old)
			manual := clock.NewManual(old.Created.Add(retentionWindow))
			replacement := old
			replacement.Created, replacement.Updated = manual.Now(), manual.Now()
			replacement.Observation.EventID = "replacement-event"
			fenced := &retentionReplacementRepository{Repository: repo}
			s := service.New(service.Config{Repository: fenced, Clock: manual})
			t.Cleanup(func() { _ = s.Close() })
			fenced.afterView = func() error {
				return repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutFinding(replacement) })
			}
			drainRetention(t, s)
			if fenced.afterView != nil {
				t.Fatal("replacement was not committed between selection and execution")
			}
			assertRetainedFinding(t, repo, replacement, true)
			advanceRetention(t, manual, retentionWindow-time.Nanosecond)
			drainRetention(t, s)
			assertRetainedFinding(t, repo, replacement, true)
			advanceRetention(t, manual, time.Nanosecond)
			drainRetention(t, s)
			assertRetainedFinding(t, repo, replacement, false)
		})
	}
}
