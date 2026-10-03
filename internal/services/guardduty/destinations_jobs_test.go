package guardduty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/scheduler"
	"stackd/storage/memory"
)

// Retain the real memory reader so the sink can check its lifetime without
// waiting for a lock, starting a goroutine, or depending on a wall-clock timeout.
type destinationJobRepository struct {
	Repository
	borrowed Reader
}

func (r *destinationJobRepository) View(ctx context.Context, fn func(Reader) error) error {
	return r.Repository.View(ctx, func(reader Reader) error {
		r.borrowed = reader
		return fn(reader)
	})
}
func (r *destinationJobRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.Repository.Update(ctx, func(tx Transaction) error {
		r.borrowed = tx
		return fn(tx)
	})
}
func (r *destinationJobRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return r.Repository.Attempt(ctx, func(tx Transaction) error {
		r.borrowed = tx
		return fn(tx)
	})
}

// Only external-effect outcomes and interleavings are controlled here. Real
// encrypted S3 delivery is covered by integration, not by a payload-echo mock.
type destinationJobSink struct {
	t          *testing.T
	repository *destinationJobRepository
	detector   Detector
	keys       []string
	effect     func() error
}

func (s *destinationJobSink) outsideTransaction() {
	s.t.Helper()
	if s.repository.borrowed == nil {
		s.t.Fatal("sink reached without a repository admission snapshot")
	}
	_, err := s.repository.borrowed.Detector(s.detector.Scope, s.detector.ID)
	if !errors.Is(err, memory.ErrClosedTransaction) {
		s.t.Fatalf("external S3 effect retained an open GuardDuty transaction: %v", err)
	}
}
func (s *destinationJobSink) Validate(context.Context, PublishingDestination) error {
	s.outsideTransaction()
	return nil
}
func (s *destinationJobSink) Export(_ context.Context, _ PublishingDestination, key string, _ []byte) error {
	s.outsideTransaction()
	s.keys = append(s.keys, key)
	if s.effect != nil {
		return s.effect()
	}
	return nil
}

type destinationJobFixture struct {
	s             *Service
	ctx           context.Context
	d             Detector
	clock         *clock.Manual
	sink          *destinationJobSink
	destinationID string
	findingID     string
}

func newDestinationJobFixture(t *testing.T, frequency string) *destinationJobFixture {
	t.Helper()
	s, ctx, d, _ := filterFixture(t)
	// Commands still exercise their real admission/commit paths, but their
	// wakeups cannot race these synchronous source selections and executions.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	d.Status, d.Frequency, d.ARN = "ENABLED", frequency, detectorARN(d.Scope, d.ID)
	r := &destinationJobRepository{Repository: s.repository}
	s.repository = r
	if err := r.Update(ctx, func(tx Transaction) error { return tx.PutDetector(d) }); err != nil {
		t.Fatal(err)
	}
	sink := &destinationJobSink{t: t, repository: r, detector: d}
	s.destinationSink = sink
	out, rejected := filterCall(s, ctx, "CreatePublishingDestination", &api.CreatePublishingDestinationRequest{
		DetectorId: new(api.DetectorId(d.ID)), DestinationType: new(api.DestinationTypeS3),
		DestinationProperties: &api.DestinationProperties{
			DestinationArn: new(api.String("arn:aws:s3:::finding-exports/prefix")),
			KmsKeyArn:      new(api.String("arn:aws:kms:us-east-1:123456789012:key/exports")),
		},
	})
	if rejected != nil {
		t.Fatal(rejected)
	}
	return &destinationJobFixture{s: s, ctx: ctx, d: d, clock: s.clock.(*clock.Manual), sink: sink,
		destinationID: value(out.(*api.CreatePublishingDestinationResponse).DestinationId), findingID: "0123456789abcdef0123456789abcdef"}
}

func (h *destinationJobFixture) advance(t *testing.T, duration time.Duration) {
	t.Helper()
	if err := h.clock.Advance(duration); err != nil {
		t.Fatal(err)
	}
}
func (h *destinationJobFixture) occurrence(t *testing.T) {
	t.Helper()
	if err := h.s.repository.Update(h.ctx, func(tx Transaction) error {
		finding, err := tx.Finding(h.d.Scope, h.d.ID, h.findingID)
		if errors.Is(err, ErrNotFound) || err == nil && findingExpired(finding, h.clock.Now()) {
			finding = Finding{Scope: h.d.Scope, DetectorID: h.d.ID, ID: h.findingID, Created: h.clock.Now(),
				Observation: Observation{Type: "Policy:IAMUser/RootCredentialUsage", Severity: 8, ResourceType: "AccessKey", UserType: "Root", API: "ListBuckets", ServiceName: "s3.amazonaws.com"}}
		} else if err != nil {
			return err
		}
		finding.Count++
		finding.Updated = h.clock.Now()
		finding.Observation.EventID = fmt.Sprintf("observation-%d", finding.Count)
		filters, err := tx.Filters(h.d.Scope, h.d.ID)
		if err != nil {
			return err
		}
		return h.s.putOccurrence(tx, h.d, finding, filters)
	}); err != nil {
		t.Fatal(err)
	}
}
func (h *destinationJobFixture) row(t *testing.T) FindingExport {
	t.Helper()
	var row FindingExport
	if err := h.s.repository.View(h.ctx, func(r Reader) error {
		var err error
		row, err = r.FindingExport(h.d.Scope, h.d.ID, h.destinationID, h.findingID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return row
}
func (h *destinationJobFixture) destination(t *testing.T) PublishingDestination {
	t.Helper()
	var destination PublishingDestination
	if err := h.s.repository.View(h.ctx, func(r Reader) error {
		var err error
		destination, err = r.PublishingDestination(h.d.Scope, h.d.ID, h.destinationID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return destination
}
func (h *destinationJobFixture) next(t *testing.T) scheduler.Job {
	t.Helper()
	job, found, err := (destinationJobs{h.s}).Next(h.ctx)
	if err != nil || !found {
		t.Fatalf("expected pending S3 work: found=%v err=%v", found, err)
	}
	return job
}
func (h *destinationJobFixture) noJob(t *testing.T) {
	t.Helper()
	job, found, err := (destinationJobs{h.s}).Next(h.ctx)
	if err != nil || found {
		t.Fatalf("unexpected pending S3 work: %+v found=%v err=%v", job, found, err)
	}
}
func (h *destinationJobFixture) run(t *testing.T, job scheduler.Job) {
	t.Helper()
	if err := (destinationJobs{h.s}).Run(h.ctx, job); err != nil {
		t.Fatal(err)
	}
}
func (h *destinationJobFixture) archive(t *testing.T, archived bool) {
	t.Helper()
	var input any = &api.ArchiveFindingsRequest{DetectorId: new(api.DetectorId(h.d.ID)), FindingIds: api.FindingIds{api.FindingId(h.findingID)}}
	op := "ArchiveFindings"
	if !archived {
		op = "UnarchiveFindings"
		input = &api.UnarchiveFindingsRequest{DetectorId: new(api.DetectorId(h.d.ID)), FindingIds: api.FindingIds{api.FindingId(h.findingID)}}
	}
	if _, err := filterCall(h.s, h.ctx, op, input); err != nil {
		t.Fatal(err)
	}
}
func (h *destinationJobFixture) update(t *testing.T) {
	t.Helper()
	if _, err := filterCall(h.s, h.ctx, "UpdatePublishingDestination", &api.UpdatePublishingDestinationRequest{
		DetectorId: new(api.DetectorId(h.d.ID)), DestinationId: new(api.String(h.destinationID)),
		DestinationProperties: &api.DestinationProperties{DestinationArn: new(api.String("arn:aws:s3:::replacement-exports/repaired"))},
	}); err != nil {
		t.Fatal(err)
	}
}
func (h *destinationJobFixture) remove(t *testing.T) {
	t.Helper()
	if _, err := filterCall(h.s, h.ctx, "DeletePublishingDestination", &api.DeletePublishingDestinationRequest{
		DetectorId: new(api.DetectorId(h.d.ID)), DestinationId: new(api.String(h.destinationID)),
	}); err != nil {
		t.Fatal(err)
	}
}
func (h *destinationJobFixture) noExports(t *testing.T, deleted bool) {
	t.Helper()
	if err := h.s.repository.View(h.ctx, func(r Reader) error {
		if deleted {
			if _, err := r.PublishingDestination(h.d.Scope, h.d.ID, h.destinationID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("deleted destination was resurrected: %v", err)
			}
		}
		rows, err := r.FindingExports(h.d.Scope, h.d.ID, h.destinationID)
		if len(rows) != 0 {
			t.Fatalf("destination retained obsolete exports: %+v", rows)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
func requireDestinationPendingCount(t *testing.T, row FindingExport, count int64) {
	t.Helper()
	var finding api.Finding
	if err := json.Unmarshal(row.Payload, &finding); err != nil {
		t.Fatal(err)
	}
	if finding.Service == nil || finding.Service.Count == nil || int64(*finding.Service.Count) != count || value(finding.Id) != row.FindingID {
		t.Fatalf("coalesced outbox did not retain occurrence %d: %+v", count, finding)
	}
	if row.ParentEventID != fmt.Sprintf("observation-%d", count) {
		t.Fatalf("coalesced outbox retained an older observation parent: %q", row.ParentEventID)
	}
}

func TestDestinationExportsCoalesceWithoutMovingDeadlines(t *testing.T) {
	for _, tc := range []struct {
		frequency string
		interval  time.Duration
	}{{"FIFTEEN_MINUTES", 15 * time.Minute}, {"ONE_HOUR", time.Hour}, {"SIX_HOURS", 6 * time.Hour}} {
		t.Run(tc.frequency, func(t *testing.T) {
			h := newDestinationJobFixture(t, tc.frequency)
			start := h.clock.Now()
			h.occurrence(t)
			first, stale := h.row(t), h.next(t)
			if !first.Due.Equal(start.Add(5 * time.Minute)) {
				t.Fatalf("first S3 export must wait five minutes, not detector cadence: %v", first.Due)
			}
			h.advance(t, 2*time.Minute)
			h.occurrence(t)
			coalesced := h.row(t)
			if coalesced.ID != first.ID || coalesced.ObjectKey != first.ObjectKey || !coalesced.Created.Equal(first.Created) || !coalesced.Due.Equal(first.Due) {
				t.Fatal("coalescing replaced the publication identity or postponed its deadline")
			}
			requireDestinationPendingCount(t, coalesced, 2)
			job := h.next(t)
			h.advance(t, 3*time.Minute-time.Nanosecond)
			h.run(t, job)
			if len(h.sink.keys) != 0 || !reflect.DeepEqual(h.row(t), coalesced) {
				t.Fatal("first export ran before its deadline")
			}
			h.advance(t, time.Nanosecond)
			h.run(t, stale)
			if len(h.sink.keys) != 0 || !reflect.DeepEqual(h.row(t), coalesced) {
				t.Fatal("superseded occurrence job consumed the latest pending publication")
			}
			h.run(t, job)
			published := h.clock.Now()
			completed := h.row(t)
			if len(h.sink.keys) != 1 || !completed.Due.IsZero() || len(completed.Payload) != 0 || !completed.LastPublished.Equal(published) {
				t.Fatalf("first publication did not complete exactly once: %+v, keys=%v", completed, h.sink.keys)
			}
			h.noJob(t)
			h.advance(t, 2*time.Minute)
			h.occurrence(t)
			second := h.row(t)
			if second.ID == first.ID || second.ObjectKey == first.ObjectKey || !second.Due.Equal(published.Add(tc.interval)) {
				t.Fatalf("next publication did not use a fresh object at last-success cadence: %+v", second)
			}
			h.advance(t, time.Minute)
			h.occurrence(t)
			if got := h.row(t); got.ID != second.ID || got.ObjectKey != second.ObjectKey || !got.Due.Equal(second.Due) {
				t.Fatal("subsequent coalescing postponed detector cadence")
			}
			requireDestinationPendingCount(t, h.row(t), 4)
			job = h.next(t)
			h.advance(t, job.Due.Sub(h.clock.Now())-time.Nanosecond)
			h.run(t, job)
			if len(h.sink.keys) != 1 {
				t.Fatal("subsequent S3 export ran before detector cadence")
			}
			h.advance(t, time.Nanosecond)
			h.run(t, job)
			if got := h.row(t); len(h.sink.keys) != 2 || !got.LastPublished.Equal(h.clock.Now()) || !got.Due.IsZero() {
				t.Fatalf("cadenced publication did not complete at its boundary: %+v", got)
			}
			h.advance(t, tc.interval+time.Minute)
			h.occurrence(t)
			job = h.next(t)
			if !job.Due.Equal(h.clock.Now()) {
				t.Fatalf("an overdue cadence added a new five-minute delay: %v", job.Due)
			}
			h.run(t, job)
			if len(h.sink.keys) != 3 {
				t.Fatal("overdue occurrence did not publish immediately")
			}
			h.noJob(t)
		})
	}
}

func TestDestinationExportFailureRetriesStableObjectAndResetsHealth(t *testing.T) {
	h := newDestinationJobFixture(t, "SIX_HOURS")
	h.occurrence(t)
	original, job := h.row(t), h.next(t)
	h.advance(t, 7*time.Minute)
	h.sink.effect = func() error {
		h.advance(t, time.Minute)
		return errors.New("current KMS policy denies encryption")
	}
	h.run(t, job)
	failedAt := h.clock.Now()
	failed, retry := h.destination(t), h.row(t)
	if failed.Status != "UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY" || !failed.FailureStarted.Equal(failedAt) || !retry.Due.Equal(failedAt.Add(5*time.Minute)) || !retry.LastPublished.IsZero() {
		t.Fatalf("failure did not use actual effect completion time: destination=%+v cursor=%+v", failed, retry)
	}
	if retry.ID != original.ID || retry.ObjectKey != original.ObjectKey {
		t.Fatal("failed publication changed its retry identity")
	}
	h.advance(t, time.Minute)
	h.occurrence(t)
	latest := h.row(t)
	if latest.ID != original.ID || latest.ObjectKey != original.ObjectKey || !latest.Due.Equal(retry.Due) {
		t.Fatal("new occurrence changed a failed publication's object or retry deadline")
	}
	requireDestinationPendingCount(t, latest, 2)
	h.run(t, job)
	if len(h.sink.keys) != 1 {
		t.Fatal("stale first attempt bypassed the retry deadline")
	}
	job = h.next(t)
	h.advance(t, job.Due.Sub(h.clock.Now())-time.Nanosecond)
	h.run(t, job)
	if len(h.sink.keys) != 1 || !reflect.DeepEqual(h.row(t), latest) {
		t.Fatal("retry ran early or consumed newer pending evidence")
	}
	h.advance(t, time.Nanosecond)
	h.sink.effect = func() error { return errors.New("S3 bucket policy still denies delivery") }
	h.run(t, job)
	if got := h.destination(t); !got.FailureStarted.Equal(failedAt) {
		t.Fatal("a repeated failure extended the ninety-day failure window")
	}
	job = h.next(t)
	if !job.Due.Equal(h.clock.Now().Add(5 * time.Minute)) {
		t.Fatal("repeated failure used detector cadence instead of retry delay")
	}
	h.sink.effect = nil
	h.advance(t, 5*time.Minute)
	h.run(t, job)
	healthy, completed := h.destination(t), h.row(t)
	if healthy.Status != "PUBLISHING" || !healthy.FailureStarted.IsZero() || !completed.LastPublished.Equal(h.clock.Now()) || !completed.Due.IsZero() || len(completed.Payload) != 0 {
		t.Fatalf("successful retry did not clear health and pending work: destination=%+v cursor=%+v", healthy, completed)
	}
	if !reflect.DeepEqual(h.sink.keys, []string{original.ObjectKey, original.ObjectKey, original.ObjectKey}) {
		t.Fatalf("retries created duplicate object identities: %v", h.sink.keys)
	}
	h.run(t, job)
	if len(h.sink.keys) != 3 {
		t.Fatal("a completed retry ran twice")
	}
	h.noJob(t)
	h.occurrence(t)
	if got := h.row(t); !got.Due.Equal(completed.LastPublished.Add(6*time.Hour)) || got.ObjectKey == original.ObjectKey {
		t.Fatalf("recovery did not restart cadence from successful delivery: %+v", got)
	}
}

func TestDestinationArchiveGateAndExplicitUnarchive(t *testing.T) {
	for _, suppressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("suppressed=%v", suppressed), func(t *testing.T) {
			h := newDestinationJobFixture(t, "ONE_HOUR")
			h.occurrence(t)
			first, stale := h.row(t), h.next(t)
			if suppressed {
				createTestFilter(t, h.s, h.ctx, h.d, "suppress", "suppress-token", 1)
				if _, err := filterCall(h.s, h.ctx, "UpdateFilter", &api.UpdateFilterRequest{DetectorId: new(api.DetectorId(h.d.ID)), FilterName: new(api.String("suppress")), Action: new(api.FilterAction("ARCHIVE"))}); err != nil {
					t.Fatal(err)
				}
				h.occurrence(t)
			} else {
				h.archive(t, true)
			}
			if got := h.row(t); !got.Due.IsZero() || len(got.Payload) != 0 || !got.LastPublished.IsZero() {
				t.Fatalf("archiving retained pending S3 work or counted it as delivered: %+v", got)
			}
			h.occurrence(t)
			h.noJob(t)
			h.advance(t, 5*time.Minute)
			h.run(t, stale)
			if len(h.sink.keys) != 0 {
				t.Fatal("an archived finding reached S3 through a stale job")
			}
			h.archive(t, false)
			unarchived := h.row(t)
			if !unarchived.Due.Equal(h.clock.Now().Add(5*time.Minute)) || unarchived.ID == first.ID || unarchived.ObjectKey == first.ObjectKey {
				t.Fatalf("explicit unarchive did not start a fresh first-publication window: %+v", unarchived)
			}
			job := h.next(t)
			h.advance(t, 5*time.Minute)
			h.run(t, job)
			if len(h.sink.keys) != 1 || !h.row(t).LastPublished.Equal(h.clock.Now()) {
				t.Fatal("explicitly unarchived finding was still gated from S3")
			}
			h.noJob(t)
			// Revalidation must apply the same archive gate to existing findings;
			// an old suppression flag cannot undo an explicit unarchive.
			h.update(t)
			if got := h.row(t); !got.Due.Equal(h.clock.Now().Add(5 * time.Minute)) {
				t.Fatalf("destination revalidation omitted an explicitly unarchived finding: %+v", got)
			}
		})
	}
}

func TestDestinationReplacementAndDeletionFenceSelectedJobs(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(fmt.Sprintf("deleted=%v", deleted), func(t *testing.T) {
			h := newDestinationJobFixture(t, "ONE_HOUR")
			h.occurrence(t)
			stale := h.next(t)
			var replacement FindingExport
			if deleted {
				h.remove(t)
			} else {
				// Do not advance: replacing at the same instant can produce the
				// same deadline and expose a reset per-cursor version collision.
				h.update(t)
				replacement = h.row(t)
			}
			h.advance(t, 5*time.Minute)
			h.run(t, stale)
			if len(h.sink.keys) != 0 {
				t.Fatal("a job selected before destination cutover performed an S3 effect")
			}
			if deleted {
				h.noExports(t, true)
				h.noJob(t)
				return
			}
			if !reflect.DeepEqual(h.row(t), replacement) {
				t.Fatal("stale job consumed replacement destination work")
			}
			h.run(t, h.next(t))
			if !reflect.DeepEqual(h.sink.keys, []string{replacement.ObjectKey}) {
				t.Fatal("replacement destination did not deliver its own pending object")
			}
		})
	}
}

func TestDestinationCutoverDuringEffectFencesCompletion(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		for _, failed := range []bool{false, true} {
			t.Run(fmt.Sprintf("deleted=%v/failed=%v", deleted, failed), func(t *testing.T) {
				h := newDestinationJobFixture(t, "ONE_HOUR")
				h.occurrence(t)
				job := h.next(t)
				h.advance(t, 5*time.Minute)
				var replacement FindingExport
				var destination PublishingDestination
				h.sink.effect = func() error {
					if deleted {
						h.remove(t)
					} else {
						h.update(t)
						replacement, destination = h.row(t), h.destination(t)
					}
					if failed {
						return errors.New("old destination denied delivery")
					}
					return nil
				}
				h.run(t, job)
				if len(h.sink.keys) != 1 {
					t.Fatal("expected exactly one in-flight external effect")
				}
				if deleted {
					h.noExports(t, true)
					h.noJob(t)
					return
				}
				if !reflect.DeepEqual(h.row(t), replacement) || !reflect.DeepEqual(h.destination(t), destination) {
					t.Fatal("old effect completion consumed replacement work or changed its health")
				}
				h.sink.effect = nil
				h.advance(t, 5*time.Minute)
				h.run(t, h.next(t))
				if len(h.sink.keys) != 2 || h.sink.keys[1] != replacement.ObjectKey || !h.row(t).LastPublished.Equal(h.clock.Now()) {
					t.Fatal("replacement work was lost after fencing old completion")
				}
				h.noJob(t)
			})
		}
	}
}

func TestDestinationNewOccurrenceDuringEffectFencesCompletion(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed=%v", failed), func(t *testing.T) {
			h := newDestinationJobFixture(t, "ONE_HOUR")
			h.occurrence(t)
			original, job := h.row(t), h.next(t)
			h.advance(t, 5*time.Minute)
			var latest FindingExport
			h.sink.effect = func() error {
				h.advance(t, time.Minute)
				h.occurrence(t)
				latest = h.row(t)
				if failed {
					return errors.New("old effect failed after a newer occurrence committed")
				}
				return nil
			}
			h.run(t, job)
			if latest.ID != original.ID || latest.ObjectKey != original.ObjectKey || !latest.Due.Equal(original.Due) || !reflect.DeepEqual(h.row(t), latest) {
				t.Fatal("in-flight completion replaced or consumed newer pending content")
			}
			requireDestinationPendingCount(t, latest, 2)
			if got := h.destination(t); got.Status != "PUBLISHING" || !got.FailureStarted.IsZero() {
				t.Fatal("superseded effect completion changed current destination health")
			}
			h.sink.effect = nil
			h.run(t, h.next(t))
			completed := h.row(t)
			if !reflect.DeepEqual(h.sink.keys, []string{original.ObjectKey, original.ObjectKey}) || !completed.Due.IsZero() || len(completed.Payload) != 0 || !completed.LastPublished.Equal(h.clock.Now()) {
				t.Fatalf("newer occurrence was lost or moved to a duplicate object: %+v keys=%v", completed, h.sink.keys)
			}
			h.run(t, job)
			if len(h.sink.keys) != 2 {
				t.Fatal("superseded job delivered again after newer content completed")
			}
			h.noJob(t)
		})
	}
}

func TestDestinationFailureStopsAtNinetyDaysUnlessRevalidated(t *testing.T) {
	for _, repairBeforeDeadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("repairBeforeDeadline=%v", repairBeforeDeadline), func(t *testing.T) {
			h := newDestinationJobFixture(t, "ONE_HOUR")
			h.occurrence(t)
			job := h.next(t)
			h.advance(t, 5*time.Minute)
			h.sink.effect = func() error { return errors.New("bucket policy denied delivery") }
			h.run(t, job)
			failed := h.destination(t)
			// Cancel the per-finding retry so Next exposes the independent
			// destination-health deadline, rather than manufacturing a job.
			h.archive(t, true)
			stop := h.next(t)
			if stop.Key != failed.ARN+"/failure" || !stop.Due.Equal(failed.FailureStarted.Add(90*24*time.Hour)) {
				t.Fatalf("failure deadline was not retained independently of findings: %+v", stop)
			}
			h.advance(t, 90*24*time.Hour-time.Nanosecond)
			h.run(t, stop)
			if got := h.destination(t); got.Status != "UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY" {
				t.Fatal("destination stopped before ninety complete days of failure")
			}
			// The original finding has expired. A fresh observed occurrence
			// ensures stopping must remove real pending work, not an empty queue.
			h.occurrence(t)
			if repairBeforeDeadline {
				h.update(t)
			}
			h.advance(t, time.Nanosecond)
			h.run(t, stop)
			if repairBeforeDeadline {
				if got := h.destination(t); got.Status != "PUBLISHING" || !got.FailureStarted.IsZero() || got.Version == failed.Version {
					t.Fatalf("stale health job stopped the repaired destination: %+v", got)
				}
			} else {
				if got := h.destination(t); got.Status != "STOPPED" || !got.FailureStarted.Equal(failed.FailureStarted) {
					t.Fatalf("ninety-day failure did not stop publishing: %+v", got)
				}
				h.noExports(t, false)
				h.occurrence(t)
				h.noExports(t, false)
				h.noJob(t)
				h.update(t)
			}
			if len(h.sink.keys) != 1 {
				t.Fatal("health expiration or revalidation retried an S3 effect")
			}
			repaired, pending := h.destination(t), h.row(t)
			if repaired.Status != "PUBLISHING" || !repaired.FailureStarted.IsZero() || repaired.Version == failed.Version {
				t.Fatalf("update did not revalidate failed destination health: %+v", repaired)
			}
			h.run(t, stop)
			if !reflect.DeepEqual(h.destination(t), repaired) || !reflect.DeepEqual(h.row(t), pending) {
				t.Fatal("stale failure completion changed repaired destination or pending work")
			}
			h.sink.effect = nil
			h.advance(t, pending.Due.Sub(h.clock.Now()))
			h.run(t, h.next(t))
			if len(h.sink.keys) != 2 || !h.row(t).LastPublished.Equal(h.clock.Now()) {
				t.Fatal("revalidated destination did not resume actual publication")
			}
			h.noJob(t)
		})
	}
}
