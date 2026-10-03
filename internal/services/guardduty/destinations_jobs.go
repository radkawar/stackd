package guardduty

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/apievents"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type destinationJobs struct{ s *Service }

func (j destinationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	consider := func(job scheduler.Job) {
		if !found || scheduler.Compare(job, next) < 0 {
			next, found = job, true
		}
	}
	err := j.s.repository.View(ctx, func(r Reader) error {
		detectors, err := r.AllDetectors()
		if err != nil {
			return err
		}
		for _, detector := range detectors {
			destinations, err := r.PublishingDestinations(detector.Scope, detector.ID)
			if err != nil {
				return err
			}
			for _, d := range destinations {
				if d.Status == "STOPPED" {
					continue
				}
				if !d.FailureStarted.IsZero() {
					consider(scheduler.Job{Key: d.ARN + "/failure", Due: d.FailureStarted.Add(findingRetention), Version: uint64(d.Version)})
				}
				row, err := r.NextFindingExport(d.Scope, d.DetectorID, d.ID)
				if errors.Is(err, ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				consider(scheduler.Job{Key: d.ARN + "/export/" + row.FindingID + "/" + row.ID, Due: row.Due, Version: uint64(row.Version)})
			}
		}
		return nil
	})
	return next, found, err
}

func (j destinationJobs) Run(ctx context.Context, job scheduler.Job) error {
	parsed, err := arn.Parse(job.Key)
	if err != nil || parsed.Service != "guardduty" {
		return errors.New("invalid GuardDuty export job ARN")
	}
	parts := strings.Split(parsed.Resource, "/")
	if len(parts) < 5 || parts[0] != "detector" || parts[2] != "publishingdestination" {
		return errors.New("invalid GuardDuty export resource")
	}
	scope := Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, InvokedBy: ServicePrincipal})
	if len(parts) == 5 && parts[4] == "failure" {
		return j.stopFailed(ctx, scope, parts[1], parts[3], job)
	}
	if len(parts) != 7 || parts[4] != "export" || parts[5] == "" || parts[6] == "" {
		return errors.New("invalid GuardDuty export cursor")
	}
	var destination PublishingDestination
	var pending FindingExport
	eligible, discarded := false, false
	err = j.s.repository.View(ctx, func(r Reader) error {
		var err error
		destination, err = r.PublishingDestination(scope, parts[1], parts[3])
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		pending, err = r.FindingExport(scope, parts[1], parts[3], parts[5])
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if destination.Status == "STOPPED" || pending.ID != parts[6] || pending.DestinationVersion != destination.Version || pending.Version != int64(job.Version) || !pending.Due.Equal(job.Due) || pending.Due.After(j.s.clock.Now()) || pending.Due.IsZero() {
			return nil
		}
		finding, err := r.Finding(scope, parts[1], parts[5])
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		discarded = errors.Is(err, ErrNotFound) || finding.Archived || findingExpired(finding, j.s.clock.Now())
		eligible = true
		return nil
	})
	if err != nil || !eligible {
		return err
	}
	var deliveryErr error
	if !discarded {
		if j.s.destinationSink == nil {
			return errors.New("GuardDuty S3 destination owner is unavailable")
		}
		var body bytes.Buffer
		compressor := gzip.NewWriter(&body)
		if _, err := compressor.Write(pending.Payload); err != nil {
			return err
		}
		if err := compressor.Close(); err != nil {
			return err
		}
		metadata := awsctx.FromContext(ctx)
		metadata.ParentEventID = pending.ParentEventID
		effect, cancel := context.WithTimeout(awsctx.WithMetadata(ctx, metadata), 30*time.Second)
		deliveryErr = j.s.destinationSink.Export(effect, destination, pending.ObjectKey, body.Bytes())
		cancel()
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	return j.s.repository.Update(completion, func(tx Transaction) error {
		d, err := tx.PublishingDestination(scope, parts[1], parts[3])
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil || d.Version != destination.Version {
			return err
		}
		row, err := tx.FindingExport(scope, parts[1], parts[3], parts[5])
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil || row.Version != pending.Version || row.ID != pending.ID || !row.Due.Equal(pending.Due) {
			return err
		}
		now := j.s.clock.Now().UTC()
		row.Version++
		if deliveryErr == nil {
			row.Due, row.Payload = time.Time{}, nil
			if !discarded {
				row.LastPublished = now
				d.Status, d.FailureStarted = "PUBLISHING", time.Time{}
			}
		} else {
			row.Due = now.Add(exportRetryDelay)
			d.Status = "UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY"
			if d.FailureStarted.IsZero() {
				d.FailureStarted = now
			}
		}
		d.Updated = now
		if err := tx.PutPublishingDestination(d); err != nil {
			return err
		}
		return tx.PutFindingExport(row)
	})
}

func (j destinationJobs) stopFailed(ctx context.Context, scope Scope, detector, id string, job scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		d, err := tx.PublishingDestination(scope, detector, id)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.Version != int64(job.Version) || d.FailureStarted.IsZero() || d.FailureStarted.Add(findingRetention).After(j.s.clock.Now()) || !d.FailureStarted.Add(findingRetention).Equal(job.Due) {
			return nil
		}
		d.Status, d.Updated = "STOPPED", j.s.clock.Now().UTC()
		if err := tx.PutPublishingDestination(d); err != nil {
			return err
		}
		return tx.DeleteDestinationExports(scope, detector, id)
	})
}
