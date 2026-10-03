package guardduty

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type ipListJobs struct{ s *Service }

func (j ipListJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		detectors, err := r.AllDetectors()
		if err != nil {
			return err
		}
		for _, d := range detectors {
			lists, err := r.IPLists(d.Scope, d.ID)
			if err != nil {
				return err
			}
			for _, v := range lists {
				if v.Status != "ACTIVATING" || v.Due.IsZero() {
					continue
				}
				job := scheduler.Job{Key: v.ARN, Due: v.Due, Version: uint64(v.Version)}
				if !found || scheduler.Compare(job, next) < 0 {
					next, found = job, true
				}
			}
		}
		return nil
	})
	return next, found, err
}

func (j ipListJobs) Run(ctx context.Context, job scheduler.Job) error {
	parsed, err := arn.Parse(job.Key)
	if err != nil || parsed.Service != "guardduty" {
		return errors.New("invalid GuardDuty IP list job ARN")
	}
	parts := strings.Split(parsed.Resource, "/")
	if len(parts) != 4 || parts[0] != "detector" || parts[1] == "" || parts[3] == "" || (IPListKind(parts[2]) != TrustedIPList && IPListKind(parts[2]) != ThreatIPList) {
		return errors.New("invalid GuardDuty IP list job resource")
	}
	sc := Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, InvokedBy: ServicePrincipal})
	var pending IPList
	eligible := false
	err = j.s.repository.View(ctx, func(r Reader) error {
		var err error
		pending, err = r.IPList(sc, parts[1], IPListKind(parts[2]), parts[3])
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		eligible = pending.Status == "ACTIVATING" && uint64(pending.Version) == job.Version && pending.Due.Equal(job.Due) && !pending.Due.After(j.s.clock.Now())
		return nil
	})
	if err != nil || !eligible {
		return err
	}
	// Do not borrow a repository transaction for S3 or KMS authorization/read.
	ranges, rejected := j.s.readIPList(ctx, pending)
	if err := ctx.Err(); err != nil {
		return err
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		return completeIPList(tx, pending, ranges, rejected)
	})
}
