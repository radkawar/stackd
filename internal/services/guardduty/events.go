package guardduty

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// FindingPublisher commits a producer-owned finding event to the shared event
// transaction. Customer target effects remain owned by EventBridge delivery.
type FindingPublisher interface {
	PublishFinding(context.Context, Finding, api.Finding) error
}

func publicationInterval(frequency string) time.Duration {
	switch frequency {
	case "FIFTEEN_MINUTES":
		return 15 * time.Minute
	case "ONE_HOUR":
		return time.Hour
	default:
		return 6 * time.Hour
	}
}

type findingJobs struct{ s *Service }

func (j findingJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		detectors, err := r.AllDetectors()
		if err != nil {
			return err
		}
		for _, detector := range detectors {
			findings, err := r.Findings(detector.Scope, detector.ID)
			if err != nil {
				return err
			}
			for _, finding := range findings {
				due := findingExpires(finding)
				if !finding.PublishDue.IsZero() && finding.PublishDue.Before(due) {
					due = finding.PublishDue
				}
				job := scheduler.Job{Key: detector.ARN + "/finding/" + finding.ID, Due: due}
				if !found || scheduler.Compare(job, next) < 0 {
					next, found = job, true
				}
			}
		}
		return nil
	})
	return next, found, err
}
func (j findingJobs) Run(ctx context.Context, job scheduler.Job) error {
	parsed, err := arn.Parse(job.Key)
	if err != nil || parsed.Service != "guardduty" {
		return errors.New("invalid GuardDuty finding job ARN")
	}
	parts := strings.Split(parsed.Resource, "/")
	if len(parts) != 4 || parts[0] != "detector" || parts[2] != "finding" {
		return errors.New("invalid GuardDuty finding resource")
	}
	sc := Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, InvokedBy: ServicePrincipal})
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		finding, err := tx.Finding(sc, parts[1], parts[3])
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		now := j.s.clock.Now().UTC()
		if findingExpired(finding, now) {
			return tx.DeleteFinding(sc, parts[1], parts[3])
		}
		if !finding.PublishDue.Equal(job.Due) || finding.PublishDue.IsZero() || finding.PublishDue.After(now) {
			return nil
		}
		if !finding.Suppressed {
			if j.s.findings == nil {
				return errors.New("GuardDuty finding publisher is unavailable")
			}
			output, err := findingOutput(finding)
			if err != nil {
				return err
			}
			if err := j.s.findings.PublishFinding(tx.Context(), finding, output); err != nil {
				return err
			}
			finding.LastPublished = now
		}
		finding.PublishDue = time.Time{}
		return tx.PutFinding(finding)
	})
}
