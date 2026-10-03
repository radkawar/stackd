package integrations

import (
	"context"
	"encoding/json"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/services/cloudtrail"
	"stackd/internal/services/guardduty"
	"stackd/internal/services/s3"
	"stackd/journal"
)

// GuardDutyAPIDetector consumes the source outcome, not a customer-controlled
// EventBridge event or a sample-finding payload.
type GuardDutyAPIDetector interface {
	ObserveAPICall(context.Context, journal.Envelope, journal.APICallCompleted, []guardduty.DetectionTarget) error
}

// GuardDutyEvents is called inside CloudTrail's shared source-event transaction.
// Journal append and finding admission therefore commit or roll back together.
// It does not depend on any customer trail selecting the API event for delivery.
type GuardDutyEvents struct {
	Journal  apievents.Sink
	Detector GuardDutyAPIDetector
	Trails   cloudtrail.Repository
	Buckets  s3.Repository
}

func (a *GuardDutyEvents) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := a.Journal.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if a.Detector == nil {
		return nil
	} // Assembly binds the observer before serving requests.
	targets, err := a.trailTargets(ctx, envelope, call)
	if err != nil {
		return err
	}
	grants, err := a.bucketGrantTargets(ctx, envelope, call)
	if err != nil {
		return err
	}
	targets = append(targets, grants...)
	return a.Detector.ObserveAPICall(ctx, envelope, call, targets)
}

func (a *GuardDutyEvents) trailTargets(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) ([]guardduty.DetectionTarget, error) {
	if call.EventSource != "s3.amazonaws.com" || call.ErrorCode != "" || (call.EventName != "DeleteBucket" && call.EventName != "DeleteObject") {
		return nil, nil
	}
	var request struct {
		Bucket string `json:"bucketName"`
		Key    string `json:"key"`
	}
	if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
		return nil, err
	}
	if request.Bucket == "" {
		return nil, nil
	}
	var targets []guardduty.DetectionTarget
	err := a.Trails.View(ctx, func(r cloudtrail.Reader) error {
		trails, err := r.Trails(envelope.Partition, envelope.AccountID)
		if err != nil {
			return err
		}
		for _, trail := range trails {
			if trail.Bucket != request.Bucket {
				continue
			}
			if call.EventName == "DeleteBucket" {
				targets = []guardduty.DetectionTarget{{ResourceType: "AWS::S3::Bucket", ResourceName: request.Bucket}}
				return nil
			}
			prefix := trail.Prefix
			if prefix != "" {
				prefix += "/"
			}
			prefix += "AWSLogs/"
			if trail.OrganizationID != "" {
				prefix += trail.OrganizationID + "/"
			}
			prefix += envelope.AccountID + "/CloudTrail/"
			if strings.HasPrefix(request.Key, prefix) && strings.HasSuffix(request.Key, ".json.gz") {
				targets = []guardduty.DetectionTarget{{ResourceType: "AWS::S3::Object", ResourceName: request.Bucket + "/" + request.Key}}
				return nil
			}
		}
		return nil
	})
	return targets, err
}
