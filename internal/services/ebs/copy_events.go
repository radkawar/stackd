package ebs

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/ebs"
	"stackd/internal/awsctx"
)

// Notification is an EBS-owned native service event, not an API audit event.
type Notification struct {
	ID         string
	Scope      Scope
	DetailType string
	At         time.Time
	Resources  []string
	Detail     json.RawMessage
}

// NotificationPublisher admits EBS notifications and target work in the caller's
// transaction, preserving the originating request and event IDs.
type NotificationPublisher interface {
	PublishEBSNotification(context.Context, Notification) error
}

// Native EBS notifications place the region after the empty ARN region slot.
// This captured wire identity deliberately differs from the EC2 resource ARN.
func snapshotEventARN(key SnapshotKey) string {
	return "arn:" + key.Partition + ":ec2::" + key.Region + ":snapshot/" + key.ID
}

type snapshotCopyEventDetail struct {
	Event                       string `json:"event"`
	Result                      string `json:"result"`
	Cause                       string `json:"cause"`
	RequestID                   string `json:"request-id"`
	StartTime                   string `json:"startTime"`
	EndTime                     string `json:"endTime"`
	SnapshotID                  string `json:"snapshot_id"`
	Source                      string `json:"source"`
	Incremental                 string `json:"incremental"`
	CompletionDurationStartTime string `json:"completionDurationStartTime,omitempty"`
	TransferType                string `json:"transferType"`
	MetCompletionDuration       string `json:"metCompletionDuration,omitempty"`
}

const snapshotEventTimeLayout = "2006-01-02T15:04:05.000Z"

func copySnapshotEvent(record SnapshotRecord, at time.Time) (Notification, error) {
	copy := record.Copy
	resource := snapshotEventARN(record.Key)
	detail := snapshotCopyEventDetail{
		Event: "copySnapshot", Result: "succeeded", Cause: record.StateMessage,
		StartTime:  record.Created.UTC().Format(snapshotEventTimeLayout),
		EndTime:    at.UTC().Format(snapshotEventTimeLayout),
		SnapshotID: resource, Source: snapshotEventARN(copy.Source),
		Incremental: strconv.FormatBool(copy.Incremental), TransferType: "standard",
	}
	if copy.CompletionDurationMinutes > 0 {
		detail.TransferType = "time-based"
	}
	if record.Status == api.StatusERROR {
		detail.Result = "failed"
	} else {
		// The transfer-duration clock starts at admission, including when
		// payload work resumes after an interruption.
		detail.CompletionDurationStartTime = detail.StartTime
		if copy.CompletionDurationMinutes > 0 {
			deadline := record.Created.Add(time.Duration(copy.CompletionDurationMinutes) * time.Minute)
			detail.MetCompletionDuration = strconv.FormatBool(!at.After(deadline))
		}
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return Notification{}, err
	}
	return Notification{ID: uuid.NewString(), Scope: record.Key.Scope, DetailType: "EBS Snapshot Notification", At: at, Resources: []string{resource}, Detail: body}, nil
}

func (s *Service) publishCopySnapshotEvent(ctx context.Context, record SnapshotRecord, at time.Time) error {
	if s.events == nil || record.Copy == nil {
		return nil
	}
	event, err := copySnapshotEvent(record, at)
	if err != nil {
		return err
	}
	return s.publishNotification(ctx, event, record.Copy.RequestID, record.Copy.ParentEventID)
}

func (s *Service) publishNotification(ctx context.Context, event Notification, requestID, parentID string) error {
	if s.events == nil {
		return nil
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: event.Scope.Partition, AccountID: event.Scope.AccountID, Region: event.Scope.Region,
		RequestID: requestID, ParentEventID: parentID,
		InvokedBy: "ec2.amazonaws.com", SourceIP: "ec2.amazonaws.com", UserAgent: "ec2.amazonaws.com",
	})
	return s.events.PublishEBSNotification(ctx, event)
}
