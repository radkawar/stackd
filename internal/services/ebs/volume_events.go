package ebs

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/ebs"
)

type volumeEventDetail struct {
	Event     string `json:"event"`
	Result    string `json:"result"`
	Cause     string `json:"cause"`
	RequestID string `json:"request-id"`
}

func (s *Service) publishVolumeEvent(ctx context.Context, volume VolumeRecord, action, result string, at time.Time) error {
	if s.events == nil {
		return nil
	}
	requestID, parentID := volume.RequestID, volume.ParentEventID
	if action == "modifyVolume" {
		requestID, parentID = volume.Modification.RequestID, volume.Modification.ParentEventID
	}
	body, err := json.Marshal(volumeEventDetail{Event: action, Result: result, Cause: volume.StateMessage, RequestID: requestID})
	if err != nil {
		return err
	}
	resources := []string{volumeARN(volume.Key)}
	if action == "createVolume" && result == "failed" && volume.KMSKeyARN != "" {
		resources = append(resources, volume.KMSKeyARN)
	}
	event := Notification{ID: uuid.NewString(), Scope: volume.Key.Scope, DetailType: "EBS Volume Notification", At: at, Resources: resources, Detail: body}
	return s.publishNotification(ctx, event, requestID, parentID)
}

func (s *Service) publishVolumeSnapshotEvent(ctx context.Context, snapshot SnapshotRecord, at time.Time) error {
	if s.events == nil {
		return nil
	}
	detail := struct {
		Event      string `json:"event"`
		Result     string `json:"result"`
		Cause      string `json:"cause"`
		RequestID  string `json:"request-id"`
		SnapshotID string `json:"snapshot_id"`
		Source     string `json:"source"`
		StartTime  string `json:"startTime"`
		EndTime    string `json:"endTime"`
	}{
		Event: "createSnapshot", Result: "succeeded", Cause: snapshot.StateMessage,
		SnapshotID: snapshotEventARN(snapshot.Key),
		Source:     "arn:" + snapshot.Key.Partition + ":ec2::" + snapshot.Key.Region + ":volume/" + snapshot.Volume.Source.ID,
		StartTime:  snapshot.Created.UTC().Format(snapshotEventTimeLayout), EndTime: at.UTC().Format(snapshotEventTimeLayout),
	}
	if snapshot.Status == api.StatusERROR {
		detail.Result = "failed"
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	event := Notification{ID: uuid.NewString(), Scope: snapshot.Key.Scope, DetailType: "EBS Snapshot Notification", At: at, Resources: []string{detail.SnapshotID}, Detail: body}
	return s.publishNotification(ctx, event, snapshot.Volume.RequestID, snapshot.Volume.ParentEventID)
}
