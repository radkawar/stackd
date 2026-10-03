package lambda

import (
	"encoding/json"
	"fmt"
	"time"

	streams "stackd/internal/awsapi/dynamodbstreams"
)

func dynamoDBRecord(mapping EventSourceMappingRecord, record streams.Record, now time.Time) (StreamQueuedRecord, error) {
	if record.Dynamodb == nil || value(record.Dynamodb.SequenceNumber) == "" {
		return StreamQueuedRecord{}, fmt.Errorf("stream record has no sequence number")
	}
	d := record.Dynamodb
	if d.ApproximateCreationDateTime == nil {
		return StreamQueuedRecord{}, fmt.Errorf("stream record has no creation time")
	}
	created := *d.ApproximateCreationDateTime
	var size int64
	if d.SizeBytes != nil {
		size = int64(*d.SizeBytes)
	}
	native := struct {
		EventID        string `json:"eventID"`
		EventName      string `json:"eventName"`
		EventVersion   string `json:"eventVersion"`
		EventSource    string `json:"eventSource"`
		AWSRegion      string `json:"awsRegion"`
		EventSourceARN string `json:"eventSourceARN"`
		DynamoDB       any    `json:"dynamodb"`
		UserIdentity   any    `json:"userIdentity,omitempty"`
	}{EventID: value(record.EventID), EventName: string(value(record.EventName)), EventVersion: value(record.EventVersion), EventSource: value(record.EventSource), AWSRegion: value(record.AwsRegion), EventSourceARN: mapping.EventSourceARN}
	native.DynamoDB = struct {
		ApproximateCreationDateTime float64              `json:"ApproximateCreationDateTime"`
		Keys                        streams.AttributeMap `json:"Keys"`
		NewImage                    streams.AttributeMap `json:"NewImage,omitempty"`
		OldImage                    streams.AttributeMap `json:"OldImage,omitempty"`
		SequenceNumber              string               `json:"SequenceNumber"`
		SizeBytes                   int64                `json:"SizeBytes"`
		StreamViewType              string               `json:"StreamViewType"`
	}{float64(created.UnixNano()) / float64(time.Second), d.Keys, d.NewImage, d.OldImage, value(d.SequenceNumber), size, value(d.StreamViewType)}
	if record.UserIdentity != nil {
		native.UserIdentity = struct {
			PrincipalID string `json:"principalId"`
			Type        string `json:"type"`
		}{value(record.UserIdentity.PrincipalId), value(record.UserIdentity.Type)}
	}
	payload, err := sourceJSON(native)
	if err != nil {
		return StreamQueuedRecord{}, err
	}
	keys, err := json.Marshal(d.Keys)
	if err != nil {
		return StreamQueuedRecord{}, err
	}
	return StreamQueuedRecord{ID: native.EventID, Sequence: value(d.SequenceNumber), ItemKey: string(keys), CreatedAt: created, CapturedAt: now, Payload: payload}, nil
}
