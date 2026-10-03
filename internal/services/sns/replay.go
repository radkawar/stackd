package sns

import (
	"encoding/json"
	"strings"
	"time"

	"stackd/internal/awswire"
)

func (s *Service) setReplayPolicy(r Reader, sub *SubscriptionRecord, document string) *awswire.Error {
	if !strings.HasSuffix(sub.Key.Topic.Name, ".fifo") {
		return failure("InvalidParameter", "Invalid parameter: AttributeName")
	}
	if !json.Valid([]byte(document)) {
		return failure("InvalidParameter", "Invalid parameter: ReplayPolicy: Unable to parse JSON")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(document), &fields) != nil || fields == nil {
		return failure("InvalidParameter", "Invalid parameter: ReplayPolicy: JSON is missing required fields")
	}
	if len(fields) == 0 {
		sub.Replay = ReplayRecord{}
		return nil
	}
	point, hasPoint := fields["PointType"]
	start, hasStart := fields["StartingPoint"]
	if !hasPoint || !hasStart {
		return failure("InvalidParameter", "Invalid parameter: ReplayPolicy: JSON is missing required fields")
	}
	var pointType string
	if json.Unmarshal(point, &pointType) != nil || pointType != "Timestamp" {
		return failure("InvalidParameter", "Invalid parameter: ReplayPolicy: Invalid PointType")
	}
	topic, err := r.Topic(sub.Key.Topic)
	if err != nil {
		return wireError(err)
	}
	if topic.Archive == nil {
		return failure("InvalidParameter", "Invalid parameter: ReplayPolicy: Topic does not have an ArchivePolicy")
	}
	var timestamp string
	if json.Unmarshal(start, &timestamp) != nil {
		return failure("InvalidParameter", "Invalid parameter: ReplayPolicy: Invalid StartingPoint value")
	}
	starting, err := time.Parse(time.RFC3339Nano, timestamp)
	now := s.clock.Now()
	if err != nil || starting.After(now) || starting.Before(beginningArchiveTime(*topic.Archive, now)) {
		return failure("InvalidParameter", "Invalid parameter: ReplayPolicy: Invalid StartingPoint value")
	}
	var ending time.Time
	if end, hasEnd := fields["EndingPoint"]; hasEnd {
		if json.Unmarshal(end, &timestamp) != nil {
			return failure("InvalidParameter", "Invalid parameter: ReplayPolicy: Invalid EndingPoint value")
		}
		ending, err = time.Parse(time.RFC3339Nano, timestamp)
		if err != nil || ending.Before(starting) || ending.After(now) {
			return failure("InvalidParameter", "Invalid parameter: ReplayPolicy: Invalid EndingPoint value")
		}
	}
	// A new replay does not stop an active live subscription. Conversely, an
	// already paused subscription remains paused until its replay catches up.
	sub.Replay = ReplayRecord{Policy: document, Status: "Pending", Start: starting, End: ending, Due: now, Paused: sub.Replay.Paused}
	return nil
}

// enqueueDelivery establishes one native delivery identity and FIFO predecessor.
// Live fanout and replay share this ordering boundary, not separate queues.
func enqueueDelivery(tx Transaction, delivery DeliveryRecord) error {
	delivery.ID, delivery.Version = identifier(), 1
	if delivery.FIFOGroup != "" {
		var err error
		delivery.FIFOPrevious, err = tx.DeliveryTail(delivery.Subscription, delivery.FIFOGroup)
		if err != nil {
			return err
		}
	}
	return tx.PutDelivery(delivery)
}
