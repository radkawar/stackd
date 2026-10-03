package configservice

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"stackd/internal/scheduler"
	"strings"
	"time"
)

type configJobs struct{ service *Service }

func (source configJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	s := source.service
	job, found, err := s.nextRuleJob(ctx)
	if err != nil {
		return job, false, err
	}
	err = s.repository.View(ctx, func(reader Reader) error {
		rows, err := reader.Deliveries()
		if err != nil {
			return err
		}
		for _, d := range rows {
			if d.Status != "PENDING" && d.Status != "RUNNING" {
				continue
			}
			candidate := scheduler.Job{Key: "delivery:" + d.ID, Version: uint64(d.Attempts), Due: d.Due}
			if !found || candidate.Due.Before(job.Due) || candidate.Due.Equal(job.Due) && candidate.Key < job.Key {
				job = candidate
				found = true
			}
		}
		return nil
	})
	return job, found, err
}
func (source configJobs) Run(ctx context.Context, job scheduler.Job) error {
	if strings.HasPrefix(job.Key, "rule:") {
		return source.service.processRuleJob(ctx, job)
	}
	return source.service.processDelivery(ctx, job)
}
func (s *Service) processDelivery(ctx context.Context, job scheduler.Job) error {
	id := strings.TrimPrefix(job.Key, "delivery:")
	var selected Delivery
	var recorder Recorder
	var channel Channel
	var items []Item
	var previous *Item
	claimed := false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.Deliveries()
		if err != nil {
			return err
		}
		for _, d := range rows {
			if d.ID != id || uint64(d.Attempts) != job.Version || (d.Status != "PENDING" && d.Status != "RUNNING") || d.Due.After(s.clock.Now()) {
				continue
			}
			c, ok, err := tx.Channel(d.Scope)
			if err != nil {
				return err
			}
			if !ok || c.Name != d.ChannelName {
				d.Status = "CANCELLED"
				return tx.PutDelivery(d)
			}
			r, ok, err := tx.Recorder(d.Scope)
			if err != nil {
				return err
			}
			if !ok {
				d.Status = "CANCELLED"
				return tx.PutDelivery(d)
			}
			periodic := d.Kind == "PeriodicSnapshot"
			if d.Kind == "PeriodicSnapshot" {
				d.Status = "COMPLETED"
				d.CompletedAt = s.clock.Now().UTC()
				if err := tx.PutDelivery(d); err != nil {
					return err
				}
				c.NextDelivery = s.clock.Now().Add(deliveryPeriod(c.Frequency))
				if err := tx.PutChannel(c); err != nil {
					return err
				}
				if err := s.schedulePeriodicSnapshot(tx, c); err != nil {
					return err
				}
				if !r.Recording {
					return nil
				}
				d = Delivery{Scope: d.Scope, ID: uuid(), ChannelName: d.ChannelName, Kind: "ConfigSnapshot", Due: s.clock.Now().UTC(), CreatedAt: s.clock.Now().UTC(), Status: "PENDING"}
				d.ObjectKey = objectKey(c, d)
			}
			all, err := tx.Items(d.Scope)
			if err != nil {
				return err
			}
			if periodic {
				for _, item := range all {
					d.LastSequence = max(d.LastSequence, item.Sequence)
				}
			}
			for _, item := range all {
				if item.Sequence <= d.LastSequence && (d.Kind == "ConfigSnapshot" || item.Sequence >= d.FirstSequence) {
					items = append(items, item)
				}
			}
			if d.Kind == "ConfigurationItemChangeNotification" && len(items) == 1 {
				for i := range all {
					item := &all[i]
					if itemKey(*item) == itemKey(items[0]) && item.Sequence < items[0].Sequence && (previous == nil || item.Sequence > previous.Sequence) {
						previous = item
					}
				}
			}
			if d.Kind == "ConfigSnapshot" && d.Attempts == 0 && c.TopicARN != "" {
				now := s.clock.Now().UTC()
				if err := tx.PutDelivery(Delivery{Scope: d.Scope, ID: d.ID + ":started", ChannelName: d.ChannelName, Kind: "ConfigurationSnapshotDeliveryStarted", Due: now, CreatedAt: now, Status: "PENDING", ObjectKey: d.ObjectKey}); err != nil {
					return err
				}
			}
			d.Attempts++
			d.Status = "RUNNING"
			d.Due = s.clock.Now().Add(time.Minute)
			if err := tx.PutDelivery(d); err != nil {
				return err
			}
			selected, recorder, channel = d, r, c
			claimed = true
			break
		}
		return nil
	})
	if err != nil || !claimed {
		return err
	}
	workerCtx := scopedContext(ctx, selected.Scope)
	var effectErr error
	if s.effects == nil {
		effectErr = failure("InternalServiceException", "Config delivery dependencies are unavailable.")
	} else if selected.Kind == "ConfigurationItemChangeNotification" {
		var body []byte
		body, effectErr = notificationBody(selected, items, previous)
		if effectErr == nil {
			effectErr = s.effects.Notify(workerCtx, recorder, channel, body)
		}
	} else if kind, ok := exportNotificationKinds[selected.Kind]; ok {
		var body []byte
		body, effectErr = exportNotificationBody(selected, channel, kind)
		if effectErr == nil {
			effectErr = s.effects.Notify(workerCtx, recorder, channel, body)
		}
	} else {
		var body []byte
		body, effectErr = exportBody(selected, items)
		if effectErr == nil {
			effectErr = s.effects.Deliver(workerCtx, recorder, channel, selected.ObjectKey, body)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.Deliveries()
		if err != nil {
			return err
		}
		for _, d := range rows {
			if d.ID != selected.ID || d.Attempts != selected.Attempts || d.Status != "RUNNING" {
				continue
			}
			d.CompletedAt = s.clock.Now().UTC()
			d.Status = "SUCCESS"
			d.ErrorCode = ""
			d.ErrorMessage = ""
			if effectErr != nil {
				rejected := wireError(effectErr)
				d.Status = "PENDING"
				d.ErrorCode = rejected.Code
				d.ErrorMessage = rejected.Message
				d.Due = s.clock.Now().Add(time.Hour)
			}
			if err := tx.PutDelivery(d); err != nil {
				return err
			}
			if effectErr == nil && (d.Kind == "ConfigSnapshot" || d.Kind == "ConfigHistory") && channel.TopicARN != "" {
				// Export completion notifications are independently retained; a successful S3
				// object must not be rewritten merely because SNS currently rejects delivery.
				notice := Delivery{Scope: d.Scope, ID: d.ID + ":completed", ChannelName: d.ChannelName, Kind: "ConfigurationSnapshotDeliveryCompleted", ObjectKey: d.ObjectKey, Status: "PENDING", Due: s.clock.Now().UTC(), CreatedAt: s.clock.Now().UTC()}
				if d.Kind == "ConfigHistory" {
					notice.Kind = "ConfigurationHistoryDeliveryCompleted"
				}
				return tx.PutDelivery(notice)
			}
			return nil
		}
		return nil
	})
}

// Config S3/SNS documents embed configuration objects; the public Config API
// exposes those same values as JSON strings. Both originate in immutable items.
func documentItem(item Item) map[string]any {
	out := map[string]any{"configurationItemVersion": "1.3", "awsAccountId": item.AccountID, "configurationItemCaptureTime": item.CaptureTime.UTC().Format(configTime), "configurationItemStatus": item.Status, "configurationStateId": item.Sequence, "resourceType": item.ResourceType, "resourceId": item.ResourceID, "ARN": item.ARN, "awsRegion": item.Region, "tags": item.Tags, "relatedEvents": []string{}, "relationships": []any{}, "configurationStateMd5Hash": ""}
	if item.Tags == nil {
		out["tags"] = map[string]string{}
	}
	if item.ResourceName != "" {
		out["resourceName"] = item.ResourceName
	}
	if item.AvailabilityZone != "" {
		out["availabilityZone"] = item.AvailabilityZone
	}
	if !item.CreationTime.IsZero() {
		out["resourceCreationTime"] = item.CreationTime.UTC().Format(configTime)
	}
	if item.Configuration != "" {
		out["configuration"] = json.RawMessage(item.Configuration)
	} else {
		out["configuration"] = nil
	}
	supp := map[string]json.RawMessage{}
	for k, v := range item.Supplementary {
		supp[k] = json.RawMessage(v)
	}
	out["supplementaryConfiguration"] = supp
	relationships := make([]map[string]string, 0, len(item.Relationships))
	for _, r := range item.Relationships {
		relationships = append(relationships, map[string]string{"resourceType": r.ResourceType, "resourceId": r.ResourceID, "resourceName": r.ResourceName, "name": r.Name})
	}
	out["relationships"] = relationships
	return out
}
func exportBody(delivery Delivery, items []Item) ([]byte, error) {
	if delivery.Kind == "ConfigSnapshot" {
		latest := latestItems(items)
		items = items[:0]
		for _, key := range slices.Sorted(maps.Keys(latest)) {
			item := latest[key]
			if item.Status != "ResourceDeleted" {
				items = append(items, item)
			}
		}
	}
	documents := make([]map[string]any, 0, len(items))
	for _, item := range items {
		documents = append(documents, documentItem(item))
	}
	document := map[string]any{"fileVersion": "1.0", "configurationItems": documents}
	if delivery.Kind == "ConfigSnapshot" {
		document["configSnapshotId"] = delivery.ID
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(raw); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
func notificationBody(delivery Delivery, items []Item, previous *Item) ([]byte, error) {
	if len(items) != 1 {
		return nil, failure("InternalServiceException", "Configuration notification does not identify one retained item.")
	}
	item := items[0]
	document := documentItem(item)
	for _, key := range []string{"resourceName", "availabilityZone", "resourceCreationTime"} {
		if _, present := document[key]; !present {
			document[key] = nil
		}
	}
	diff, err := configurationDiff(previous, item)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"messageType": "ConfigurationItemChangeNotification", "configurationItem": document, "configurationItemDiff": diff, "notificationCreationTime": delivery.CreatedAt.UTC().Format(configTime), "recordVersion": "1.3"})
}

// exportNotificationKinds maps retained delivery rows to the native message
// types captured in testdata/aws/configservice/resource_transitions.json.
var exportNotificationKinds = map[string]bool{"ConfigurationSnapshotDeliveryStarted": false, "ConfigurationSnapshotDeliveryCompleted": true, "ConfigurationHistoryDeliveryCompleted": true}

func exportNotificationBody(delivery Delivery, channel Channel, includesObject bool) ([]byte, error) {
	body := map[string]any{"messageType": delivery.Kind, "notificationCreationTime": delivery.CreatedAt.UTC().Format(configTime), "recordVersion": "1.1"}
	if delivery.Kind != "ConfigurationHistoryDeliveryCompleted" {
		body["configSnapshotId"] = strings.TrimSuffix(strings.TrimSuffix(delivery.ID, ":started"), ":completed")
	}
	if includesObject {
		body["s3ObjectKey"], body["s3Bucket"] = delivery.ObjectKey, channel.Bucket
	}
	return json.Marshal(body)
}

// configTime is the native millisecond UTC spelling in delivered documents.
const configTime = "2006-01-02T15:04:05.000Z"
