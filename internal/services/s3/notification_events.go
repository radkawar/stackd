package s3

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"stackd/internal/awsctx"
)

func notificationTestEvent(m awsctx.Metadata, bucket BucketRecord, at time.Time) (string, error) {
	body, err := json.Marshal(map[string]any{
		"Service": "Amazon S3", "Event": "s3:TestEvent",
		"Time": at.UTC().Format("2006-01-02T15:04:05.000Z"), "Bucket": bucket.Key.Name,
		"RequestId": m.RequestID, "HostId": base64.StdEncoding.EncodeToString([]byte(m.RequestID)),
	})
	return string(body), err
}

// notifyObject captures configured publications with the object mutation. The
// per-command snapshot also avoids rereading rules for every DeleteObjects member.
func (s *Service) notifyObject(tx Transaction, c *apiCall, bucket BucketRecord, object ObjectRecord, name string) error {
	return s.notifyObjectEvent(tx, c, bucket, object, name, nil, nil, s.clock.Now().UTC())
}

func (s *Service) notifyObjectEvent(tx Transaction, c *apiCall, bucket BucketRecord, object ObjectRecord, name string, restore *ObjectRestore, replication *replicationNotification, at time.Time) error {
	if c.notifications == nil {
		state, err := tx.NotificationState(bucket.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		c.notifications = &state.Applied
	}
	configuration := c.notifications
	if len(configuration.Rules) == 0 && !configuration.EventBridge {
		return nil
	}
	ctx := c.observationContext(tx.Context())
	systemRestore := restore != nil && name != "ObjectRestore:Post"
	lifecycle := strings.HasPrefix(name, "Lifecycle")
	tiering := name == "IntelligentTiering"
	if systemRestore || replication != nil || lifecycle || tiering {
		ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
			Partition: bucket.Key.Partition, AccountID: bucket.AccountID, Region: bucket.Region,
			RequestID: uuid.NewString(), ParentEventID: c.eventID, SourceIP: "s3.amazonaws.com",
			ServicePrincipal: awsctx.ServicePrincipal{Name: "s3.amazonaws.com", SourceARN: bucket.Key.ARN(), Type: "Service"},
		})
	}
	m := awsctx.FromContext(ctx)
	if c.eventID == "" {
		c.eventID = uuid.NewString()
	}
	fields := map[string]any{"key": strings.ReplaceAll(url.QueryEscape(object.Key.Name), "%2F", "/")}
	tagging := strings.HasPrefix(name, "ObjectTagging:")
	retention := name == "ObjectRetention:Put"
	acl := name == "ObjectAcl:Put"
	if !tagging && !retention && !acl && !tiering {
		fields["sequencer"] = fmt.Sprintf("%018X", object.Sequence)
	}
	if object.VersionID != "" && object.VersionID != "null" {
		fields["versionId"] = object.VersionID
	}
	switch name {
	case "ObjectCreated:Put", "ObjectCreated:Copy", "ObjectCreated:CompleteMultipartUpload", "ObjectRetention:Put", "ObjectRestore:Post", "ObjectRestore:Completed", "ObjectRestore:Delete", "IntelligentTiering":
		fields["size"] = object.Size
		fields["eTag"] = strings.Trim(object.ETag, "\"")
	case "ObjectRemoved:DeleteMarkerCreated":
		fields["eTag"] = "d41d8cd98f00b204e9800998ecf8427e"
	case "ObjectTagging:Put", "ObjectTagging:Delete", "ObjectAcl:Put":
		fields["eTag"] = strings.Trim(object.ETag, "\"")
	}
	if replication != nil {
		fields["size"] = object.Size
		fields["eTag"] = strings.Trim(object.ETag, "\"")
	}
	if name == "ObjectCreated:Copy" {
		fields["hasObjectAnnotation"] = false
	}
	var record map[string]any
	var ownerIdentity string
	for _, rule := range configuration.Rules {
		if !notificationMatches(rule, object.Key.Name, "s3:"+name) {
			continue
		}
		if record == nil {
			ownerIdentity = "A" + strings.ToUpper(canonicalID(bucket.Key.Partition, bucket.AccountID)[:12])
			principal := m.PrincipalID
			if principal == "" {
				principal = m.AccountID
				if m.ServicePrincipal.Name != "" {
					principal = m.ServicePrincipal.Name
				}
			}
			principal = "AWS:" + principal
			if systemRestore {
				principal = "AmazonCustomer:" + ownerIdentity
			}
			if replication != nil {
				principal, ownerIdentity = "s3.amazonaws.com", bucket.AccountID
			}
			record = map[string]any{
				"eventVersion": "2.6", "eventSource": "aws:s3", "awsRegion": bucket.Region,
				"eventTime": at.Format("2006-01-02T15:04:05.000Z"), "eventName": name,
				"userIdentity":      map[string]any{"principalId": principal},
				"requestParameters": map[string]any{"sourceIPAddress": m.SourceIP},
				"responseElements":  map[string]any{"x-amz-request-id": m.RequestID, "x-amz-id-2": base64.StdEncoding.EncodeToString([]byte(c.eventID))},
			}
			if lifecycle || tiering {
				record["eventVersion"] = "2.3"
				record["userIdentity"].(map[string]any)["principalId"] = "s3.amazonaws.com"
			}
			if lifecycle {
				lifecycleNotificationRecord(record, fields, object, name)
			}
			if tiering {
				tieringNotificationRecord(record, object)
			}
			if replication != nil {
				record["replicationEventData"] = replication.fields()
			}
			if retention {
				if data := retentionEventData(object.Retention, at, false); data != nil {
					record["objectRetentionEventData"] = data
				}
			}
			if name == "ObjectRestore:Completed" && restore != nil {
				data := map[string]any{"lifecycleRestoreStorageClass": object.StorageClass}
				if object.StorageClass != "INTELLIGENT_TIERING" {
					data["lifecycleRestorationExpiryTime"] = restore.Due.UTC().Format("2006-01-02T15:04:05.000Z")
				}
				record["glacierEventData"] = map[string]any{"restoreEventData": data}
			}
		}
		// The retail owner identifier is opaque and distinct from the canonical
		// user identifier exposed by ACL APIs. It remains stable per account.
		record["s3"] = map[string]any{
			"s3SchemaVersion": "1.0", "configurationId": rule.ID,
			"bucket": map[string]any{"name": bucket.Key.Name, "arn": bucket.Key.ARN(), "ownerIdentity": map[string]any{"principalId": ownerIdentity}},
			"object": fields,
		}
		payload, err := json.Marshal(map[string]any{"Records": []any{record}})
		if err != nil {
			return err
		}
		delivery := notificationDelivery(ctx, c, bucket, rule, string(payload))
		delivery.ID, delivery.Due, delivery.Version = uuid.NewString(), at, 1
		if err := tx.PutNotificationDelivery(delivery); err != nil {
			return err
		}
	}
	if !configuration.EventBridge || replication != nil {
		return nil
	}
	if s.objectEvents == nil {
		return unsupported("Native EventBridge publication is not configured.")
	}
	// EventBridge has a distinct wire schema and does not form-encode the key.
	fields["key"] = object.Key.Name
	if etag, ok := fields["eTag"]; ok {
		fields["etag"] = etag
		delete(fields, "eTag")
	}
	if version, ok := fields["versionId"]; ok {
		fields["version-id"] = version
		delete(fields, "versionId")
	}
	if annotation, ok := fields["hasObjectAnnotation"]; ok {
		fields["has-object-annotation"] = annotation
		delete(fields, "hasObjectAnnotation")
	}
	requester := m.AccountID
	if m.ServicePrincipal.Name != "" {
		requester = m.ServicePrincipal.Name
	}
	detail := map[string]any{
		"version": "0", "event-version": "1.2", "bucket": map[string]any{"name": bucket.Key.Name},
		"object": fields, "request-id": m.RequestID, "requester": requester,
		"source-ip-address": m.SourceIP, "reason": "PutObject",
	}
	detailType := "Object Created"
	switch name {
	case "ObjectCreated:Copy":
		detail["reason"] = "CopyObject"
	case "ObjectCreated:CompleteMultipartUpload":
		detail["reason"] = "CompleteMultipartUpload"
	}
	if strings.HasPrefix(name, "ObjectRemoved:") {
		detailType = "Object Deleted"
		detail["reason"] = "DeleteObject"
		detail["deletion-type"] = "Permanently Deleted"
		if name == "ObjectRemoved:DeleteMarkerCreated" {
			detail["deletion-type"] = "Delete Marker Created"
		}
	}
	if tagging {
		delete(detail, "reason")
		detailType = "Object Tags Added"
		if name == "ObjectTagging:Delete" {
			detailType = "Object Tags Deleted"
		}
	}
	if acl {
		delete(detail, "reason")
		detailType = "Object ACL Updated"
	}
	if retention {
		delete(detail, "reason")
		detailType = "Object Retention Updated"
		if data := retentionEventData(object.Retention, at, true); data != nil {
			detail["object-retention-event-data"] = data
		}
	}
	if restore != nil {
		delete(fields, "sequencer")
		delete(detail, "reason")
		detail["source-storage-class"] = object.StorageClass
		detailType = "Object Restore Initiated"
		if systemRestore {
			delete(detail, "source-ip-address")
			detailType = "Object Restore Expired"
		}
		if name == "ObjectRestore:Completed" {
			detailType = "Object Restore Completed"
			if object.StorageClass != "INTELLIGENT_TIERING" {
				detail["restore-expiry-time"] = restore.Due.UTC().Format(time.RFC3339)
			}
		}
	}
	if lifecycle {
		detailType = lifecycleEventBridgeDetail(detail, fields, object, name)
	}
	if tiering {
		detailType = tieringEventBridgeDetail(detail, object)
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	return s.objectEvents.PublishObjectEvent(ctx, bucket, at, detailType, string(payload), c.eventID)
}

func (s *Service) notifyRemoval(tx Transaction, c *apiCall, bucket BucketRecord, key string, explicit bool, result objectRemoval) error {
	name := "ObjectRemoved:Delete"
	if !explicit && bucket.Versioning != "" {
		name = "ObjectRemoved:DeleteMarkerCreated"
	}
	return s.notifyObject(tx, c, bucket, ObjectRecord{Key: ObjectKey{Bucket: bucket.Key, Name: key}, VersionID: result.version, Sequence: result.sequence}, name)
}

func retentionEventData(retention ObjectRetention, at time.Time, eventBridge bool) map[string]any {
	if retention.Mode == "" {
		return nil
	}
	untilKey, holdKey, durationKey := "retainUntilDate", "eventHold", "eventHoldDuration"
	if eventBridge {
		untilKey, holdKey, durationKey = "retain-until-date", "event-hold", "event-hold-duration"
	}
	out := map[string]any{"mode": retention.Mode, untilKey: retention.until(at).UTC().Format("2006-01-02T15:04:05.000Z")}
	if retention.EventHold != "" {
		out[holdKey] = retention.EventHold
	}
	if retention.EventHoldDuration.Days != 0 {
		out[durationKey] = map[string]int32{"days": retention.EventHoldDuration.Days}
	} else if retention.EventHoldDuration.Years != 0 {
		out[durationKey] = map[string]int32{"years": retention.EventHoldDuration.Years}
	}
	return out
}
