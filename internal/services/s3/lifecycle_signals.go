package s3

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

func lifecycleNotificationRecord(record, objectFields map[string]any, object ObjectRecord, name string) {
	switch name {
	case "LifecycleExpiration:DeleteMarkerCreated":
		objectFields["eTag"] = "d41d8cd98f00b204e9800998ecf8427e"
	case "LifecycleTransition":
		delete(objectFields, "sequencer")
		objectFields["size"], objectFields["eTag"] = object.Size, strings.Trim(object.ETag, "\"")
		record["lifecycleEventData"] = map[string]any{
			"transitionEventData": map[string]any{"destinationStorageClass": object.StorageClass},
		}
	}
}

func lifecycleEventBridgeDetail(detail, objectFields map[string]any, object ObjectRecord, name string) string {
	delete(detail, "source-ip-address")
	if name == "LifecycleTransition" {
		delete(detail, "reason")
		delete(objectFields, "sequencer")
		objectFields["size"], objectFields["etag"] = object.Size, strings.Trim(object.ETag, "\"")
		detail["destination-storage-class"] = object.StorageClass
		return "Object Storage Class Changed"
	}
	detail["reason"] = "Lifecycle Expiration"
	detail["deletion-type"] = "Permanently Deleted"
	if name == "LifecycleExpiration:DeleteMarkerCreated" {
		detail["deletion-type"] = "Delete Marker Created"
		objectFields["etag"] = "d41d8cd98f00b204e9800998ecf8427e"
	}
	return "Object Deleted"
}

func lifecycleTransitionLogOperation(storageClass string) string {
	switch storageClass {
	case "STANDARD_IA":
		return "S3.TRANSITION_SIA.OBJECT"
	case "ONEZONE_IA":
		return "S3.TRANSITION_ZIA.OBJECT"
	case "INTELLIGENT_TIERING":
		return "S3.TRANSITION_INT.OBJECT"
	case "GLACIER_IR":
		return "S3.TRANSITION_GIR.OBJECT"
	case "DEEP_ARCHIVE":
		return "S3.TRANSITION_GDA.OBJECT"
	default:
		return "S3.TRANSITION.OBJECT"
	}
}

// Lifecycle owns internal mutations, not HTTP requests. Log the documented
// operation and retained object identity without manufacturing a transport,
// caller, status code or timing measurement. Delivery uses the ordinary queue.
func recordLifecycleAccessLog(tx Transaction, bucket BucketRecord, object ObjectRecord, operation string, at time.Time) error {
	config, err := tx.BucketLogging(bucket.Key)
	if err != nil || config == nil {
		return err
	}
	size := object.Size
	if object.DeleteMarker || operation == "S3.DELETE.UPLOAD" {
		size = -1
	}
	record := accessLogRecord{
		owner: canonicalID(bucket.Key.Partition, bucket.AccountID), bucket: bucket.Key.Name, at: at,
		operation: operation, key: object.Key.Name, versionID: object.VersionID,
		status: -1, objectSize: size, totalMillis: -1, turnaroundMillis: -1,
	}
	return tx.PutAccessLogDelivery(AccessLogDelivery{
		ID: uuid.NewString(), Source: bucket.Key, AccountID: bucket.AccountID, Region: bucket.Region,
		Destination: *config, At: at, Due: at.Add(accessLogInterval), Record: record.format(),
	})
}
