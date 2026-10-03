package s3

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// inventoryRows reads a single metadata snapshot. It never invokes customer
// List/Get operations, reads payloads, or changes access/tiering state.
func inventoryRows(r Reader, bucket BucketRecord, config InventoryConfiguration, at time.Time, columns []inventoryColumn) ([][]any, error) {
	var lifecycle *LifecycleConfiguration
	var err error
	needReplication, needExpiration, needTags := false, false, false
	for _, column := range columns {
		needReplication = needReplication || column.Name == "ReplicationStatus" || column.Name == "LifecycleExpirationDate"
		needExpiration = needExpiration || column.Name == "LifecycleExpirationDate"
	}
	if needExpiration {
		lifecycle, err = r.BucketLifecycle(bucket.Key)
		if err != nil {
			return nil, err
		}
		if lifecycle != nil {
			for _, rule := range lifecycle.Rules {
				needTags = needTags || rule.Enabled && len(rule.Filter.Tags) != 0 && (rule.Expiration != nil || rule.NoncurrentExpiration != nil)
			}
		}
	}
	prefix := ""
	if config.FilterPrefix != nil {
		prefix = *config.FilterPrefix
	}
	versions := VersionQuery{Bucket: bucket.Key, Prefix: prefix, Limit: 1000}
	objects := ObjectQuery{Bucket: bucket.Key, Prefix: prefix, Limit: 1000}
	var rows [][]any
	var previous ObjectKey
	var successor time.Time
	var newer int32
	for {
		var page []ObjectRecord
		if config.AllVersions {
			page, err = r.ObjectVersions(versions)
		} else {
			page, err = r.Objects(objects)
		}
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return rows, nil
		}
		for _, object := range page {
			latest := !config.AllVersions || previous != object.Key
			if latest {
				newer = 0
			}
			status := ""
			if needReplication {
				status, err = objectReplicationStatus(r, object)
				if err != nil {
					return nil, err
				}
			}
			var expiration any
			if needExpiration && lifecycle != nil && !object.DeleteMarker && status != "FAILED" && status != "PENDING" {
				var tags []Tag
				if needTags {
					tags, err = r.ObjectTags(object.VersionKey())
					if err != nil {
						return nil, err
					}
				}
				// Versioned current expiration adds a marker even when the
				// retained version is locked; permanent deletion cannot.
				protected := object.LegalHold == "ON" || object.Retention.protected(at)
				if !protected || latest && bucket.Versioning != "" {
					if deadline, _, found := lifecycleVersionExpiration(lifecycle, object, tags, latest, successor, newer); found {
						expiration = deadline
					}
				}
			}
			row := make([]any, len(columns))
			for i, column := range columns {
				row[i], err = inventoryValue(bucket, object, at, column.Name, latest, status, expiration)
				if err != nil {
					return nil, err
				}
			}
			rows = append(rows, row)
			if !latest {
				newer++
			}
			previous, successor = object.Key, object.Modified
		}
		last := page[len(page)-1]
		if config.AllVersions {
			versions.AfterKey, versions.AfterOrder = last.Key.Name, new(last.CreatedOrder)
		} else {
			objects.After = last.Key.Name
		}
	}
}

func inventoryValue(bucket BucketRecord, object ObjectRecord, at time.Time, column string, latest bool, replication string, expiration any) (any, error) {
	// Markers retain identity, time, ownership and replication metadata, but
	// have no payload, encryption, checksum, storage tier or object retention.
	switch column {
	case "Bucket":
		return bucket.Key.Name, nil
	case "Key":
		return object.Key.Name, nil
	case "VersionId":
		if object.VersionID == "null" {
			return "", nil
		}
		return object.VersionID, nil
	case "IsLatest":
		return latest, nil
	case "IsDeleteMarker":
		return object.DeleteMarker, nil
	case "LastModifiedDate":
		return object.Modified, nil
	case "ReplicationStatus":
		return inventoryString(replication), nil
	case "ObjectOwner":
		return originalACL(bucket, object.ACL).OwnerID, nil
	case "ObjectAccessControlList":
		return inventoryACL(originalACL(bucket, object.ACL))
	case "LifecycleExpirationDate":
		return expiration, nil
	}
	if object.DeleteMarker {
		return nil, nil
	}
	switch column {
	case "Size":
		return object.Size, nil
	case "ETag":
		return inventoryString(strings.Trim(object.ETag, "\"")), nil
	case "StorageClass":
		return storageClassName(object.StorageClass), nil
	case "IsMultipartUploaded":
		return object.UploadID != "", nil
	case "EncryptionStatus":
		switch object.EncryptionAlgorithm {
		case "AES256":
			return "SSE-S3", nil
		case "aws:kms":
			return "SSE-KMS", nil
		case "aws:kms:dsse":
			return "DSSE-KMS", nil
		case "SSE-C":
			return "SSE-C", nil
		case "":
			return "NOT-SSE", nil
		default:
			return nil, fmt.Errorf("unknown inventory encryption algorithm %q", object.EncryptionAlgorithm)
		}
	case "ObjectLockRetainUntilDate":
		if until := object.Retention.until(at); !until.IsZero() {
			return until, nil
		}
		return nil, nil
	case "ObjectLockMode":
		return inventoryString(object.Retention.Mode), nil
	case "ObjectLockLegalHoldStatus":
		if object.LegalHold == "ON" {
			return "ON", nil
		}
		return "OFF", nil
	case "ObjectLockEventHoldStatus":
		return inventoryString(object.Retention.EventHold), nil
	case "ObjectLockEventHoldDuration", "ObjectLockEventHoldDurationUnit":
		period := object.Retention.EventHoldDuration
		if object.Retention.EventHold == "" || period.Days == 0 && period.Years == 0 {
			return nil, nil
		}
		duration, unit := period.Days, "DAYS"
		if period.Years != 0 {
			duration, unit = period.Years, "YEARS"
		}
		if column == "ObjectLockEventHoldDurationUnit" {
			return unit, nil
		}
		return int64(duration), nil
	case "IntelligentTieringAccessTier":
		return inventoryAccessTier(object, at), nil
	case "BucketKeyStatus":
		// S3 Bucket Key writes are rejected by the encryption owner. No
		// published version can use one; bucket defaults are not provenance.
		return "DISABLED", nil
	case "ChecksumAlgorithm":
		return inventoryString(object.ChecksumAlgorithm), nil
	default:
		return nil, fmt.Errorf("unknown inventory column %q", column)
	}
}

func inventoryString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func inventoryAccessTier(object ObjectRecord, at time.Time) any {
	if object.StorageClass != "INTELLIGENT_TIERING" {
		return nil
	}
	// Unmonitored small objects remain in Frequent Access. The other online
	// tiers are billing views of the existing last-access timestamp.
	if object.Tiering == nil {
		return "FREQUENT"
	}
	switch object.Tiering.ArchiveTier {
	case DeepArchiveAccessTier:
		return "DEEP_ARCHIVE"
	case ArchiveAccessTier:
		return "ARCHIVE"
	}
	if !at.Before(object.Tiering.Accessed.AddDate(0, 0, 90)) {
		return "ARCHIVE_INSTANT_ACCESS"
	}
	if !at.Before(object.Tiering.Accessed.AddDate(0, 0, 30)) {
		return "INFREQUENT"
	}
	return "FREQUENT"
}

func inventoryACL(acl *AccessControlList) (string, error) {
	type grant struct {
		CanonicalID string `json:"canonicalId,omitempty"`
		URI         string `json:"uri,omitempty"`
		Type        string `json:"type"`
		Permission  string `json:"permission"`
	}
	report := struct {
		Version string  `json:"version"`
		Status  string  `json:"status"`
		Grants  []grant `json:"grants"`
	}{Version: "2022-11-10", Status: "AVAILABLE", Grants: make([]grant, 0, len(acl.Grants))}
	for _, stored := range acl.Grants {
		report.Grants = append(report.Grants, grant{CanonicalID: stored.ID, URI: stored.URI, Type: stored.Type, Permission: stored.Permission})
	}
	data, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}
