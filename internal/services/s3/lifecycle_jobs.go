package s3

import (
	"context"
	"encoding/json"
	"time"

	"stackd/internal/scheduler"
)

type lifecycleJobs struct{ service *Service }

func (source lifecycleJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	var found bool
	err := source.service.repository.View(ctx, func(reader Reader) error {
		scan, err := reader.NextLifecycleScan()
		if err != nil || scan == nil {
			return err
		}
		key, err := json.Marshal(scan.Bucket)
		if err != nil {
			return err
		}
		job, found = scheduler.Job{Key: string(key), Due: scan.Due}, true
		return nil
	})
	return job, found, err
}

func (source lifecycleJobs) Run(ctx context.Context, job scheduler.Job) error {
	var key BucketKey
	if err := json.Unmarshal([]byte(job.Key), &key); err != nil {
		return err
	}
	s := source.service
	return s.repository.Update(ctx, func(tx Transaction) error {
		config, err := tx.BucketLifecycle(key)
		if err != nil || config == nil || config.NextScan == nil {
			return err
		}
		if !config.NextScan.Equal(job.Due) {
			return nil
		}
		bucket, err := tx.Bucket(key)
		if err != nil {
			return err
		}
		if err := s.expireLifecycleVersions(tx, bucket, config, job.Due); err != nil {
			return err
		}
		if err := s.abortLifecycleUploads(tx, bucket, config, job.Due); err != nil {
			return err
		}
		// Run at the selected day, not the advanced clock horizon. A single
		// large advance and several daily advances observe the same actions.
		return tx.AdvanceLifecycleScan(key, job.Due.AddDate(0, 0, 1))
	})
}

func (s *Service) expireLifecycleVersions(tx Transaction, bucket BucketRecord, config *LifecycleConfiguration, at time.Time) error {
	query := VersionQuery{Bucket: bucket.Key, Limit: 1000}
	var previous ObjectKey
	var successor time.Time
	var newer int32
	hasTags := false
	for _, rule := range config.Rules {
		hasTags = hasTags || rule.Enabled && len(rule.Filter.Tags) != 0
	}
	for {
		versions, err := tx.ObjectVersions(query)
		if err != nil || len(versions) == 0 {
			return err
		}
		for _, object := range versions {
			current := previous != object.Key
			if current {
				newer = 0
			}
			if !current && bucket.Versioning == "Suspended" && object.VersionID == "null" {
				// Expiring the numbered current version can replace an older
				// null slot already present in this page with a new marker.
				stored, err := tx.ObjectVersion(object.VersionKey())
				if err != nil {
					return err
				}
				if stored.CreatedOrder != object.CreatedOrder {
					continue
				}
			}
			var tags []Tag
			if hasTags && !object.DeleteMarker {
				tags, err = tx.ObjectTags(object.VersionKey())
				if err != nil {
					return err
				}
			}
			action := chooseLifecycleAction(bucket, config, object, tags, current, successor, newer, at)
			if action.kind != lifecycleNone {
				if err := s.applyLifecycleAction(tx, bucket, config, object, action, current, at); err != nil {
					return err
				}
			}
			if !current {
				newer++
			}
			previous, successor = object.Key, object.Modified
		}
		last := versions[len(versions)-1]
		query.AfterKey, query.AfterOrder = last.Key.Name, new(last.CreatedOrder)
	}
}

type lifecycleActionKind uint8

const (
	lifecycleNone lifecycleActionKind = iota
	lifecycleMarker
	lifecycleTransition
	lifecycleDelete
)

type lifecycleAction struct {
	kind         lifecycleActionKind
	storageClass string
}

func chooseLifecycleAction(bucket BucketRecord, config *LifecycleConfiguration, object ObjectRecord, tags []Tag, current bool, successor time.Time, newer int32, at time.Time) lifecycleAction {
	var selected lifecycleAction
	protected := object.LegalHold == "ON" || object.Retention.protected(at)
	selectTransition := func(class string) {
		if selected.kind < lifecycleTransition || selected.kind == lifecycleTransition && lifecycleClassPriority(class) > lifecycleClassPriority(selected.storageClass) {
			selected = lifecycleAction{kind: lifecycleTransition, storageClass: class}
		}
	}
	for _, rule := range config.Rules {
		if !rule.Enabled || !objectFilterMatches(rule.Filter, object, tags) {
			continue
		}
		if current {
			if expiration := rule.Expiration; expiration != nil {
				deadline, timed := expiration.deadline(object.Modified)
				eligible := timed && !deadline.After(at)
				if object.DeleteMarker {
					eligible = eligible || expiration.ExpiredObjectDeleteMarker != nil && *expiration.ExpiredObjectDeleteMarker
				}
				if eligible {
					if object.DeleteMarker || bucket.Versioning == "" {
						if !protected {
							return lifecycleAction{kind: lifecycleDelete}
						}
					} else if selected.kind < lifecycleMarker {
						selected.kind = lifecycleMarker
					}
				}
			}
			if !object.DeleteMarker {
				for _, transition := range rule.Transitions {
					deadline, _ := transition.deadline(object.Modified)
					if !deadline.After(at) && lifecycleObjectTransitionAllowed(object, transition.StorageClass, at) && lifecycleTransitionSize(config, rule.Filter, object, transition.StorageClass) {
						selectTransition(transition.StorageClass)
					}
				}
			}
		} else {
			if expiration := rule.NoncurrentExpiration; expiration != nil && !protected && lifecycleNoncurrentDue(*expiration, successor, newer, at) {
				return lifecycleAction{kind: lifecycleDelete}
			}
			if !object.DeleteMarker {
				for _, transition := range rule.NoncurrentTransitions {
					if lifecycleNoncurrentDue(transition.LifecycleNoncurrentExpiration, successor, newer, at) && lifecycleObjectTransitionAllowed(object, transition.StorageClass, at) && lifecycleTransitionSize(config, rule.Filter, object, transition.StorageClass) {
						selectTransition(transition.StorageClass)
					}
				}
			}
		}
	}
	return selected
}

func lifecycleNoncurrentDue(action LifecycleNoncurrentExpiration, successor time.Time, newer int32, at time.Time) bool {
	return (action.NewerNoncurrentVersions == nil || newer >= *action.NewerNoncurrentVersions) && !objectDayDeadline(successor, action.Days).After(at)
}

// Conflicting transitions prefer lower storage cost, except Intelligent-Tiering
// is explicitly favored over every destination other than Glacier and Deep.
func lifecycleClassPriority(class string) int {
	switch class {
	case "DEEP_ARCHIVE":
		return 6
	case "GLACIER":
		return 5
	case "INTELLIGENT_TIERING":
		return 4
	case "GLACIER_IR":
		return 3
	case "ONEZONE_IA":
		return 2
	default:
		return 1
	}
}

func (s *Service) applyLifecycleAction(tx Transaction, bucket BucketRecord, config *LifecycleConfiguration, object ObjectRecord, action lifecycleAction, current bool, at time.Time) error {
	status, err := objectReplicationStatus(tx, object)
	if err != nil || status == "PENDING" || status == "FAILED" {
		return err
	}
	if current && object.DeleteMarker {
		older, err := tx.ObjectVersions(VersionQuery{Bucket: bucket.Key, Prefix: object.Key.Name, AfterKey: object.Key.Name, AfterOrder: new(object.CreatedOrder), Limit: 1})
		if err != nil {
			return err
		}
		if len(older) != 0 && older[0].Key == object.Key {
			return nil
		}
	}
	c := &apiCall{eventID: config.ParentEventID}
	name, operation := "LifecycleExpiration:Delete", "S3.EXPIRE.OBJECT"
	switch action.kind {
	case lifecycleDelete:
		object.Sequence, err = tx.DeleteObject(object.VersionKey())
	case lifecycleMarker:
		object = ObjectRecord{Key: object.Key, DeleteMarker: true, Modified: at.UTC()}
		object.VersionID, err = issueVersion(bucket.Versioning)
		if err == nil {
			object.Sequence, err = tx.PutObject(object, nil)
		}
		name, operation = "LifecycleExpiration:DeleteMarkerCreated", "S3.CREATE.DELETEMARKER"
	case lifecycleTransition:
		object.Sequence, err = tx.TransitionObject(object.VersionKey(), action.storageClass)
		object.StorageClass = action.storageClass
		if err == nil {
			initializeObjectTiering(&object, at)
			err = tx.SetObjectTiering(object.VersionKey(), object.CreatedOrder, object.Tiering)
		}
		name, operation = "LifecycleTransition", lifecycleTransitionLogOperation(action.storageClass)
	}
	if err != nil {
		return err
	}
	// Lifecycle does not replicate marker creation or invoke public object
	// APIs. Notifications and access-log intent commit with the state change.
	if err := s.notifyObjectEvent(tx, c, bucket, object, name, nil, nil, at); err != nil {
		return err
	}
	return recordLifecycleAccessLog(tx, bucket, object, operation, at)
}

func (s *Service) abortLifecycleUploads(tx Transaction, bucket BucketRecord, config *LifecycleConfiguration, at time.Time) error {
	query := MultipartQuery{Bucket: bucket.Key, Limit: 1000}
	for {
		uploads, err := tx.MultipartUploads(query)
		if err != nil || len(uploads) == 0 {
			return err
		}
		for _, upload := range uploads {
			for _, rule := range config.Rules {
				if rule.Enabled && rule.AbortIncompleteDays != nil && objectFilterMatches(rule.Filter, upload.ObjectRecord, nil) && !objectDayDeadline(upload.Modified, *rule.AbortIncompleteDays).After(at) {
					if err := tx.DeleteMultipartUpload(upload.UploadKey()); err != nil {
						return err
					}
					if err := recordLifecycleAccessLog(tx, bucket, upload.ObjectRecord, "S3.DELETE.UPLOAD", at); err != nil {
						return err
					}
					break
				}
			}
		}
		last := uploads[len(uploads)-1]
		query.AfterKey, query.AfterOrder = last.Key.Name, new(last.CreatedOrder)
	}
}
