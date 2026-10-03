package s3

import (
	"context"
	"encoding/json"

	"stackd/internal/scheduler"
)

// Restore work is fenced by the existing version identity, deadline and phase.
// No additional durable job ID or scheduler is needed, including after reopen.
type objectRestoreJobs struct{ service *Service }

func (source objectRestoreJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	var found bool
	err := source.service.repository.View(ctx, func(r Reader) error {
		state, err := r.NextObjectRestore()
		if err != nil || state == nil {
			return err
		}
		key, err := json.Marshal(state.Key)
		if err != nil {
			return err
		}
		job = scheduler.Job{Key: string(key), Version: restorePhase(state), Due: state.Due}
		found = true
		return nil
	})
	return job, found, err
}

func (source objectRestoreJobs) Run(ctx context.Context, job scheduler.Job) error {
	var key ObjectVersionKey
	if err := json.Unmarshal([]byte(job.Key), &key); err != nil {
		return err
	}
	s := source.service
	return s.repository.Update(ctx, func(tx Transaction) error {
		state, err := tx.ObjectRestore(key)
		if err != nil || state == nil {
			return err
		}
		if !state.Due.Equal(job.Due) || restorePhase(state) != job.Version {
			return nil
		}
		object, err := tx.ObjectVersion(key)
		if err != nil {
			return err
		}
		bucket, err := tx.Bucket(key.Bucket)
		if err != nil {
			return err
		}
		if !state.Ongoing {
			return s.expireObjectRestore(tx, bucket, object, state)
		}
		// Internal transitions occur at their persisted deadline, not the
		// driver's advanced horizon. One large clock step and many small steps
		// therefore expose identical completion and expiration boundaries.
		state.Ongoing = false
		if object.StorageClass == "INTELLIGENT_TIERING" {
			initializeObjectTiering(&object, job.Due)
			if err := tx.SetObjectTiering(key, object.CreatedOrder, object.Tiering); err != nil {
				return err
			}
			if err := tx.DeleteObjectRestore(key); err != nil {
				return err
			}
		} else {
			state.Due = objectDayDeadline(job.Due, state.Days)
			if err := tx.PutObjectRestore(*state); err != nil {
				return err
			}
		}
		c := &apiCall{eventID: state.ParentEventID}
		return s.notifyObjectEvent(tx, c, bucket, object, "ObjectRestore:Completed", state, nil, job.Due)
	})
}

func restorePhase(state *ObjectRestore) uint64 {
	if state.Ongoing {
		return 1
	}
	return 2
}

func (s *Service) expireObjectRestore(tx Transaction, bucket BucketRecord, object ObjectRecord, state *ObjectRestore) error {
	if err := tx.DeleteObjectRestore(state.Key); err != nil {
		return err
	}
	c := &apiCall{eventID: state.ParentEventID}
	return s.notifyObjectEvent(tx, c, bucket, object, "ObjectRestore:Delete", state, nil, state.Due)
}
