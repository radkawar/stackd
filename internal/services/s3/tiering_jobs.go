package s3

import (
	"context"
	"encoding/json"
	"time"

	"stackd/internal/scheduler"
)

type tieringJobs struct{ service *Service }

func (source tieringJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	var found bool
	err := source.service.repository.View(ctx, func(reader Reader) error {
		scan, err := reader.NextTieringScan()
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

func (source tieringJobs) Run(ctx context.Context, job scheduler.Job) error {
	var key BucketKey
	if err := json.Unmarshal([]byte(job.Key), &key); err != nil {
		return err
	}
	s := source.service
	return s.repository.Update(ctx, func(tx Transaction) error {
		// Configuration changes can replace or cancel a selected scan. If a
		// different bucket is now earliest, let the driver select it first.
		scan, err := tx.NextTieringScan()
		if err != nil || scan == nil {
			return err
		}
		if scan.Bucket != key || !scan.Due.Equal(job.Due) {
			return nil
		}
		bucket, err := tx.Bucket(key)
		if err != nil {
			return err
		}
		configurations, err := tx.BucketTieringConfigurations(BucketConfigurationQuery{Bucket: key, Limit: 1000})
		if err != nil {
			return err
		}
		if err := s.archiveTieringVersions(tx, bucket, configurations, job.Due); err != nil {
			return err
		}
		return tx.SetTieringScan(key, new(job.Due.AddDate(0, 0, 1)))
	})
}

func (s *Service) archiveTieringVersions(tx Transaction, bucket BucketRecord, configurations []TieringConfiguration, at time.Time) error {
	hasTags := false
	for _, configuration := range configurations {
		hasTags = hasTags || configuration.Enabled && configuration.Filter != nil && len(configuration.Filter.Tags) != 0
	}
	query := VersionQuery{Bucket: bucket.Key, Limit: 1000}
	for {
		versions, err := tx.ObjectVersions(query)
		if err != nil || len(versions) == 0 {
			return err
		}
		for _, object := range versions {
			if object.Tiering == nil || object.Tiering.ArchiveTier == DeepArchiveAccessTier {
				continue
			}
			var tags []Tag
			if hasTags {
				tags, err = tx.ObjectTags(object.VersionKey())
				if err != nil {
					return err
				}
			}
			tier, parent := object.Tiering.ArchiveTier, ""
			for _, configuration := range configurations {
				if !configuration.Enabled || configuration.Filter != nil && !objectFilterMatches(*configuration.Filter, object, tags) {
					continue
				}
				for _, rule := range configuration.Tierings {
					if at.Before(object.Tiering.Accessed.AddDate(0, 0, int(rule.Days))) {
						continue
					}
					if tier == "" || tier == ArchiveAccessTier && rule.AccessTier == DeepArchiveAccessTier {
						tier, parent = rule.AccessTier, configuration.ParentEventID
					}
				}
			}
			if tier == object.Tiering.ArchiveTier {
				continue
			}
			state := *object.Tiering
			state.ArchiveTier = tier
			if err := tx.SetObjectTiering(object.VersionKey(), object.CreatedOrder, &state); err != nil {
				return err
			}
			object.Tiering = &state
			if err := s.notifyObjectEvent(tx, &apiCall{eventID: parent}, bucket, object, "IntelligentTiering", nil, nil, at); err != nil {
				return err
			}
		}
		last := versions[len(versions)-1]
		query.AfterKey, query.AfterOrder = last.Key.Name, new(last.CreatedOrder)
	}
}
