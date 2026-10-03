package glue

import (
	"context"
	"errors"

	"stackd/internal/scheduler"
)

// Deletions use a one-second local scheduling interval, not an AWS latency
// guarantee. Retained deadlines and current status fence stale scheduler work.
type registryJobs struct{ s *Service }

func registryLifecycleKey(v RegistryLifecycle) string {
	switch v.Kind {
	case "registry":
		return "registry:" + v.Registry.ARN("registry")
	case "schema":
		return "schema:" + v.Schema.ARN()
	default:
		return "version:" + v.VersionID
	}
}
func (j registryJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var v RegistryLifecycle
	err := j.s.repository.View(ctx, func(r Reader) error { var err error; v, err = r.NextRegistryLifecycle(); return err })
	if errors.Is(err, ErrNotFound) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: registryLifecycleKey(v), Due: v.Due}, true, nil
}
func (j registryJobs) Run(ctx context.Context, job scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		v, err := tx.NextRegistryLifecycle()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if registryLifecycleKey(v) != job.Key || !v.Due.Equal(job.Due) || v.Due.After(j.s.clock.Now()) {
			return nil
		}
		switch v.Kind {
		case "registry":
			return tx.DeleteRegistry(v.Registry)
		case "schema":
			return tx.DeleteSchema(v.Schema)
		case "version":
			version, err := tx.SchemaVersionByID(v.Schema.Scope, v.VersionID)
			if err != nil {
				return err
			}
			if err := tx.DeleteSchemaVersion(version.Key); err != nil {
				return err
			}
			schema, err := tx.Schema(v.Schema)
			if err != nil {
				return err
			}
			if schema.LatestVersion == version.Key.Number {
				versions, err := tx.SchemaVersions(v.Schema)
				if err != nil {
					return err
				}
				schema.LatestVersion = 0
				for _, candidate := range versions {
					if candidate.Status != "DELETING" {
						schema.LatestVersion = candidate.Key.Number
						break
					}
				}
				schema.Updated = j.s.clock.Now().UTC()
				return tx.PutSchema(schema)
			}
		}
		return nil
	})
}
