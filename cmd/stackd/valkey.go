package main

import (
	"context"
	"errors"
	"fmt"

	runtime "stackd/engine/valkey"
	"stackd/storage"
	"stackd/storage/elasticache"
	"stackd/storage/memorydb"
)

// Retained SQLite controllers detach; an ephemeral controller must retire the
// native resources whose only metadata owner is about to disappear.
func removeValkeyDeployments(ctx context.Context, backends *storage.Backends, engine runtime.Runtime) error {
	var clusters, snapshots []string
	if err := backends.ElastiCache.View(ctx, func(r elasticache.Reader) error {
		rows, err := r.AllClusters()
		if err != nil {
			return err
		}
		for _, v := range rows {
			clusters = append(clusters, v.RuntimeID)
		}
		backups, err := r.AllSnapshots()
		if err != nil {
			return err
		}
		for _, v := range backups {
			snapshots = append(snapshots, v.RuntimeID)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := backends.MemoryDB.View(ctx, func(r memorydb.Reader) error {
		rows, err := r.AllClusters()
		if err != nil {
			return err
		}
		for _, v := range rows {
			clusters = append(clusters, v.RuntimeID)
		}
		backups, err := r.AllSnapshots()
		if err != nil {
			return err
		}
		for _, v := range backups {
			snapshots = append(snapshots, v.RuntimeID)
		}
		return nil
	}); err != nil {
		return err
	}
	var result error
	for _, id := range clusters {
		if id != "" {
			if err := engine.Delete(ctx, id); err != nil {
				result = errors.Join(result, fmt.Errorf("remove ephemeral Valkey deployment: %w", err))
			}
		}
	}
	for _, id := range snapshots {
		if id != "" {
			if err := engine.DeleteSnapshot(ctx, id); err != nil {
				result = errors.Join(result, fmt.Errorf("remove ephemeral Valkey snapshot: %w", err))
			}
		}
	}
	return result
}
