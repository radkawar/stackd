package main

import (
	"context"
	"errors"
	"fmt"
	runtime "stackd/engine/docdb"
	store "stackd/storage/docdb"
)

// Persistent controllers detach; ephemeral controllers retire exact native
// resources before discarding their sole metadata owner.
func removeDocumentDBDatabases(ctx context.Context, repository store.Repository, engine runtime.Runtime) error {
	var clusters []store.Cluster
	var snapshots []store.Snapshot
	if err := repository.View(ctx, func(r store.Reader) error {
		var err error
		clusters, err = r.Clusters()
		if err != nil {
			return err
		}
		snapshots, err = r.Snapshots()
		return err
	}); err != nil {
		return err
	}
	var result error
	for _, v := range clusters {
		if err := engine.Delete(ctx, v.RuntimeID); err != nil {
			result = errors.Join(result, fmt.Errorf("remove ephemeral DocumentDB cluster %s: %w", v.Key.ARN(), err))
		}
	}
	for _, v := range snapshots {
		if err := engine.DeleteSnapshot(ctx, v.RuntimeID); err != nil {
			result = errors.Join(result, fmt.Errorf("remove ephemeral DocumentDB snapshot %s: %w", v.Key.ARN(), err))
		}
	}
	return result
}
