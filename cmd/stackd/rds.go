package main

import (
	"context"
	"errors"
	"fmt"

	runtime "stackd/engine/rds"
	store "stackd/storage/rds"
)

// Ephemeral controllers cannot leave unreachable native data after their sole
// metadata owner exits. Persistent controllers intentionally detach instead.
func removeRDSDatabases(ctx context.Context, repository store.Repository, engine runtime.Runtime) error {
	var databases []store.Database
	var snapshots []store.Snapshot
	if err := repository.View(ctx, func(reader store.Reader) error {
		var err error
		databases, err = reader.AllDatabases()
		if err != nil {
			return err
		}
		snapshots, err = reader.AllSnapshots()
		return err
	}); err != nil {
		return err
	}
	var result error
	seen := map[string]bool{}
	for _, database := range databases {
		if database.RuntimeID == "" || seen[database.RuntimeID] {
			continue
		}
		seen[database.RuntimeID] = true
		if err := engine.Delete(ctx, database.RuntimeID); err != nil {
			result = errors.Join(result, fmt.Errorf("remove ephemeral RDS database %s: %w", database.Key.ARN(), err))
		}
	}
	for _, snapshot := range snapshots {
		if err := engine.DeleteSnapshot(ctx, snapshot.RuntimeID); err != nil {
			result = errors.Join(result, fmt.Errorf("remove ephemeral RDS snapshot %s: %w", snapshot.Key.ARN(), err))
		}
	}
	return result
}
