package secretsmanager

import (
	"context"
	"errors"

	"stackd/internal/scheduler"
)

type replicationJobs struct{ s *Service }

func replicationJob(replica ReplicaRecord) scheduler.Job {
	return scheduler.Job{
		Key:     "replication:" + replica.PrimaryARN + ":" + replica.Key.Region,
		Version: uint64(replica.Due.UnixNano()), Due: *replica.Due,
	}
}

func (j replicationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var selected scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		replica, err := r.NextReplica()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		selected, found = replicationJob(replica), true
		return nil
	})
	return selected, found, err
}

func (j replicationJobs) Run(ctx context.Context, selected scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		replica, err := tx.NextReplica()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if replicationJob(replica) != selected || selected.Due.After(j.s.clock.Now().UTC()) {
			return nil
		}
		source, err := tx.Secret(replica.Key.Primary)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err != nil || source.ARN != replica.PrimaryARN || source.Deleted != nil {
			// Only remove this old link. A recreated source or destination is not
			// owned by the job, even when its regional name is identical.
			return tx.DeleteReplica(replica.Key)
		}
		if replica.Status != "InProgress" {
			replica.Due = nil
			return tx.PutReplica(replica)
		}
		target, err := tx.Secret(replicaSecretKey(source.Key, replica.Key.Region))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err != nil || !matchesReplica(target, replica) {
			replica.Status, replica.StatusMessage, replica.Due = "Failed", "Replication failed: The replica secret no longer exists.", nil
			return tx.PutReplica(replica)
		}
		// The originating transaction already re-encrypted and installed all
		// values. No caller identity, payload snapshot or external effect survives.
		replica.Status, replica.StatusMessage, replica.Due = "InSync", "Replication succeeded", nil
		return tx.PutReplica(replica)
	})
}
