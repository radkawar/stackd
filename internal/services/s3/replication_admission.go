package s3

import (
	"cmp"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

func replicationRuleMatches(rule ReplicationRule, object ObjectRecord, tags []Tag) bool {
	if !rule.Enabled || rule.Filter.Prefix != nil && !strings.HasPrefix(object.Key.Name, *rule.Filter.Prefix) {
		return false
	}
	if object.EncryptionAlgorithm == "aws:kms" && rule.SSEKMSObjects != "Enabled" {
		return false
	}
	for _, required := range rule.Filter.Tags {
		if !slices.Contains(tags, required) {
			return false
		}
	}
	return true
}

// enqueueObjectReplication is called by source mutation owners, independently of
// notification configuration. Private replica writes do not call it: replication
// does not recursively admit another object copy or echo metadata changes.
func (s *Service) enqueueObjectReplication(tx Transaction, c *apiCall, bucket BucketRecord, object ObjectRecord, operation ReplicationOperation) error {
	if operation == ReplicationObject && (object.Replica || object.StorageClass == "GLACIER" || object.StorageClass == "DEEP_ARCHIVE") {
		return nil
	}
	configuration, err := tx.BucketReplication(bucket.Key)
	if err != nil || configuration == nil {
		return err
	}
	tags, err := tx.ObjectTags(object.VersionKey())
	if err != nil {
		return err
	}
	metadata := operation != ReplicationObject && operation != ReplicationDelete
	var admitted map[BucketKey]bool
	if metadata && !object.Replica {
		states, err := tx.ReplicationStates(object.VersionKey())
		if err != nil {
			return err
		}
		admitted = make(map[BucketKey]bool, len(states))
		for _, state := range states {
			if state.Operation == ReplicationObject {
				admitted[state.Destination] = true
			}
		}
	}
	winners := make(map[BucketKey]*ReplicationRule)
	for i := range configuration.Rules {
		rule := &configuration.Rules[i]
		if !replicationRuleMatches(*rule, object, tags) {
			continue
		}
		if operation == ReplicationDelete && (rule.DeleteMarkerReplication == "Disabled" || len(rule.Filter.Tags) != 0) {
			continue
		}
		if metadata {
			if object.Replica {
				eligible, err := replicaMetadataTarget(tx, bucket.Key, object, *rule)
				if err != nil {
					return err
				}
				if !eligible {
					continue
				}
			} else if !admitted[rule.Destination.Bucket] {
				// Adding matching tags does not backfill an existing version.
				continue
			}
		}
		previous := winners[rule.Destination.Bucket]
		if previous == nil || replicationPriority(*rule) > replicationPriority(*previous) {
			winners[rule.Destination.Bucket] = rule
		}
	}
	selected := make([]*ReplicationRule, 0, len(winners))
	for _, rule := range winners {
		selected = append(selected, rule)
	}
	slices.SortFunc(selected, func(a, b *ReplicationRule) int {
		return cmp.Or(cmp.Compare(a.Destination.Bucket.Partition, b.Destination.Bucket.Partition), cmp.Compare(a.Destination.Bucket.Name, b.Destination.Bucket.Name))
	})
	if len(selected) != 0 && c.eventID == "" {
		c.eventID = uuid.NewString()
	}
	now := s.clock.Now()
	for _, rule := range selected {
		job := ReplicationJob{Source: object.VersionKey(), Destination: rule.Destination, Operation: operation,
			RoleARN: configuration.RoleARN, RuleID: rule.ID, ParentEventID: c.eventID, Created: now, Due: now.Add(time.Second)}
		if err := tx.PutReplicationJob(&job); err != nil {
			return err
		}
		if err := tx.PutReplicationState(ReplicationState{Source: job.Source, Destination: job.Destination.Bucket,
			Operation: operation, Sequence: job.Sequence, Status: "PENDING"}); err != nil {
			return err
		}
	}
	return nil
}

func replicationPriority(rule ReplicationRule) int32 {
	if rule.Priority == nil {
		return 0
	}
	return *rule.Priority
}

func replicaMetadataTarget(reader Reader, source BucketKey, object ObjectRecord, rule ReplicationRule) (bool, error) {
	if rule.ReplicaModifications != "Enabled" {
		return false, nil
	}
	key := ObjectVersionKey{ObjectKey: ObjectKey{Bucket: rule.Destination.Bucket, Name: object.Key.Name}, VersionID: object.VersionID}
	target, err := reader.ObjectVersion(key)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	configuration, err := reader.BucketReplication(rule.Destination.Bucket)
	if err != nil || configuration == nil {
		return false, err
	}
	tags, err := reader.ObjectTags(key)
	if err != nil {
		return false, err
	}
	for _, reverse := range configuration.Rules {
		if reverse.Destination.Bucket == source && reverse.ReplicaModifications == "Enabled" && replicationRuleMatches(reverse, target, tags) {
			return true, nil
		}
	}
	return false, nil
}
