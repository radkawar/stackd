package dynamodb

import (
	"maps"
	"strconv"

	api "stackd/internal/awsapi/dynamodb"
)

// Length-prefixing the already canonical typed scalars keeps arbitrary string
// and binary keys unambiguous, independent of attribute and schema order.
func replicaKeyID(schema api.KeySchema, key api.Key) string {
	id := capacityKeyID("", schema, key)
	return strconv.Itoa(len(id.partition)) + ":" + id.partition + id.sort
}

func replicaImagesEqual(a, b api.AttributeMap) bool {
	return maps.EqualFunc(a, b, AttributeValuesEqual)
}

// Publication and conflict markers share the capture-removal transaction. A
// successful no-op is not a new conflicting write, including numeric spelling
// changes and set reordering. Incoming absolute images never echo into the log.
func publishReplicaMutation(tx Transaction, pending *MutationCapture, source MutationSource, item MutationItem, after api.AttributeMap) error {
	if source.ReplicationGroupID == "" {
		return nil
	}
	keyID := replicaKeyID(source.KeySchema, item.Key)
	version := pending.Version
	if item.ReplicaSequence != 0 {
		expected, err := tx.ReplicaChange(source.ReplicationGroupID, item.ReplicaSequence)
		if err != nil {
			return err
		}
		if !replicaImagesEqual(after, expected.Item) {
			return nil
		}
		version = expected.Version
	} else {
		if replicaImagesEqual(item.Before, after) {
			return nil
		}
		change := ReplicaChange{GroupID: source.ReplicationGroupID, Version: version, At: pending.At,
			Origin: source.Table, OriginPhysicalName: source.PhysicalName, KeyID: keyID, Key: item.Key, Item: after}
		if err := tx.AppendReplicaChanges([]ReplicaChange{change}); err != nil {
			return err
		}
	}
	current, err := tx.ReplicaVersion(source.PhysicalName, keyID)
	if err != nil {
		return err
	}
	if current >= version {
		return nil
	}
	return tx.PutReplicaVersion(source.PhysicalName, keyID, version)
}
