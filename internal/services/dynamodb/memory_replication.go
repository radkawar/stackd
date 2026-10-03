package dynamodb

import (
	"cmp"
	"slices"
	"sort"

	api "stackd/internal/awsapi/dynamodb"
)

type replicaVersionKey struct {
	physicalName string
	keyID        string
}

func cloneReplicaBootstrap(v ReplicaBootstrap) ReplicaBootstrap {
	v.KeySchema = api.CloneKeySchema(v.KeySchema)
	v.AttributeDefinitions = api.CloneAttributeDefinitions(v.AttributeDefinitions)
	return v
}

func cloneReplicaChange(v ReplicaChange) ReplicaChange {
	v.Key = api.CloneKey(v.Key)
	v.Item = api.CloneAttributeMap(v.Item)
	return v
}

func (r memoryReader) ReplicaTables(groupID string) ([]TableRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []TableRecord
	for _, table := range r.s.tables {
		if table.Replica.GroupID != "" && (groupID == "" || table.Replica.GroupID == groupID) {
			out = append(out, cloneTableRecord(table))
		}
	}
	slices.SortFunc(out, compareTables)
	return out, nil
}

func (r memoryReader) ReplicaBootstrap(key TableKey) (ReplicaBootstrap, error) {
	if err := r.tx.Check(false); err != nil {
		return ReplicaBootstrap{}, err
	}
	v, ok := r.s.replicaBootstraps[key]
	if !ok {
		return ReplicaBootstrap{}, ErrNotFound
	}
	return cloneReplicaBootstrap(v), nil
}

func (r memoryReader) ReplicaBootstraps(databaseID string) ([]ReplicaBootstrap, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []ReplicaBootstrap
	for _, v := range r.s.replicaBootstraps {
		if databaseID == "" || v.SourceDatabaseID == databaseID {
			out = append(out, cloneReplicaBootstrap(v))
		}
	}
	slices.SortFunc(out, func(a, b ReplicaBootstrap) int {
		return cmp.Or(cmp.Compare(a.Table.Partition, b.Table.Partition), cmp.Compare(a.Table.AccountID, b.Table.AccountID), cmp.Compare(a.Table.Region, b.Table.Region), cmp.Compare(a.Table.Name, b.Table.Name))
	})
	return out, nil
}

func (r memoryReader) ReplicaSequence(groupID string) (int64, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	changes := r.s.replicaChanges[groupID]
	if len(changes) == 0 {
		return 0, nil
	}
	return changes[len(changes)-1].Sequence, nil
}

func (r memoryReader) ReplicaChange(groupID string, sequence int64) (ReplicaChange, error) {
	if err := r.tx.Check(false); err != nil {
		return ReplicaChange{}, err
	}
	changes := r.s.replicaChanges[groupID]
	index := sort.Search(len(changes), func(i int) bool { return changes[i].Sequence >= sequence })
	if index == len(changes) || changes[index].Sequence != sequence {
		return ReplicaChange{}, ErrNotFound
	}
	return cloneReplicaChange(changes[index]), nil
}

func (r memoryReader) ReplicaChanges(groupID string, after int64, limit int) ([]ReplicaChange, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	changes := r.s.replicaChanges[groupID]
	start := sort.Search(len(changes), func(i int) bool { return changes[i].Sequence > after })
	changes = changes[start:]
	if limit > 0 && len(changes) > limit {
		changes = changes[:limit]
	}
	var out []ReplicaChange
	if len(changes) != 0 {
		out = make([]ReplicaChange, len(changes))
		for i, v := range changes {
			out[i] = cloneReplicaChange(v)
		}
	}
	return out, nil
}

func (r memoryReader) ReplicaVersion(physicalName, keyID string) (int64, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	return r.s.replicaVersions[replicaVersionKey{physicalName, keyID}], nil
}

func (w memoryWriter) PutReplicaBootstrap(v ReplicaBootstrap) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.replicaBootstraps[v.Table] = cloneReplicaBootstrap(v)
	return nil
}

func (w memoryWriter) DeleteReplicaBootstrap(key TableKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.replicaBootstraps, key)
	delete(w.s.replicaBootstrapVersions, key)
	return nil
}

func (w memoryWriter) SnapshotReplicaVersions(target TableKey, sourcePhysicalName string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.replicaBootstraps[target]; !ok {
		return ErrNotFound
	}
	// Pins are immutable once retained, so transaction cloning only copies the
	// outer map. Replacing a pin never mutates an earlier transaction's map.
	versions := make(map[string]int64)
	for key, version := range w.s.replicaVersions {
		if key.physicalName == sourcePhysicalName {
			versions[key.keyID] = version
		}
	}
	w.s.replicaBootstrapVersions[target] = versions
	return nil
}

func (w memoryWriter) InstallReplicaVersions(target TableKey, targetPhysicalName string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.replicaBootstraps[target]; !ok {
		return ErrNotFound
	}
	if err := w.DeleteReplicaVersions(targetPhysicalName); err != nil {
		return err
	}
	for keyID, version := range w.s.replicaBootstrapVersions[target] {
		w.s.replicaVersions[replicaVersionKey{targetPhysicalName, keyID}] = version
	}
	return nil
}

func (w memoryWriter) PutReplicaVersion(physicalName, keyID string, version int64) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.replicaVersions[replicaVersionKey{physicalName, keyID}] = version
	return nil
}

func (w memoryWriter) DeleteReplicaVersions(physicalName string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key := range w.s.replicaVersions {
		if key.physicalName == physicalName {
			delete(w.s.replicaVersions, key)
		}
	}
	return nil
}

func (w memoryWriter) AppendReplicaChanges(changes []ReplicaChange) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	// Each transaction owns its slice headers. Only the invisible tail of a
	// retained backing array may be changed; retained images stay immutable.
	for _, v := range changes {
		w.s.replicaSequence++
		v = cloneReplicaChange(v)
		v.Sequence = w.s.replicaSequence
		w.s.replicaChanges[v.GroupID] = append(w.s.replicaChanges[v.GroupID], v)
	}
	return nil
}

func (w memoryWriter) TrimReplicaChanges(groupID string, throughSequence int64) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	changes := w.s.replicaChanges[groupID]
	start := sort.Search(len(changes), func(i int) bool { return changes[i].Sequence > throughSequence })
	if start == len(changes) {
		delete(w.s.replicaChanges, groupID)
	} else if start != 0 {
		// Copy only row headers, releasing acknowledged images without touching
		// shared payloads or the previous transaction's retained slice.
		w.s.replicaChanges[groupID] = slices.Clone(changes[start:])
	}

	var oldest int64
	pending := false
	for _, v := range w.s.replicaChanges[groupID] {
		if !pending || v.Version < oldest {
			oldest, pending = v.Version, true
		}
	}
	for _, capture := range w.s.mutationCaptures {
		for _, source := range capture.Sources {
			if source.ReplicationGroupID == groupID {
				if !pending || capture.Version < oldest {
					oldest, pending = capture.Version, true
				}
				break
			}
		}
	}

	members := make(map[string]struct{})
	for _, table := range w.s.tables {
		if table.Replica.GroupID == groupID && groupID != "" {
			members[table.PhysicalName] = struct{}{}
		}
	}
	for key, version := range w.s.replicaVersions {
		if _, member := members[key.physicalName]; member && (!pending || version < oldest) {
			delete(w.s.replicaVersions, key)
		}
	}
	return nil
}
