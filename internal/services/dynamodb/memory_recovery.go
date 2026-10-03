package dynamodb

import (
	"slices"
	"sort"
	"strings"
	"time"

	api "stackd/internal/awsapi/dynamodb"
)

func cloneRecoveryRecord(v RecoveryRecord) RecoveryRecord {
	v.KeySchema = api.CloneKeySchema(v.KeySchema)
	v.AttributeDefinitions = api.CloneAttributeDefinitions(v.AttributeDefinitions)
	if v.SnapshotAt != nil {
		v.SnapshotAt = new(*v.SnapshotAt)
	}
	if v.CompactThrough != nil {
		v.CompactThrough = new(*v.CompactThrough)
	}
	return v
}

func cloneRecoveryChange(v RecoveryChange) RecoveryChange {
	v.Key = api.CloneKey(v.Key)
	v.Item = api.CloneAttributeMap(v.Item)
	return v
}

func (r memoryReader) Recovery(id string) (RecoveryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return RecoveryRecord{}, err
	}
	v, ok := r.s.recoveries[id]
	if !ok {
		return RecoveryRecord{}, ErrNotFound
	}
	return cloneRecoveryRecord(v), nil
}

func (r memoryReader) RecoverySequence(id string) (int64, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	changes := r.s.recoveryChanges[id]
	if len(changes) == 0 {
		return 0, nil
	}
	return changes[len(changes)-1].Sequence, nil
}

func (r memoryReader) Recoveries(databaseID string) ([]RecoveryRecord, error) {
	return r.recoveries(databaseID, false)
}

func (r memoryReader) UnsettledRecoveries(databaseID string) ([]RecoveryRecord, error) {
	return r.recoveries(databaseID, true)
}

func (r memoryReader) recoveries(databaseID string, unsettledOnly bool) ([]RecoveryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []RecoveryRecord
	for _, v := range r.s.recoveries {
		if (databaseID == "" || v.DatabaseID == databaseID) && (!unsettledOnly || v.SnapshotAt == nil || v.CompactThrough != nil) {
			out = append(out, cloneRecoveryRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b RecoveryRecord) int {
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

func (r memoryReader) RecoveryChanges(q RecoveryChangeQuery) ([]RecoveryChange, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	changes := r.s.recoveryChanges[q.RecoveryID]
	start := sort.Search(len(changes), func(i int) bool {
		return changes[i].Sequence > q.After
	})
	var out []RecoveryChange
	for _, v := range changes[start:] {
		if q.ThroughSequence != nil && v.Sequence > *q.ThroughSequence {
			break
		}
		if !q.Through.IsZero() && v.At.After(q.Through) {
			continue
		}
		out = append(out, cloneRecoveryChange(v))
		if q.Limit > 0 && len(out) == q.Limit {
			break
		}
	}
	return out, nil
}

func (w memoryWriter) PutRecovery(v RecoveryRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.recoveries[v.ID] = cloneRecoveryRecord(v)
	return nil
}

func (w memoryWriter) DeleteRecovery(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.recoveries, id)
	delete(w.s.recoveryChanges, id)
	return nil
}

func (w memoryWriter) AppendRecoveryChanges(changes []RecoveryChange) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for _, v := range changes {
		if _, ok := w.s.recoveries[v.RecoveryID]; !ok {
			return ErrNotFound
		}
	}
	// Map cloning isolates each slice header. Appending beyond the previous
	// length never mutates a visible retained entry; rollback hides that tail.
	for _, v := range changes {
		w.s.recoverySequence++
		v = cloneRecoveryChange(v)
		v.Sequence = w.s.recoverySequence
		w.s.recoveryChanges[v.RecoveryID] = append(w.s.recoveryChanges[v.RecoveryID], v)
	}
	return nil
}

func (w memoryWriter) DeleteRecoveryChanges(id string, through time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	changes := w.s.recoveryChanges[id]
	retained := 0
	for _, v := range changes {
		if v.At.After(through) {
			retained++
		}
	}
	if retained == len(changes) {
		return nil
	}
	if retained == 0 {
		delete(w.s.recoveryChanges, id)
		return nil
	}
	next := make([]RecoveryChange, 0, retained)
	for _, v := range changes {
		if v.At.After(through) {
			next = append(next, v)
		}
	}
	w.s.recoveryChanges[id] = next
	return nil
}
