package secretsmanager

import "slices"

func cloneReplica(v ReplicaRecord) ReplicaRecord {
	v.Due = clonePointer(v.Due)
	return v
}
func (r memoryReader) Replica(key ReplicaKey) (ReplicaRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ReplicaRecord{}, err
	}
	v, ok := r.s.replicas[key]
	if !ok {
		return ReplicaRecord{}, ErrNotFound
	}
	return cloneReplica(v), nil
}
func (r memoryReader) Replicas(key SecretKey) ([]ReplicaRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ReplicaRecord{}
	for k, v := range r.s.replicas {
		if k.Primary == key {
			out = append(out, cloneReplica(v))
		}
	}
	slices.SortFunc(out, func(a, b ReplicaRecord) int {
		if a.Key.Region < b.Key.Region {
			return -1
		}
		if a.Key.Region > b.Key.Region {
			return 1
		}
		return 0
	})
	return out, nil
}
func (r memoryReader) NextReplica() (ReplicaRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ReplicaRecord{}, err
	}
	var next ReplicaRecord
	for _, v := range r.s.replicas {
		if v.Due == nil {
			continue
		}
		if next.Due == nil || v.Due.Before(*next.Due) || (v.Due.Equal(*next.Due) && v.PrimaryARN+v.Key.Region < next.PrimaryARN+next.Key.Region) {
			next = v
		}
	}
	if next.Due == nil {
		return ReplicaRecord{}, ErrNotFound
	}
	return cloneReplica(next), nil
}
func (w memoryWriter) PutReplica(v ReplicaRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.replicas[v.Key] = cloneReplica(v)
	return nil
}
func (w memoryWriter) DeleteReplica(key ReplicaKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.replicas, key)
	return nil
}
func (r memoryReader) Rotation(key SecretKey) (RotationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return RotationRecord{}, err
	}
	v, ok := r.s.rotations[key]
	if !ok {
		return RotationRecord{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) NextRotationWork() (RotationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return RotationRecord{}, err
	}
	var next RotationRecord
	for _, v := range r.s.rotations {
		if !v.Due.Before(v.Deadline) {
			continue
		}
		if next.ARN == "" || v.Due.Before(next.Due) || (v.Due.Equal(next.Due) && v.ARN < next.ARN) {
			next = v
		}
	}
	if next.ARN == "" {
		return RotationRecord{}, ErrNotFound
	}
	return next, nil
}
func (r memoryReader) NextScheduledRotation() (SecretRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SecretRecord{}, err
	}
	var next SecretRecord
	for _, v := range r.s.secrets {
		if v.RotationDue == nil || v.Deleted != nil {
			continue
		}
		if next.RotationDue == nil || v.RotationDue.Before(*next.RotationDue) || (v.RotationDue.Equal(*next.RotationDue) && v.ARN < next.ARN) {
			next = v
		}
	}
	if next.RotationDue == nil {
		return SecretRecord{}, ErrNotFound
	}
	return cloneSecret(next), nil
}
func (w memoryWriter) PutRotation(v RotationRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.rotations[v.Secret] = v
	return nil
}
func (w memoryWriter) DeleteRotation(key SecretKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.rotations, key)
	return nil
}
