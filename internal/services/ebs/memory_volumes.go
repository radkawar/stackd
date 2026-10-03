package ebs

import (
	"cmp"
	"maps"
	"slices"
	"time"

	ec2api "stackd/internal/awsapi/ec2"
)

func cloneVolume(v VolumeRecord) VolumeRecord {
	v.CreationInput = ec2api.CloneCreateVolumeRequest(v.CreationInput)
	v.Tags = maps.Clone(v.Tags)
	v.WrappedKey = slices.Clone(v.WrappedKey)
	if v.Creation != nil {
		creation := *v.Creation
		creation.SourceWrappedKey = slices.Clone(creation.SourceWrappedKey)
		v.Creation = &creation
	}
	v.Modification = clonePointer(v.Modification)
	v.ModificationStarts = slices.Clone(v.ModificationStarts)
	return v
}

func (r memoryReader) Volume(k VolumeKey) (VolumeRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return VolumeRecord{}, err
	}
	v, ok := r.s.volumes[k]
	if !ok {
		return VolumeRecord{}, ErrNotFound
	}
	return cloneVolume(v), nil
}

func (r memoryReader) Volumes(scope Scope) ([]VolumeRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []VolumeRecord{}
	for k, v := range r.s.volumes {
		if k.Scope == scope {
			out = append(out, cloneVolume(v))
		}
	}
	slices.SortFunc(out, func(a, b VolumeRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}

func (r memoryReader) VolumeByToken(scope Scope, token string) (VolumeRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return VolumeRecord{}, err
	}
	for k, v := range r.s.volumes {
		if k.Scope == scope && token != "" && value(v.CreationInput.ClientToken) == token {
			return cloneVolume(v), nil
		}
	}
	return VolumeRecord{}, ErrNotFound
}

func (r memoryReader) VolumeBlock(k VolumeBlockKey) (VolumeBlockRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return VolumeBlockRecord{}, err
	}
	v, ok := r.s.volumeBlocks[k]
	if !ok {
		return VolumeBlockRecord{}, ErrNotFound
	}
	v.Data = slices.Clone(v.Data)
	return v, nil
}

func (r memoryReader) VolumeBlocks(k VolumeKey) ([]VolumeBlockInfo, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []VolumeBlockInfo{}
	for key, v := range r.s.volumeBlocks {
		if key.Volume == k {
			out = append(out, v.VolumeBlockInfo)
		}
	}
	slices.SortFunc(out, func(a, b VolumeBlockInfo) int { return cmp.Compare(a.Key.Index, b.Key.Index) })
	return out, nil
}

// VolumeWorkTime returns the next active lifecycle deadline, excluding completed
// modifications and retained deleted metadata used only for client-token replay.
func VolumeWorkTime(v VolumeRecord) time.Time {
	if v.Status == ec2api.VolumeStateDeleted {
		return time.Time{}
	}
	due := v.TransitionAt
	if m := v.Modification; m != nil {
		var next time.Time
		switch m.State {
		case ec2api.VolumeModificationStateModifying:
			next = m.OptimizingAt
		case ec2api.VolumeModificationStateOptimizing:
			next = m.CompletedAt
		}
		if !next.IsZero() && (due.IsZero() || next.Before(due)) {
			due = next
		}
	}
	return due
}

func (r memoryReader) NextVolumeWork() (VolumeRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return VolumeRecord{}, err
	}
	var next VolumeRecord
	var due time.Time
	for _, v := range r.s.volumes {
		d := VolumeWorkTime(v)
		if d.IsZero() {
			continue
		}
		if due.IsZero() || d.Before(due) || (d.Equal(due) && compareKeys(SnapshotKey(v.Key), SnapshotKey(next.Key)) < 0) {
			due, next = d, v
		}
	}
	if due.IsZero() {
		return VolumeRecord{}, ErrNotFound
	}
	return cloneVolume(next), nil
}

// VolumeID uses the shared scoped resource sequence without consuming a second ID.
func VolumeID(scope Scope, sequence uint64) string {
	return resourceID("vol-", scope, sequence)
}

func (w memoryWriter) NextVolumeID(scope Scope) (string, error) {
	return w.nextResourceID("vol-", scope)
}

func (w memoryWriter) PutVolume(v VolumeRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.volumes[v.Key] = cloneVolume(v)
	return nil
}

func (w memoryWriter) PutVolumeBlock(v VolumeBlockRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Data = slices.Clone(v.Data)
	w.s.volumeBlocks[v.Key] = v
	return nil
}

func (w memoryWriter) DeleteVolumeBlocks(k VolumeKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key := range w.s.volumeBlocks {
		if key.Volume == k {
			delete(w.s.volumeBlocks, key)
		}
	}
	return nil
}
