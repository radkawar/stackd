package stepfunctions

import (
	"cmp"
	"maps"
	"slices"
)

func cloneEncryptedPayload(v *EncryptedPayload) *EncryptedPayload {
	if v == nil {
		return nil
	}
	return &EncryptedPayload{DataKey: slices.Clone(v.DataKey), Content: slices.Clone(v.Content)}
}

func cloneRevision(v RevisionRecord) RevisionRecord {
	v.Encrypted = cloneEncryptedPayload(v.Encrypted)
	return v
}

func cloneMachine(v MachineRecord) MachineRecord {
	v.Tags = maps.Clone(v.Tags)
	if v.DeleteAt != nil {
		v.DeleteAt = new(*v.DeleteAt)
	}
	return v
}

func cloneAlias(v AliasRecord) AliasRecord {
	v.Routes = slices.Clone(v.Routes)
	return v
}

func cloneActivity(v ActivityRecord) ActivityRecord {
	v.Tags = maps.Clone(v.Tags)
	return v
}

func (r memoryReader) Machine(key MachineKey) (MachineRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return MachineRecord{}, err
	}
	row, ok := r.s.machines[key]
	if !ok {
		return MachineRecord{}, ErrNotFound
	}
	return cloneMachine(row), nil
}

func (r memoryReader) Machines(scope Scope) ([]MachineRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]MachineRecord, 0)
	for key, row := range r.s.machines {
		if key.Scope == scope {
			rows = append(rows, cloneMachine(row))
		}
	}
	slices.SortFunc(rows, func(a, b MachineRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return rows, nil
}

func (r memoryReader) MachineCount(scope Scope) (int64, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	var count int64
	for key := range r.s.machines {
		if key.Scope == scope {
			count++
		}
	}
	return count, nil
}

func (w memoryWriter) PutMachine(row MachineRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	previous, existed := w.s.machines[row.Key]
	w.s.machines[row.Key] = cloneMachine(row)
	if existed && previous.ID != row.ID {
		for key := range w.s.aliases {
			if key.Machine == row.Key && key.MachineID == previous.ID {
				delete(w.s.aliases, key)
			}
		}
		for key, version := range w.s.versions {
			if key.Machine == row.Key && key.MachineID == previous.ID {
				delete(w.s.versions, key)
				w.reclaimRevision(RevisionKey{Scope: row.Key.Scope, ID: version.RevisionID})
			}
		}
	}
	if existed && previous.RevisionID != row.RevisionID {
		w.reclaimRevision(RevisionKey{Scope: row.Key.Scope, ID: previous.RevisionID})
	}
	return nil
}

func (w memoryWriter) DeleteMachine(key MachineKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	row, ok := w.s.machines[key]
	if !ok {
		return ErrNotFound
	}
	revisions := map[RevisionKey]struct{}{{Scope: key.Scope, ID: row.RevisionID}: {}}
	delete(w.s.machines, key)
	for versionKey, version := range w.s.versions {
		if versionKey.Machine == key {
			revisions[RevisionKey{Scope: key.Scope, ID: version.RevisionID}] = struct{}{}
			delete(w.s.versions, versionKey)
		}
	}
	for aliasKey := range w.s.aliases {
		if aliasKey.Machine == key {
			delete(w.s.aliases, aliasKey)
		}
	}
	for revision := range revisions {
		w.reclaimRevision(revision)
	}
	return nil
}

func (r memoryReader) Revision(key RevisionKey) (RevisionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return RevisionRecord{}, err
	}
	row, ok := r.s.revisions[key]
	if !ok {
		return RevisionRecord{}, ErrNotFound
	}
	return cloneRevision(row), nil
}

func (w memoryWriter) PutRevision(row RevisionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, exists := w.s.revisions[row.Key]; !exists {
		w.s.revisions[row.Key] = cloneRevision(row)
	}
	return nil
}

// Only displaced owners trigger reclamation; a revision inserted before its
// machine or version in the current transaction must remain available.
func (w memoryWriter) reclaimRevision(key RevisionKey) {
	for machineKey, machine := range w.s.machines {
		if machineKey.Scope == key.Scope && machine.RevisionID == key.ID {
			return
		}
	}
	for versionKey, version := range w.s.versions {
		if versionKey.Machine.Scope == key.Scope && version.RevisionID == key.ID {
			return
		}
	}
	for executionKey, execution := range w.s.executions {
		if executionKey.Scope == key.Scope && execution.RevisionID == key.ID {
			return
		}
	}
	delete(w.s.revisions, key)
}

func (r memoryReader) Version(key VersionKey) (VersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return VersionRecord{}, err
	}
	row, ok := r.s.versions[key]
	if !ok {
		return VersionRecord{}, ErrNotFound
	}
	return row, nil
}

func (r memoryReader) Versions(machine MachineKey, machineID string) ([]VersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]VersionRecord, 0)
	for key, row := range r.s.versions {
		if key.Machine == machine && key.MachineID == machineID {
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b VersionRecord) int { return cmp.Compare(b.Key.Number, a.Key.Number) })
	return rows, nil
}

func (w memoryWriter) PutVersion(row VersionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	previous, existed := w.s.versions[row.Key]
	w.s.versions[row.Key] = row
	if existed && previous.RevisionID != row.RevisionID {
		w.reclaimRevision(RevisionKey{Scope: row.Key.Machine.Scope, ID: previous.RevisionID})
	}
	return nil
}

func (w memoryWriter) DeleteVersion(key VersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	row, ok := w.s.versions[key]
	if !ok {
		return ErrNotFound
	}
	delete(w.s.versions, key)
	w.reclaimRevision(RevisionKey{Scope: key.Machine.Scope, ID: row.RevisionID})
	return nil
}

func (r memoryReader) Alias(key AliasKey) (AliasRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return AliasRecord{}, err
	}
	row, ok := r.s.aliases[key]
	if !ok {
		return AliasRecord{}, ErrNotFound
	}
	return cloneAlias(row), nil
}

func (r memoryReader) Aliases(machine MachineKey, machineID string) ([]AliasRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]AliasRecord, 0)
	for key, row := range r.s.aliases {
		if key.Machine == machine && key.MachineID == machineID {
			rows = append(rows, cloneAlias(row))
		}
	}
	slices.SortFunc(rows, func(a, b AliasRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return rows, nil
}

func (w memoryWriter) PutAlias(row AliasRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.aliases[row.Key] = cloneAlias(row)
	return nil
}

func (w memoryWriter) DeleteAlias(key AliasKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.aliases[key]; !ok {
		return ErrNotFound
	}
	delete(w.s.aliases, key)
	return nil
}

func (r memoryReader) Activity(key ActivityKey) (ActivityRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ActivityRecord{}, err
	}
	row, ok := r.s.activities[key]
	if !ok {
		return ActivityRecord{}, ErrNotFound
	}
	return cloneActivity(row), nil
}

func (r memoryReader) Activities(scope Scope) ([]ActivityRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]ActivityRecord, 0)
	for key, row := range r.s.activities {
		if key.Scope == scope {
			rows = append(rows, cloneActivity(row))
		}
	}
	slices.SortFunc(rows, func(a, b ActivityRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return rows, nil
}

func (r memoryReader) ActivityCount(scope Scope) (int64, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	var count int64
	for key := range r.s.activities {
		if key.Scope == scope {
			count++
		}
	}
	return count, nil
}

func (w memoryWriter) PutActivity(row ActivityRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.activities[row.Key] = cloneActivity(row)
	return nil
}

func (w memoryWriter) DeleteActivity(key ActivityKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.activities[key]; !ok {
		return ErrNotFound
	}
	delete(w.s.activities, key)
	return nil
}
