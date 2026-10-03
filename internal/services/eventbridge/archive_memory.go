package eventbridge

import (
	"slices"
	"time"
)

type archiveEntryKey struct{ archiveID, eventID string }

func cloneArchivePayload(v ArchivePayload) ArchivePayload {
	v.Content = slices.Clone(v.Content)
	v.DataKey = slices.Clone(v.DataKey)
	return v
}

func cloneArchive(v ArchiveRecord) ArchiveRecord {
	v.Pattern = cloneArchivePayload(v.Pattern)
	return v
}

func cloneArchiveEntry(v ArchiveEntry) ArchiveEntry {
	v.Payload = cloneArchivePayload(v.Payload)
	return v
}

func (r memoryReader) Archive(k ArchiveKey) (ArchiveRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ArchiveRecord{}, err
	}
	v, ok := r.s.archives[k]
	if !ok {
		return ArchiveRecord{}, ErrNotFound
	}
	return cloneArchive(v), nil
}

func (r memoryReader) ArchiveByID(id string) (ArchiveRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ArchiveRecord{}, err
	}
	for _, v := range r.s.archives {
		if v.ID == id {
			return cloneArchive(v), nil
		}
	}
	return ArchiveRecord{}, ErrNotFound
}

func (r memoryReader) Archives(scope Scope) ([]ArchiveRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ArchiveRecord{}
	for k, v := range r.s.archives {
		if k.Scope == scope {
			out = append(out, cloneArchive(v))
		}
	}
	slices.SortFunc(out, func(a, b ArchiveRecord) int { return compare(a.Key.Name, b.Key.Name) })
	return out, nil
}

func (r memoryReader) ArchiveEntry(archiveID, eventID string) (ArchiveEntry, error) {
	if err := r.tx.Check(false); err != nil {
		return ArchiveEntry{}, err
	}
	v, ok := r.s.archiveEntries[archiveEntryKey{archiveID, eventID}]
	if !ok {
		return ArchiveEntry{}, ErrNotFound
	}
	return cloneArchiveEntry(v), nil
}

func (r memoryReader) NextArchiveEntry(archiveID string, start, end time.Time, after ArchiveCursor) (ArchiveEntry, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return ArchiveEntry{}, false, err
	}
	var next ArchiveEntry
	found := false
	for _, v := range r.s.archiveEntries {
		if v.ArchiveID != archiveID || v.Time.Before(start) || !v.Time.Before(end) {
			continue
		}
		if after.ID != "" && (v.Time.Before(after.Time) || v.Time.Equal(after.Time) && v.ID <= after.ID) {
			continue
		}
		if !found || v.Time.Before(next.Time) || v.Time.Equal(next.Time) && v.ID < next.ID {
			next, found = v, true
		}
	}
	return cloneArchiveEntry(next), found, nil
}

func (r memoryReader) NextArchiveExpiration() (ArchiveEntry, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return ArchiveEntry{}, false, err
	}
	var next ArchiveEntry
	found := false
	for _, v := range r.s.archiveEntries {
		if v.Expires.IsZero() {
			continue
		}
		if !found || v.Expires.Before(next.Expires) || v.Expires.Equal(next.Expires) && (v.ArchiveID < next.ArchiveID || v.ArchiveID == next.ArchiveID && v.ID < next.ID) {
			next, found = v, true
		}
	}
	return cloneArchiveEntry(next), found, nil
}

func (r memoryReader) NextArchiveMigration() (ArchiveRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return ArchiveRecord{}, false, err
	}
	var next ArchiveRecord
	found := false
	for _, v := range r.s.archives {
		if v.MigrationDue.IsZero() {
			continue
		}
		if !found || v.MigrationDue.Before(next.MigrationDue) || v.MigrationDue.Equal(next.MigrationDue) && v.ID < next.ID {
			next, found = v, true
		}
	}
	return cloneArchive(next), found, nil
}

func (r memoryReader) NextArchiveMigrationEntry(archiveID string, keyVersion uint64) (ArchiveEntry, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return ArchiveEntry{}, false, err
	}
	var next ArchiveEntry
	found := false
	for _, v := range r.s.archiveEntries {
		if v.ArchiveID == archiveID && v.KeyVersion < keyVersion && (!found || v.KeyVersion < next.KeyVersion || v.KeyVersion == next.KeyVersion && v.ID < next.ID) {
			next, found = v, true
		}
	}
	return cloneArchiveEntry(next), found, nil
}

func (w memoryWriter) PutArchive(v ArchiveRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.archives[v.Key] = cloneArchive(v)
	return nil
}

func (w memoryWriter) DeleteArchive(k ArchiveKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v, ok := w.s.archives[k]
	if !ok {
		return nil
	}
	delete(w.s.archives, k)
	for key := range w.s.archiveEntries {
		if key.archiveID == v.ID {
			delete(w.s.archiveEntries, key)
		}
	}
	return nil
}

func (w memoryWriter) PutArchiveEntry(v ArchiveEntry) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for _, archive := range w.s.archives {
		if archive.ID == v.ArchiveID {
			w.s.archiveEntries[archiveEntryKey{v.ArchiveID, v.ID}] = cloneArchiveEntry(v)
			return nil
		}
	}
	return ErrNotFound
}

func (w memoryWriter) DeleteArchiveEntry(archiveID, eventID string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.archiveEntries, archiveEntryKey{archiveID, eventID})
	return nil
}

func (w memoryWriter) UpdateArchiveEntryRetention(archiveID string, days int32) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for k, v := range w.s.archiveEntries {
		if k.archiveID != archiveID {
			continue
		}
		v.Expires = time.Time{}
		if days != 0 {
			v.Expires = time.Unix(v.Ingested.Unix()+int64(days)*86400, int64(v.Ingested.Nanosecond())).UTC()
		}
		w.s.archiveEntries[k] = v
	}
	return nil
}
