package ecs

import api "stackd/internal/awsapi/ecs"

func (r memoryReader) ServiceRevision(key ServiceRevisionKey) (ServiceRevisionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ServiceRevisionRecord{}, err
	}
	revision, ok := r.s.serviceRevisions[key]
	if !ok {
		return ServiceRevisionRecord{}, ErrNotFound
	}
	revision.Data = api.CloneServiceRevision(revision.Data)
	return revision, nil
}

func (w memoryWriter) PutServiceRevision(revision ServiceRevisionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, exists := w.s.serviceRevisions[revision.Key]; !exists {
		revision.Data = api.CloneServiceRevision(revision.Data)
		w.s.serviceRevisions[revision.Key] = revision
	}
	return nil
}

func (w memoryWriter) DeleteServiceRevisions(key ServiceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for revision := range w.s.serviceRevisions {
		if revision.ServiceKey == key {
			delete(w.s.serviceRevisions, revision)
		}
	}
	return nil
}
