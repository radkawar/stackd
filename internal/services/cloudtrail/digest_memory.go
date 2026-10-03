package cloudtrail

import (
	"cmp"
	"slices"
	"time"
)

func cloneDigestKey(v DigestKeyRecord) DigestKeyRecord {
	v.PrivateDER = slices.Clone(v.PrivateDER)
	v.PublicDER = slices.Clone(v.PublicDER)
	return v
}
func cloneDigestStream(v DigestStream) DigestStream { v.Pending = slices.Clone(v.Pending); return v }
func (r memoryReader) DigestKeys(partition, region string) ([]DigestKeyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []DigestKeyRecord{}
	for _, v := range r.state.digestKeys {
		if v.Partition == partition && v.Region == region {
			out = append(out, cloneDigestKey(v))
		}
	}
	slices.SortFunc(out, func(a, b DigestKeyRecord) int { return a.Start.Compare(b.Start) })
	return out, nil
}
func (w memoryWriter) PutDigestKey(v DigestKeyRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.digestKeys[v.Partition+"/"+v.Region+"/"+v.Fingerprint] = cloneDigestKey(v)
	return nil
}
func (r memoryReader) DigestStream(id string) (DigestStream, error) {
	if err := r.tx.Check(false); err != nil {
		return DigestStream{}, err
	}
	v, ok := r.state.digestStreams[id]
	if !ok {
		return v, ErrNotFound
	}
	return cloneDigestStream(v), nil
}
func (r memoryReader) DigestStreams(trailID string) ([]DigestStream, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []DigestStream{}
	for _, v := range r.state.digestStreams {
		if v.TrailID == trailID {
			out = append(out, cloneDigestStream(v))
		}
	}
	slices.SortFunc(out, func(a, b DigestStream) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (r memoryReader) NextDigest() (DigestStream, error) {
	if err := r.tx.Check(false); err != nil {
		return DigestStream{}, err
	}
	var out DigestStream
	for _, v := range r.state.digestStreams {
		if out.ID == "" || v.Due.Before(out.Due) || v.Due.Equal(out.Due) && v.ID < out.ID {
			out = v
		}
	}
	if out.ID == "" {
		return out, ErrNotFound
	}
	return cloneDigestStream(out), nil
}
func (w memoryWriter) PutDigestStream(v DigestStream) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.digestStreams[v.ID] = cloneDigestStream(v)
	return nil
}
func (w memoryWriter) DeleteDigestStream(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.digestStreams, id)
	for k, v := range w.state.digestLogs {
		if v.StreamID == id {
			delete(w.state.digestLogs, k)
		}
	}
	return nil
}
func (r memoryReader) DigestLogs(id string, end time.Time) ([]DigestLog, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []DigestLog{}
	for _, v := range r.state.digestLogs {
		if v.StreamID == id && v.Delivered.Before(end) {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b DigestLog) int {
		if c := a.Delivered.Compare(b.Delivered); c != 0 {
			return c
		}
		return cmp.Compare(a.DeliveryID, b.DeliveryID)
	})
	return out, nil
}
func (w memoryWriter) PutDigestLog(v DigestLog) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.state.digestStreams[v.StreamID]; !ok {
		return ErrNotFound
	}
	w.state.digestLogs[v.StreamID+"/"+v.DeliveryID] = v
	return nil
}
func (w memoryWriter) DeleteDigestLogs(id string, end time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for k, v := range w.state.digestLogs {
		if v.StreamID == id && v.Delivered.Before(end) {
			delete(w.state.digestLogs, k)
		}
	}
	return nil
}
func (r memoryReader) DigestStatus(trailID, accountID, region string) (DigestStatus, error) {
	if err := r.tx.Check(false); err != nil {
		return DigestStatus{}, err
	}
	v, ok := r.state.digestStatuses[trailID+"/"+accountID+"/"+region]
	if !ok {
		return v, ErrNotFound
	}
	v.LastAttempt, v.LastSuccess = clonePointer(v.LastAttempt), clonePointer(v.LastSuccess)
	return v, nil
}
func (w memoryWriter) PutDigestStatus(v DigestStatus) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if !w.hasTrail(v.TrailID) {
		return ErrNotFound
	}
	v.LastAttempt, v.LastSuccess = clonePointer(v.LastAttempt), clonePointer(v.LastSuccess)
	w.state.digestStatuses[v.TrailID+"/"+v.AccountID+"/"+v.Region] = v
	return nil
}
