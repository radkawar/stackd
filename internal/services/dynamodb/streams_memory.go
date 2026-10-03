package dynamodb

import (
	"cmp"
	"slices"
	api "stackd/internal/awsapi/dynamodbstreams"
	"time"
)

func streamShardKey(arn, id string) string      { return arn + "\x00" + id }
func streamEntryKey(arn, id, seq string) string { return streamShardKey(arn, id) + "\x00" + seq }
func (r memoryReader) Stream(k PolicyKey) (StreamGeneration, error) {
	if err := r.tx.Check(false); err != nil {
		return StreamGeneration{}, err
	}
	v, ok := r.s.streams[k]
	if !ok {
		return v, ErrNotFound
	}
	return cloneStream(v), nil
}
func (r memoryReader) Streams() ([]StreamGeneration, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]StreamGeneration, 0, len(r.s.streams))
	for _, v := range r.s.streams {
		out = append(out, cloneStream(v))
	}
	slices.SortFunc(out, func(a, b StreamGeneration) int { return cmp.Compare(a.Key.ResourceARN, b.Key.ResourceARN) })
	return out, nil
}
func (r memoryReader) StreamShards(arn string) ([]StreamShard, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []StreamShard
	for _, v := range r.s.shards {
		if v.StreamARN == arn {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b StreamShard) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (r memoryReader) StreamEntries(q StreamEntryQuery) ([]StreamEntry, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	limit := min(max(q.Limit, 0), 1000)
	if limit == 0 {
		return nil, nil
	}
	// Keep only the requested prefix, without cloning historical payloads.
	out := make([]StreamEntry, 0, limit)
	for _, v := range r.s.entries {
		if v.StreamARN != q.StreamARN || v.ShardID != q.ShardID {
			continue
		}
		comparison := compareSequence(v.Sequence, q.Position)
		if comparison < 0 || comparison == 0 && !q.Inclusive {
			continue
		}
		at, _ := slices.BinarySearchFunc(out, v, func(a, b StreamEntry) int {
			return cmp.Or(compareSequence(a.Sequence, b.Sequence), cmp.Compare(a.Sequence, b.Sequence))
		})
		if at == limit {
			continue
		}
		if len(out) < limit {
			out = append(out, StreamEntry{})
		}
		copy(out[at+1:], out[at:len(out)-1])
		out[at] = v
	}
	size := int64(0)
	count := 0
	for _, v := range out {
		if v.Data.Dynamodb != nil && v.Data.Dynamodb.SizeBytes != nil {
			size += int64(*v.Data.Dynamodb.SizeBytes)
		}
		if size > 1024*1024 {
			break
		}
		out[count].Data = api.CloneRecord(v.Data)
		count++
	}
	clear(out[count:])
	return out[:count:count], nil
}
func (w memoryWriter) PutStream(v StreamGeneration) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.streams[v.Key] = cloneStream(v)
	return nil
}
func (w memoryWriter) DeleteStream(k PolicyKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.streams, k)
	for id, v := range w.s.shards {
		if v.StreamARN == k.ResourceARN {
			delete(w.s.shards, id)
		}
	}
	for id, v := range w.s.entries {
		if v.StreamARN == k.ResourceARN {
			delete(w.s.entries, id)
		}
	}
	return nil
}
func (w memoryWriter) PutStreamShard(v StreamShard) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.shards[streamShardKey(v.StreamARN, v.ID)] = v
	return nil
}
func (w memoryWriter) PutStreamEntry(v StreamEntry) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Data = api.CloneRecord(v.Data)
	w.s.entries[streamEntryKey(v.StreamARN, v.ShardID, v.Sequence)] = v
	return nil
}
func (w memoryWriter) TrimStreamEntries(arn string, cutoff time.Time) (time.Time, error) {
	if err := w.tx.Check(true); err != nil {
		return time.Time{}, err
	}
	var oldest time.Time
	for key, v := range w.s.entries {
		if v.StreamARN != arn {
			continue
		}
		if v.CreatedAt.After(cutoff) {
			if oldest.IsZero() || v.CreatedAt.Before(oldest) {
				oldest = v.CreatedAt
			}
			continue
		}
		shardKey := streamShardKey(arn, v.ShardID)
		sh := w.s.shards[shardKey]
		if compareSequence(v.Sequence, sh.TrimmedThrough) > 0 {
			sh.TrimmedThrough = v.Sequence
			w.s.shards[shardKey] = sh
		}
		delete(w.s.entries, key)
	}
	return oldest, nil
}
