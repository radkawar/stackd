package sns

import "time"

func (r memoryReader) ArchiveEntry(key MessageKey) (ArchiveEntry, error) {
	if err := r.tx.Check(false); err != nil {
		return ArchiveEntry{}, err
	}
	entry, exists := r.s.archiveEntries[key]
	if !exists {
		return ArchiveEntry{}, ErrNotFound
	}
	return entry, nil
}

func (r memoryReader) NextArchiveEntry(topicID string, start time.Time, after uint64) (ArchiveEntry, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return ArchiveEntry{}, false, err
	}
	var next ArchiveEntry
	found := false
	for _, entry := range r.s.archiveEntries {
		if entry.TopicID != topicID || entry.Sequence <= after || entry.Published.Before(start) {
			continue
		}
		if !found || entry.Sequence < next.Sequence || entry.Sequence == next.Sequence && archiveMessageLess(entry.Message, next.Message) {
			next = entry
			found = true
		}
	}
	return next, found, nil
}

func (r memoryReader) NextArchiveExpiration() (ArchiveEntry, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return ArchiveEntry{}, false, err
	}
	var next ArchiveEntry
	found := false
	for _, entry := range r.s.archiveEntries {
		if !found || entry.Expires.Before(next.Expires) || entry.Expires.Equal(next.Expires) && archiveMessageLess(entry.Message, next.Message) {
			next = entry
			found = true
		}
	}
	return next, found, nil
}

func archiveMessageLess(a, b MessageKey) bool {
	return a.ID < b.ID || a.ID == b.ID && a.Protocol < b.Protocol
}

func (r memoryReader) ArchiveUsage(topicID string) (messages, bytes int64, err error) {
	if err := r.tx.Check(false); err != nil {
		return 0, 0, err
	}
	for _, entry := range r.s.archiveEntries {
		if entry.TopicID == topicID {
			messages++
			bytes += entry.SizeBytes
		}
	}
	return messages, bytes, nil
}

func (r memoryReader) NextArchiveMetric() (TopicRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return TopicRecord{}, false, err
	}
	var next TopicRecord
	found := false
	for _, topic := range r.s.topics {
		if topic.Archive == nil {
			continue
		}
		if !found || topic.Archive.MetricDue.Before(next.Archive.MetricDue) || topic.Archive.MetricDue.Equal(next.Archive.MetricDue) && topic.Key.ARN() < next.Key.ARN() {
			next = topic
			found = true
		}
	}
	return cloneTopic(next), found, nil
}

func (r memoryReader) NextReplay() (SubscriptionRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return SubscriptionRecord{}, false, err
	}
	var next SubscriptionRecord
	found := false
	for _, subscription := range r.s.subscriptions {
		if subscription.Replay.Status != "Pending" && subscription.Replay.Status != "In Progress" {
			continue
		}
		if !found || subscription.Replay.Due.Before(next.Replay.Due) || subscription.Replay.Due.Equal(next.Replay.Due) && subscription.Key.ARN() < next.Key.ARN() {
			next = subscription
			found = true
		}
	}
	return cloneSubscription(next), found, nil
}

func (w memoryWriter) PutArchiveEntry(entry ArchiveEntry) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, exists := w.s.archiveEntries[entry.Message]; !exists {
		w.s.messageReferences[entry.Message]++
	}
	w.s.archiveEntries[entry.Message] = entry
	return nil
}

func (w memoryWriter) DeleteArchiveEntry(key MessageKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, exists := w.s.archiveEntries[key]; exists {
		delete(w.s.archiveEntries, key)
		w.releaseMessage(key)
	}
	return nil
}

func (w memoryWriter) DeleteArchiveEntries(topicID string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.deleteArchiveEntries(topicID)
	return nil
}

func (w memoryWriter) deleteArchiveEntries(topicID string) {
	for key, entry := range w.s.archiveEntries {
		if entry.TopicID == topicID {
			delete(w.s.archiveEntries, key)
			w.releaseMessage(key)
		}
	}
}

func (w memoryWriter) UpdateArchiveRetention(topicID string, days int32, now time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	retention := time.Duration(days) * 24 * time.Hour
	for key, entry := range w.s.archiveEntries {
		if entry.TopicID != topicID {
			continue
		}
		expires := entry.Published.Add(retention)
		if !entry.Expires.After(now) || !expires.After(now) {
			delete(w.s.archiveEntries, key)
			w.releaseMessage(key)
			continue
		}
		entry.Expires = expires
		w.s.archiveEntries[key] = entry
	}
	return nil
}
