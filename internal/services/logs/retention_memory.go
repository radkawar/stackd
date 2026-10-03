package logs

import (
	"stackd/internal/scheduler"
	"time"
)

const retentionDayMillis = int64(24 * time.Hour / time.Millisecond)

func firstEvent(n *eventNode) *eventNode {
	if n == nil {
		return nil
	}
	for n.left != nil {
		n = n.left
	}
	return n
}

func (r memoryReader) NextRetention() (scheduler.Job, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return scheduler.Job{}, false, err
	}
	var due int64
	found := false
	for _, g := range r.state.groups {
		if g.RetentionDays == 0 {
			continue
		}
		n := firstEvent(r.state.events[g.ID])
		if n == nil {
			continue
		}
		at := n.event.Timestamp + int64(g.RetentionDays)*retentionDayMillis + 1
		if !found || at < due {
			due, found = at, true
		}
	}
	return scheduler.Job{Key: "expired-log-events", Due: time.UnixMilli(due)}, found, nil
}

func (w memoryWriter) ExpireEvents(nowMillis int64) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for _, g := range w.state.groups {
		if g.RetentionDays == 0 {
			continue
		}
		cutoff := nowMillis - int64(g.RetentionDays)*retentionDayMillis
		root := w.state.events[g.ID]
		for n := firstEvent(root); n != nil && n.event.Timestamp < cutoff; n = firstEvent(root) {
			event := n.event
			root = deleteEvent(root, event.EventCursor)
			streamRoot := deleteEvent(w.state.events[event.StreamID], event.EventCursor)
			w.state.events[event.StreamID] = streamRoot
			key := StreamKey{GroupID: g.ID, Name: event.StreamName}
			stream := w.state.streams[key]
			stream.EventCount--
			if streamRoot == nil {
				stream.FirstEvent, stream.LastEvent = 0, 0
			} else {
				stream.FirstEvent = firstEvent(streamRoot).event.Timestamp
				last := streamRoot
				for last.right != nil {
					last = last.right
				}
				stream.LastEvent = last.event.Timestamp
			}
			w.state.streams[key] = stream
		}
		w.state.events[g.ID] = root
	}
	return nil
}
