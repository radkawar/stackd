package logs

import (
	"stackd/internal/scheduler"
	"stackd/storage/sqlite/logs/internal/sqlcgen"
	"time"
)

func (r reader) NextRetention() (scheduler.Job, bool, error) {
	due, err := r.q.NextRetention(r.ctx)
	return scheduler.Job{Key: "expired-log-events", Due: time.UnixMilli(due)}, due >= 0, err
}

func (w writer) ExpireEvents(nowMillis int64) error {
	streams, err := w.q.ExpiringStreams(w.ctx, nowMillis)
	if err != nil {
		return err
	}
	for _, stream := range streams {
		if err := w.q.DeleteExpiredEvents(w.ctx, sqlcgen.DeleteExpiredEventsParams{StreamID: stream.ID, Timestamp: stream.Cutoff}); err != nil {
			return err
		}
		if err := w.q.RefreshRetainedStream(w.ctx, stream.ID); err != nil {
			return err
		}
	}
	return nil
}
