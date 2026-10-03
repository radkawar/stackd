package logs

import (
	"context"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

func (s *Service) putLogEvents(tx Transaction, in *api.PutLogEventsRequest) (*api.PutLogEventsResponse, *awswire.Error) {
	// TODO: Comeback implement native entity associations without treating entity metadata as retained log content.
	if in == nil {
		return nil, invalid("A request is required.")
	}
	if in.Entity != nil {
		return nil, unsupported("Log entity associations are not implemented.")
	}
	if len(in.LogEvents) < 1 || len(in.LogEvents) > MaxBatchEvents {
		return nil, invalid("A batch must contain between 1 and 10000 log events.")
	}
	bytes := 0
	for i, e := range in.LogEvents {
		if e.Message == nil || e.Timestamp == nil || len(value(e.Message)) == 0 || !utf8.ValidString(value(e.Message)) || int64(*e.Timestamp) < 0 {
			return nil, invalid("Each event requires a nonempty UTF-8 message and a nonnegative timestamp.")
		}
		bytes += len(*e.Message) + EventOverheadBytes
		if bytes > MaxBatchBytes {
			return nil, invalid("The batch of log events exceeds the maximum batch size of 1048576 bytes.")
		}
		if i > 0 && *e.Timestamp < *in.LogEvents[i-1].Timestamp {
			return nil, invalid("Log events in a single PutLogEvents request must be in chronological order.")
		}
	}
	name := value(in.LogStreamName)
	g, stream, w := s.loadPutLogEvents(tx, value(in.LogGroupName), name)
	if w != nil {
		return nil, w
	}
	now := s.clock.Now().UnixMilli()
	old := now - 14*86400000
	cut := s.retainedAfter(g)
	start, end := 0, len(in.LogEvents)
	rejected := api.RejectedLogEventsInfo{}
	for i, e := range in.LogEvents {
		ts := int64(*e.Timestamp)
		if ts < old {
			rejected.TooOldLogEventEndIndex = new(api.LogEventIndex(i + 1))
			start = i + 1
		}
		if ts < cut {
			rejected.ExpiredLogEventEndIndex = new(api.LogEventIndex(i + 1))
			start = i + 1
		}
		if ts > now+2*3600000 {
			if rejected.TooNewLogEventStartIndex == nil {
				rejected.TooNewLogEventStartIndex = new(api.LogEventIndex(i))
				end = i
			}
		}
	}
	if start < end && int64(*in.LogEvents[end-1].Timestamp)-int64(*in.LogEvents[start].Timestamp) > 86400000 {
		return nil, invalid("The batch of log events in a single PutLogEvents request cannot span more than 24 hours.")
	}
	var subscriptions []SubscriptionRecord
	if start < end {
		var err error
		subscriptions, err = tx.Subscriptions(SubscriptionQuery{GroupID: g.ID, Limit: maxSubscriptionFilters})
		if err != nil {
			return nil, wireError(err)
		}
	}
	var accepted []EventRecord
	if len(subscriptions) > 0 {
		accepted = make([]EventRecord, 0, end-start)
	}
	for _, e := range in.LogEvents[start:end] {
		g.Sequence++
		ts := int64(*e.Timestamp)
		event := EventRecord{GroupID: g.ID, StreamID: stream.ID, StreamName: name, ID: uuid.NewString(), Message: string(*e.Message), EventCursor: EventCursor{ts, now, g.Sequence}}
		if err := tx.AppendEvent(event); err != nil {
			return nil, wireError(err)
		}
		if len(subscriptions) > 0 {
			accepted = append(accepted, event)
		}
		if stream.EventCount == 0 {
			stream.FirstEvent = ts
			stream.LastEvent = ts
		} else {
			stream.FirstEvent = min(stream.FirstEvent, ts)
			stream.LastEvent = max(stream.LastEvent, ts)
		}
		stream.EventCount++
		stream.LastIngestion = now
	}
	parent := awsctx.FromContext(tx.Context()).ParentEventID
	if start < end && s.events != nil {
		batchID := uuid.NewString()
		scope := apievents.WithOrigin(tx.Context(), journal.Envelope{At: s.clock.Now(), Partition: g.Key.Partition, AccountID: g.Key.AccountID, Region: g.Key.Region})
		if err := s.events.AppendLogsBatchAccepted(tx.Context(), scope, journal.LogsBatchAccepted{BatchID: batchID, LogGroupARN: g.Key.ARN(), LogStreamName: name, EventCount: int64(end - start)}); err != nil {
			return nil, wireError(err)
		}
		parent = batchID
	}
	if w := s.enqueueSubscriptions(tx, g, name, subscriptions, accepted, parent); w != nil {
		return nil, w
	}
	if w := s.publishMetrics(tx, g, in.LogEvents[start:end]); w != nil {
		return nil, w
	}
	if err := tx.PutGroup(g); err != nil {
		return nil, wireError(err)
	}
	if err := tx.PutStream(stream); err != nil {
		return nil, wireError(err)
	}
	out := &api.PutLogEventsResponse{NextSequenceToken: new(api.SequenceToken(strconv.FormatInt(g.Sequence, 10)))}
	if rejected.TooOldLogEventEndIndex != nil || rejected.ExpiredLogEventEndIndex != nil || rejected.TooNewLogEventStartIndex != nil {
		out.RejectedLogEventsInfo = &rejected
	}
	return out, nil
}

func (s *Service) loadPutLogEvents(r Reader, group, stream string) (GroupRecord, StreamRecord, *awswire.Error) {
	if w := resourceName(stream, "log stream"); w != nil {
		return GroupRecord{}, StreamRecord{}, w
	}
	g, w := s.loadGroup(r, group, "PutLogEvents", stream)
	if w != nil {
		return g, StreamRecord{}, w
	}
	v, err := r.Stream(StreamKey{g.ID, stream})
	return g, v, wireError(err)
}

// CheckPutLogEvents checks the live destination and write authorization without
// ingesting content or recording a fabricated PutLogEvents API call.
func (s *Service) CheckPutLogEvents(ctx context.Context, groupName, streamName string) *awswire.Error {
	err := s.repository.View(ctx, func(r Reader) error {
		_, _, w := s.loadPutLogEvents(r, groupName, streamName)
		if w != nil {
			return w
		}
		return nil
	})
	return wireError(err)
}
