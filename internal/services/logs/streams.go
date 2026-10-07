package logs

import (
	"context"
	"errors"
	"strconv"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awswire"
)

// EnsureLogStream creates a missing stream through the ordinary authorized
// command. Delivery workers can reuse an existing stream without manufacturing
// repeated CreateLogStream API failures or keeping a second existence cache.
// This does not grant write permission; PutLogEvents authorizes every ingestion.
func (s *Service) EnsureLogStream(ctx context.Context, groupName, streamName string) *awswire.Error {
	err := s.repository.View(ctx, func(r Reader) error {
		group, err := r.Group(GroupKey{Scope: scopeFor(ctx), Name: groupName})
		if err != nil {
			return err
		}
		_, err = r.Stream(StreamKey{GroupID: group.ID, Name: streamName})
		return err
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return wireError(err)
	}
	_, wire := s.CreateLogStream(ctx, &api.CreateLogStreamRequest{LogGroupName: new(api.LogGroupName(groupName)), LogStreamName: new(api.LogStreamName(streamName))})
	if wire != nil && wire.Code == "ResourceAlreadyExistsException" {
		return nil
	}
	return wire
}

func (s *Service) createLogStream(tx Transaction, in *api.CreateLogStreamRequest) (*api.Unit, *awswire.Error) {
	if in == nil {
		return nil, invalid("A request is required.")
	}
	name := value(in.LogStreamName)
	if w := resourceName(name, "log stream"); w != nil {
		return nil, w
	}
	g, w := s.loadGroup(tx, value(in.LogGroupName), "CreateLogStream", name)
	if w != nil {
		return nil, w
	}
	k := StreamKey{g.ID, name}
	owner, ownerWire := cloudFormationClaim(tx.Context(), "", false)
	if old, err := tx.Stream(k); err == nil {
		if _, constrained := tx.Context().Value(cloudFormationOwnerKey{}).(cloudFormationOwner); constrained {
			if w := cloudFormationDelete(tx.Context(), old.CFNOwner); w != nil {
				return nil, w
			}
			return &api.Unit{}, nil
		}
		return nil, failure("ResourceAlreadyExistsException", "The specified log stream already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, wireError(err)
	}
	if ownerWire != nil {
		return nil, ownerWire
	}
	if err := tx.PutStream(StreamRecord{Key: k, CFNOwner: owner, ID: uuid.NewString(), Created: s.clock.Now().UnixMilli()}); err != nil {
		return nil, wireError(err)
	}
	return &api.Unit{}, nil
}
func (s *Service) deleteLogStream(tx Transaction, in *api.DeleteLogStreamRequest) (*api.Unit, *awswire.Error) {
	g, w := s.loadGroup(tx, value(in.LogGroupName), "DeleteLogStream", value(in.LogStreamName))
	if w != nil {
		return nil, w
	}
	k := StreamKey{g.ID, value(in.LogStreamName)}
	old, err := tx.Stream(k)
	if err != nil {
		return nil, wireError(err)
	}
	if w := cloudFormationDelete(tx.Context(), old.CFNOwner); w != nil {
		return nil, w
	}
	if err := tx.DeleteStream(k); err != nil {
		return nil, wireError(err)
	}
	return &api.Unit{}, nil
}
func (s *Service) describeLogStreams(tx Transaction, in *api.DescribeLogStreamsRequest) (*api.DescribeLogStreamsResponse, *awswire.Error) {
	ref, w := reference(in.LogGroupName, in.LogGroupIdentifier)
	if w != nil {
		return nil, w
	}
	g, w := s.loadGroup(tx, ref, "DescribeLogStreams", "")
	if w != nil {
		return nil, w
	}
	n, w := pageLimit(in.Limit, 50, 50)
	if w != nil {
		return nil, w
	}
	order := value(in.OrderBy)
	if order != "" && order != "LogStreamName" && order != "LastEventTime" {
		return nil, invalid("orderBy must be LogStreamName or LastEventTime.")
	}
	byTime := order == "LastEventTime"
	if byTime && in.LogStreamNamePrefix != nil {
		return nil, invalid("logStreamNamePrefix cannot be used with LastEventTime ordering.")
	}
	query := queryIdentity("DescribeLogStreams", g.ID, value(in.LogStreamNamePrefix), byTime, enabled(in.Descending))
	token, w := s.decodeToken(value(in.NextToken), query)
	if w != nil {
		return nil, w
	}
	rows, err := tx.Streams(StreamQuery{GroupID: g.ID, Prefix: value(in.LogStreamNamePrefix), After: token.Name, AfterTime: token.Cursor.Timestamp, ByTime: byTime, Descending: enabled(in.Descending), Limit: n + 1})
	if err != nil {
		return nil, wireError(err)
	}
	more := len(rows) > n
	if more {
		rows = rows[:n]
	}
	out := &api.DescribeLogStreamsResponse{LogStreams: api.LogStreams{}}
	for _, v := range rows {
		stream := api.LogStream{LogStreamName: new(api.LogStreamName(v.Key.Name)), Arn: new(api.Arn(g.Key.ARN() + ":log-stream:" + v.Key.Name)), CreationTime: new(api.Timestamp(v.Created)), StoredBytes: new(api.StoredBytes(0))}
		if v.EventCount > 0 {
			stream.FirstEventTimestamp = new(api.Timestamp(v.FirstEvent))
			stream.LastEventTimestamp = new(api.Timestamp(v.LastEvent))
			stream.LastIngestionTime = new(api.Timestamp(v.LastIngestion))
			stream.UploadSequenceToken = new(api.SequenceToken(strconv.FormatInt(v.EventCount, 10)))
		}
		out.LogStreams = append(out.LogStreams, stream)
	}
	if more {
		last := rows[len(rows)-1]
		token.Name = last.Key.Name
		token.Cursor.Timestamp = last.LastEvent
		out.NextToken = encodeToken(token)
	}
	return out, nil
}
