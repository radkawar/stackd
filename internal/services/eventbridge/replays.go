package eventbridge

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) registerReplays() {
	register(s, "StartReplay", s.startReplay)
	register(s, "DescribeReplay", s.describeReplay)
	register(s, "CancelReplay", s.cancelReplay)
	register(s, "ListReplays", s.listReplays)
}

func replaySource(ctx context.Context, arn string) (ArchiveKey, *awswire.Error) {
	scope := scopeFor(ctx)
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "events" || parts[3] != scope.Region || parts[4] != scope.Account || !strings.HasPrefix(parts[5], "archive/") {
		return ArchiveKey{}, failure("ValidationException", "Parameter EventSourceArn is not valid. Reason: Must contain an archive ARN.")
	}
	name := strings.TrimPrefix(parts[5], "archive/")
	if name == "" || strings.Contains(name, "/") {
		return ArchiveKey{}, failure("ValidationException", "Parameter EventSourceArn is not valid. Reason: Must contain an archive ARN.")
	}
	return ArchiveKey{Scope: scope, Name: name}, nil
}

func readReplay(r Reader, key ReplayKey) (ReplayRecord, error) {
	replay, err := r.Replay(key)
	if errors.Is(err, ErrNotFound) {
		return ReplayRecord{}, failure("ResourceNotFoundException", "Replay "+key.Name+" does not exist.")
	}
	return replay, err
}

func (s *Service) startReplay(ctx context.Context, in *api.StartReplayInput) (out *api.StartReplayOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "StartReplay", in, &out, &rejected, false)
	source, wire := replaySource(ctx, value(in.EventSourceArn))
	if wire != nil {
		return nil, wire
	}
	if in.Destination == nil || in.Destination.Arn == nil {
		return nil, failure("ValidationException", "Parameter Destination.Arn is not valid. Reason: Must contain an event bus ARN.")
	}
	destination, rule, wire := resourceKey(ctx, value(in.Destination.Arn))
	if wire != nil || rule != nil || !strings.HasPrefix(value(in.Destination.Arn), "arn:") {
		return nil, failure("ValidationException", "Parameter Destination.Arn is not valid. Reason: Must contain an event bus ARN.")
	}
	if in.EventStartTime == nil || in.EventEndTime == nil || !time.Time(*in.EventEndTime).After(time.Time(*in.EventStartTime)) {
		return nil, failure("ValidationException", "Parameter EventEndTime is not valid. Reason: EventStartTime must be before EventEndTime.")
	}
	metadata := awsctx.FromContext(ctx)
	replay := ReplayRecord{
		Key: ReplayKey{Scope: scopeFor(ctx), Name: value(in.ReplayName)}, Archive: source, Destination: destination,
		Description: value(in.Description), StartTime: time.Time(*in.EventStartTime).UTC().Truncate(time.Second), EndTime: time.Time(*in.EventEndTime).UTC().Truncate(time.Second),
		State: "STARTING", Version: 1, RequestID: metadata.RequestID, ActorARN: metadata.PrincipalARN,
	}
	if len(in.Destination.FilterArns) > 0 {
		replay.FilterARNs = make([]string, len(in.Destination.FilterArns))
		for i, arn := range in.Destination.FilterArns {
			replay.FilterARNs[i] = string(arn)
		}
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx, "StartReplay", replay.Key.ARN(), nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		if err := s.authorizeArchive(tx, "StartReplay", source); err != nil {
			return err
		}
		bus, err := archiveSourceBus(tx, destination)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "StartReplay", destination.ARN(), bus.Tags, nil, bus.Policy); err != nil {
			return err
		}
		if _, err := tx.Replay(replay.Key); err == nil {
			return failure("ResourceAlreadyExistsException", "Replay "+replay.Key.Name+" already exists.")
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		archive, err := readArchive(tx, source)
		if err != nil {
			var rejected *awswire.Error
			if errors.As(err, &rejected) && rejected.Code == "ResourceNotFoundException" {
				return failure("ValidationException", "Parameter EventSourceArn is not valid. Reason: Archive "+source.Name+" does not exist.")
			}
			return err
		}
		if archive.Source != destination {
			return failure("ValidationException", "Parameter Destination.Arn is not valid. Reason: Cross event bus replay is not permitted.")
		}
		for _, arn := range replay.FilterARNs {
			filterBus, filter, wire := resourceKey(ctx, arn)
			if wire != nil || filter == nil || filterBus != destination || filter.ARN() != arn {
				return failure("ValidationException", "Parameter Destination.FilterArns is not valid. Reason: Rule must be on the destination event bus.")
			}
			if _, err := tx.Rule(*filter); errors.Is(err, ErrNotFound) {
				return failure("ResourceNotFoundException", "Rule "+filter.Name+" does not exist on EventBus "+destination.Name+".")
			} else if err != nil {
				return err
			}
		}
		replay.ArchiveID = archive.ID
		replay.Started = s.clock.Now().Truncate(time.Second)
		replay.Due = replay.Started.Add(time.Minute)
		if err := tx.PutReplay(replay); err != nil {
			return err
		}
		out = &api.StartReplayOutput{ReplayArn: str[api.ReplayArn](replay.Key.ARN()), State: str[api.ReplayState](replay.State), ReplayStartTime: ptr(api.Timestamp(replay.Started))}
		return s.recordCall(tx.Context(), "StartReplay", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func replaySummary(replay ReplayRecord) api.Replay {
	out := api.Replay{
		ReplayName: str[api.ReplayName](replay.Key.Name), State: str[api.ReplayState](replay.State), EventSourceArn: str[api.ArchiveArn](replay.Archive.ARN()),
		EventStartTime: ptr(api.Timestamp(replay.StartTime)), EventEndTime: ptr(api.Timestamp(replay.EndTime)), ReplayStartTime: ptr(api.Timestamp(replay.Started)),
	}
	if replay.StateReason != "" {
		out.StateReason = str[api.ReplayStateReason](replay.StateReason)
	}
	if !replay.Finished.IsZero() {
		out.ReplayEndTime = ptr(api.Timestamp(replay.Finished))
	}
	if replay.Cursor.ID != "" {
		out.EventLastReplayedTime = ptr(api.Timestamp(replay.Cursor.Time.Truncate(time.Minute)))
	}
	return out
}

func (s *Service) describeReplay(ctx context.Context, in *api.DescribeReplayInput) (out *api.DescribeReplayOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DescribeReplay", in, &out, &rejected, true)
	key := ReplayKey{Scope: scopeFor(ctx), Name: value(in.ReplayName)}
	var replay ReplayRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorize(r, "DescribeReplay", key.ARN(), nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		var err error
		replay, err = readReplay(r, key)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	summary := replaySummary(replay)
	out = &api.DescribeReplayOutput{
		ReplayName: summary.ReplayName, ReplayArn: str[api.ReplayArn](key.ARN()), State: summary.State, StateReason: summary.StateReason,
		EventSourceArn: summary.EventSourceArn, EventStartTime: summary.EventStartTime, EventEndTime: summary.EventEndTime,
		EventLastReplayedTime: summary.EventLastReplayedTime, ReplayStartTime: summary.ReplayStartTime, ReplayEndTime: summary.ReplayEndTime,
		Destination: &api.ReplayDestination{Arn: str[api.Arn](replay.Destination.ARN())},
	}
	if replay.Description != "" {
		out.Description = str[api.ReplayDescription](replay.Description)
	}
	if len(replay.FilterARNs) > 0 {
		out.Destination.FilterArns = make(api.ReplayDestinationFilters, len(replay.FilterARNs))
		for i, arn := range replay.FilterARNs {
			out.Destination.FilterArns[i] = api.Arn(arn)
		}
	}
	return out, nil
}

func (s *Service) cancelReplay(ctx context.Context, in *api.CancelReplayInput) (out *api.CancelReplayOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "CancelReplay", in, &out, &rejected, false)
	key := ReplayKey{Scope: scopeFor(ctx), Name: value(in.ReplayName)}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx, "CancelReplay", key.ARN(), nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		replay, err := readReplay(tx, key)
		if err != nil {
			return err
		}
		if replay.State != "STARTING" && replay.State != "RUNNING" {
			return failure("IllegalStatusException", "Replay "+key.Name+" is not in a valid state for this operation.")
		}
		replay.State, replay.StateReason = "CANCELLING", ""
		replay.Due = s.clock.Now().Add(time.Second)
		replay.Version++
		if err := tx.PutReplay(replay); err != nil {
			return err
		}
		out = &api.CancelReplayOutput{ReplayArn: str[api.ReplayArn](key.ARN()), State: str[api.ReplayState](replay.State)}
		return s.recordCall(tx.Context(), "CancelReplay", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func (s *Service) listReplays(ctx context.Context, in *api.ListReplaysInput) (out *api.ListReplaysOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListReplays", in, &out, &rejected, true)
	filters := 0
	if in.EventSourceArn != nil {
		filters++
	}
	if in.NamePrefix != nil {
		filters++
	}
	if in.State != nil {
		filters++
	}
	if filters > 1 {
		return nil, failure("ValidationException", "At most one filter is allowed for ListReplays. Use either : State, EventSourceArn, or NamePrefix.")
	}
	var source ArchiveKey
	if in.EventSourceArn != nil {
		var wire *awswire.Error
		source, wire = replaySource(ctx, value(in.EventSourceArn))
		if wire != nil {
			return nil, wire
		}
	}
	scope := scopeFor(ctx)
	var rows []ReplayRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorize(r, "ListReplays", "*", nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		var err error
		rows, err = r.Replays(scope)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	filtered := rows[:0]
	for _, replay := range rows {
		if !strings.HasPrefix(replay.Key.Name, value(in.NamePrefix)) || in.State != nil && replay.State != value(in.State) || in.EventSourceArn != nil && replay.Archive != source {
			continue
		}
		filtered = append(filtered, replay)
	}
	collection := (ReplayKey{Scope: scope}).ARN() + "/ListReplays/" + value(in.NamePrefix) + "/" + value(in.State) + "/" + value(in.EventSourceArn)
	rows, next, wire := page(filtered, func(replay ReplayRecord) string { return replay.Key.Name }, collection, in.Limit, in.NextToken, "ValidationException")
	if wire != nil {
		return nil, wire
	}
	out = &api.ListReplaysOutput{Replays: make(api.ReplayList, 0, len(rows)), NextToken: next}
	for _, replay := range rows {
		out.Replays = append(out.Replays, replaySummary(replay))
	}
	return out, nil
}
