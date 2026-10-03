package eventbridge

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/eventbridge"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/eventbridge/internal/sqlcgen"
)

func (r reader) replay(v sqlcgen.EventbridgeReplay) (domain.ReplayRecord, error) {
	filters, err := r.q.GetReplayFilters(r.ctx, sqlcgen.GetReplayFiltersParams{Partition: v.Partition, Account: v.Account, Region: v.Region, ReplayName: v.Name})
	if err != nil {
		return domain.ReplayRecord{}, err
	}
	out := domain.ReplayRecord{
		Key:         domain.ReplayKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.Name},
		Archive:     domain.ArchiveKey{Scope: domain.Scope{Partition: v.ArchivePartition, Account: v.ArchiveAccount, Region: v.ArchiveRegion}, Name: v.ArchiveName},
		ArchiveID:   v.ArchiveID,
		Destination: domain.BusKey{Scope: domain.Scope{Partition: v.DestinationPartition, Account: v.DestinationAccount, Region: v.DestinationRegion}, Name: v.DestinationBusName},
		Description: v.Description, FilterARNs: filters, StartTime: v.StartTime, EndTime: v.EndTime, Started: v.Started,
		Due:    time.Unix(v.DueSeconds, v.DueNanos).UTC(),
		Cursor: domain.ArchiveCursor{Time: time.Unix(v.CursorSeconds, v.CursorNanos).UTC(), ID: v.CursorID},
		State:  v.State, StateReason: v.StateReason, Version: uint64(v.Version), RequestID: v.RequestID, ActorARN: v.ActorArn,
	}
	if v.FinishedSeconds.Valid {
		out.Finished = time.Unix(v.FinishedSeconds.Int64, v.FinishedNanos).UTC()
	}
	return out, nil
}

func (r reader) Replay(k domain.ReplayKey) (domain.ReplayRecord, error) {
	v, err := r.q.GetReplay(r.ctx, sqlcgen.GetReplayParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.ReplayRecord{}, missing(err)
	}
	return r.replay(v)
}

func (r reader) Replays(scope domain.Scope) ([]domain.ReplayRecord, error) {
	rows, err := r.q.ListReplays(r.ctx, sqlcgen.ListReplaysParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ReplayRecord, 0, len(rows))
	for _, v := range rows {
		record, err := r.replay(v)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (r reader) NextReplay() (domain.ReplayRecord, bool, error) {
	v, err := r.q.NextReplay(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ReplayRecord{}, false, nil
	}
	if err != nil {
		return domain.ReplayRecord{}, false, err
	}
	record, err := r.replay(v)
	return record, err == nil, err
}

func (r reader) NextReplayExpiration() (domain.ReplayRecord, bool, error) {
	v, err := r.q.NextReplayExpiration(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ReplayRecord{}, false, nil
	}
	if err != nil {
		return domain.ReplayRecord{}, false, err
	}
	record, err := r.replay(v)
	return record, err == nil, err
}

func (w writer) PutReplay(v domain.ReplayRecord) error {
	k := v.Key
	if err := w.q.PutReplay(w.ctx, sqlcgen.PutReplayParams{
		Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name,
		ArchivePartition: v.Archive.Partition, ArchiveAccount: v.Archive.Account, ArchiveRegion: v.Archive.Region, ArchiveName: v.Archive.Name, ArchiveID: v.ArchiveID,
		DestinationPartition: v.Destination.Partition, DestinationAccount: v.Destination.Account, DestinationRegion: v.Destination.Region, DestinationBusName: v.Destination.Name,
		Description: v.Description, StartTime: v.StartTime, EndTime: v.EndTime, Started: v.Started,
		FinishedSeconds: archiveOptionalSeconds(v.Finished), FinishedNanos: int64(v.Finished.Nanosecond()),
		DueSeconds: v.Due.Unix(), DueNanos: int64(v.Due.Nanosecond()),
		CursorSeconds: v.Cursor.Time.Unix(), CursorNanos: int64(v.Cursor.Time.Nanosecond()), CursorID: v.Cursor.ID,
		State: v.State, StateReason: v.StateReason, Version: sqlite.Uint64(v.Version), RequestID: v.RequestID, ActorArn: v.ActorARN,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteReplayFilters(w.ctx, sqlcgen.DeleteReplayFiltersParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ReplayName: k.Name}); err != nil {
		return err
	}
	for i, arn := range v.FilterARNs {
		if err := w.q.PutReplayFilter(w.ctx, sqlcgen.PutReplayFilterParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ReplayName: k.Name, Position: int64(i), Arn: arn}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteReplay(k domain.ReplayKey) error {
	return w.q.DeleteReplay(w.ctx, sqlcgen.DeleteReplayParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
}
