package codepipeline

import (
	domain "stackd/storage/codepipeline"
	"stackd/storage/sqlite/codepipeline/internal/sqlcgen"
)

func sourcePoll(row sqlcgen.CodepipelineSourcePoll) domain.SourcePoll {
	return domain.SourcePoll{
		Scope:        domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region},
		PipelineName: row.PipelineName, Incarnation: row.Incarnation, PipelineVersion: int32(row.PipelineVersion),
		StageName: row.StageName, ActionName: row.ActionName, Bucket: row.Bucket, ObjectKey: row.ObjectKey,
		RevisionID: row.RevisionID, PollID: row.PollID, ParentEventID: row.ParentEventID,
		ErrorCode: row.ErrorCode, ErrorMessage: row.ErrorMessage, LastAttempt: instant(row.LastAttempt),
		Generation: row.Generation, Due: instant(row.Due),
	}
}
func (r reader) SourcePolls(sc domain.Scope, id string) ([]domain.SourcePoll, error) {
	rows, err := r.q.ListSourcePolls(r.ctx, sqlcgen.ListSourcePollsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Incarnation: id})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SourcePoll, 0, len(rows))
	for _, row := range rows {
		out = append(out, sourcePoll(row))
	}
	return out, nil
}
func (r reader) PendingSourcePolls() ([]domain.SourcePoll, error) {
	rows, err := r.q.PendingSourcePolls(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.SourcePoll, 0, len(rows))
	for _, row := range rows {
		out = append(out, sourcePoll(row))
	}
	return out, nil
}
func (w writer) PutSourcePoll(v domain.SourcePoll) error {
	return w.q.PutSourcePoll(w.ctx, sqlcgen.PutSourcePollParams{
		Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Incarnation: v.Incarnation,
		PipelineName: v.PipelineName, PipelineVersion: int64(v.PipelineVersion), StageName: v.StageName, ActionName: v.ActionName,
		Bucket: v.Bucket, ObjectKey: v.ObjectKey, RevisionID: v.RevisionID, PollID: v.PollID, ParentEventID: v.ParentEventID,
		Generation: v.Generation, Due: nanos(v.Due),
		ErrorCode: v.ErrorCode, ErrorMessage: v.ErrorMessage, LastAttempt: nanos(v.LastAttempt),
	})
}
func (w writer) DeleteSourcePolls(sc domain.Scope, id string) error {
	return w.q.DeleteSourcePolls(w.ctx, sqlcgen.DeleteSourcePollsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Incarnation: id})
}
