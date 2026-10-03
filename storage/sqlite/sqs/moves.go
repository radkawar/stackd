package sqs

import (
	"context"

	"stackd/storage/sqlite"
	"stackd/storage/sqlite/sqs/internal/sqlcgen"
	domain "stackd/storage/sqs"
)

func (r reader) MoveTasks() ([]domain.MoveTaskRecord, error) {
	rows, err := r.q.ListMoveTasks(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.MoveTaskRecord, 0, len(rows))
	for _, row := range rows {
		task := domain.MoveTaskRecord{
			Handle: row.Handle, Sequence: uint64(row.Sequence), Source: domain.QueueKey{Partition: row.SourcePartition, Account: row.SourceAccount, Region: row.SourceRegion, Name: row.SourceName},
			SourceID: row.SourceID, Destination: row.Destination, Status: row.Status, Started: row.Started, Due: row.Due, Rate: int(row.Rate), CustomRate: row.CustomRate, Moved: row.Moved, ToMove: row.ToMove, Failure: row.Failure,
			Caller: domain.CallerMetadata{
				AccountID: row.CallerAccount, Region: row.CallerRegion, Partition: row.CallerPartition, AccessKeyID: row.AccessKeyID, RequestID: row.RequestID,
				PrincipalARN: row.PrincipalArn, PrincipalID: row.PrincipalID, UserName: row.UserName, SessionType: row.SessionType, IssuerARN: row.IssuerArn, IssuerID: row.IssuerID,
				HasSessionPolicy: row.HasSessionPolicy, FederatedProvider: row.FederatedProvider, SourceIdentity: row.SourceIdentity, MFAPresent: row.MfaPresent,
				MFAAuthenticatedAt: row.MfaAuthenticatedAt, TokenIssueTime: row.TokenIssueTime, TransportKnown: row.TransportKnown, SourceIP: row.SourceIp, SecureTransport: row.SecureTransport, UserAgent: row.UserAgent,
			},
		}
		if err := r.caller(row.Handle, &task.Caller); err != nil {
			return nil, err
		}
		out = append(out, task)
	}
	return out, nil
}

func (r reader) caller(handle string, caller *domain.CallerMetadata) error {
	lists, err := r.q.ListMoveCallerLists(r.ctx, handle)
	if err != nil {
		return err
	}
	for _, row := range lists {
		switch row.Kind {
		case "policy":
			caller.SessionPolicies = append(caller.SessionPolicies, row.Value)
		case "policy_arn":
			caller.SessionPolicyARNs = append(caller.SessionPolicyARNs, row.Value)
		case "transitive_tag":
			caller.TransitiveTagKeys = append(caller.TransitiveTagKeys, row.Value)
		case "called_via":
			caller.CalledVia = append(caller.CalledVia, row.Value)
		}
	}
	tags, err := r.q.ListMoveCallerTags(r.ctx, handle)
	if err != nil {
		return err
	}
	if len(tags) > 0 {
		caller.SessionTags = make(map[string]string, len(tags))
		for _, row := range tags {
			caller.SessionTags[row.TagKey] = row.TagValue
		}
	}
	claims, err := r.q.ListMoveCallerContext(r.ctx, handle)
	if err != nil {
		return err
	}
	if len(claims) > 0 {
		caller.SessionContext = make(map[string][]string)
		for _, row := range claims {
			caller.SessionContext[row.ContextKey] = append(caller.SessionContext[row.ContextKey], row.Value)
		}
	}
	return nil
}

func (w writer) PutMoveTask(task domain.MoveTaskRecord) error {
	m := task.Caller
	if err := w.q.PutMoveTask(w.ctx, sqlcgen.PutMoveTaskParams{
		Handle: task.Handle, Sequence: sqlite.Uint64(task.Sequence), SourcePartition: task.Source.Partition, SourceAccount: task.Source.Account, SourceRegion: task.Source.Region, SourceName: task.Source.Name,
		SourceID: task.SourceID, Destination: task.Destination, Status: task.Status, Started: task.Started, Due: task.Due, Rate: int64(task.Rate), CustomRate: task.CustomRate, Moved: task.Moved, ToMove: task.ToMove, Failure: task.Failure,
		CallerAccount: m.AccountID, CallerRegion: m.Region, CallerPartition: m.Partition, AccessKeyID: m.AccessKeyID, RequestID: m.RequestID, PrincipalArn: m.PrincipalARN, PrincipalID: m.PrincipalID, UserName: m.UserName,
		SessionType: m.SessionType, IssuerArn: m.IssuerARN, IssuerID: m.IssuerID, HasSessionPolicy: m.HasSessionPolicy, FederatedProvider: m.FederatedProvider, SourceIdentity: m.SourceIdentity, MfaPresent: m.MFAPresent,
		MfaAuthenticatedAt: m.MFAAuthenticatedAt, TokenIssueTime: m.TokenIssueTime, TransportKnown: m.TransportKnown, SourceIp: m.SourceIP, SecureTransport: m.SecureTransport, UserAgent: m.UserAgent,
	}); err != nil {
		return err
	}
	for _, clear := range []func(context.Context, string) error{w.q.ClearMoveCallerLists, w.q.ClearMoveCallerTags, w.q.ClearMoveCallerContext} {
		if err := clear(w.ctx, task.Handle); err != nil {
			return err
		}
	}
	for _, list := range []struct {
		kind   string
		values []string
	}{{"policy", m.SessionPolicies}, {"policy_arn", m.SessionPolicyARNs}, {"transitive_tag", m.TransitiveTagKeys}, {"called_via", m.CalledVia}} {
		for i, value := range list.values {
			if err := w.q.InsertMoveCallerList(w.ctx, sqlcgen.InsertMoveCallerListParams{TaskHandle: task.Handle, Kind: list.kind, Position: int64(i), Value: value}); err != nil {
				return err
			}
		}
	}
	for key, value := range m.SessionTags {
		if err := w.q.InsertMoveCallerTag(w.ctx, sqlcgen.InsertMoveCallerTagParams{TaskHandle: task.Handle, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	for key, values := range m.SessionContext {
		for i, value := range values {
			if err := w.q.InsertMoveCallerContext(w.ctx, sqlcgen.InsertMoveCallerContextParams{TaskHandle: task.Handle, ContextKey: key, Position: int64(i), Value: value}); err != nil {
				return err
			}
		}
	}
	return nil
}
