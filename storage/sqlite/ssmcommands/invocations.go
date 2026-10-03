package ssmcommands

import (
	"errors"

	"stackd/storage/sqlite/ssmcommands/internal/sqlcgen"
	domain "stackd/storage/ssmcommands"
)

func (r reader) Invocation(k domain.InvocationKey) (domain.Invocation, error) {
	id, err := r.commandID(k.Command)
	if err != nil {
		return domain.Invocation{}, err
	}
	row, err := r.q.GetInvocation(r.ctx, sqlcgen.GetInvocationParams{CommandID: id, NodeID: k.NodeID})
	if err != nil {
		return domain.Invocation{}, missing(err)
	}
	return r.invocation(k.Command, row)
}
func (r reader) Invocations(k domain.Key) ([]domain.Invocation, error) {
	id, err := r.commandID(k)
	if errors.Is(err, domain.ErrNotFound) {
		return []domain.Invocation{}, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListInvocations(r.ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Invocation, 0, len(rows))
	for _, row := range rows {
		v, err := r.invocation(k, row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) NodeInvocations(k domain.Key) ([]domain.Invocation, error) {
	commands, err := r.q.ListNodeInvocationCommands(r.ctx, sqlcgen.ListNodeInvocationCommandsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, NodeID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Invocation, 0, len(commands))
	for _, id := range commands {
		v, err := r.Invocation(domain.InvocationKey{Command: domain.Key{Scope: k.Scope, ID: id}, NodeID: k.ID})
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) invocation(k domain.Key, row sqlcgen.SsmCommandInvocation) (domain.Invocation, error) {
	out := domain.Invocation{Key: domain.InvocationKey{Command: k, NodeID: row.NodeID}, InstanceName: row.InstanceName, Status: row.Status, StatusDetails: row.StatusDetails, Trace: row.Trace, DeliveryID: row.DeliveryID, CancelID: row.CancelID, CancelJobID: row.CancelJobID, DeliveredAt: row.DeliveredAt.Time, StartedAt: row.StartedAt.Time, FinishedAt: row.FinishedAt.Time, RetryAt: row.RetryAt.Time, DeliveryAcknowledged: row.DeliveryAcknowledged, CancelAcknowledged: row.CancelAcknowledged}
	if row.PluginsPresent {
		plugins, err := r.q.ListPlugins(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Plugins = make([]domain.Plugin, 0, len(plugins))
		for _, p := range plugins {
			out.Plugins = append(out.Plugins, domain.Plugin{Name: p.Name, Action: p.Action, Status: p.Status, StatusDetails: p.StatusDetails, Code: int32(p.Code), Output: p.Output, StandardOutput: p.StandardOutput, StandardError: p.StandardError, StartedAt: p.StartedAt.Time, FinishedAt: p.FinishedAt.Time, OutputBucket: p.OutputBucket, OutputPrefix: p.OutputPrefix})
		}
	}
	if row.ReplyIdsPresent {
		replies, err := r.q.ListReplyIDs(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.ReplyIDs = make([]string, 0, len(replies))
		for _, reply := range replies {
			out.ReplyIDs = append(out.ReplyIDs, reply.ReplyID)
		}
	}
	return out, nil
}
func (w writer) PutInvocation(v domain.Invocation) error {
	commandID, err := w.commandID(v.Key.Command)
	if err != nil {
		return err
	}
	id, err := w.q.PutInvocation(w.ctx, sqlcgen.PutInvocationParams{CommandID: commandID, NodeID: v.Key.NodeID, InstanceName: v.InstanceName, Status: v.Status, StatusDetails: v.StatusDetails, Trace: v.Trace, DeliveryID: v.DeliveryID, CancelID: v.CancelID, CancelJobID: v.CancelJobID, DeliveredAt: storedTime(v.DeliveredAt), StartedAt: storedTime(v.StartedAt), FinishedAt: storedTime(v.FinishedAt), RetryAt: storedTime(v.RetryAt), DeliveryAcknowledged: v.DeliveryAcknowledged, CancelAcknowledged: v.CancelAcknowledged, PluginsPresent: v.Plugins != nil, ReplyIdsPresent: v.ReplyIDs != nil})
	if err != nil {
		return err
	}
	if err := w.q.DeletePlugins(w.ctx, id); err != nil {
		return err
	}
	for i, p := range v.Plugins {
		if err := w.q.PutPlugins(w.ctx, sqlcgen.PutPluginsParams{InvocationID: id, Position: int64(i), Name: p.Name, Action: p.Action, Status: p.Status, StatusDetails: p.StatusDetails, Code: int64(p.Code), Output: p.Output, StandardOutput: p.StandardOutput, StandardError: p.StandardError, StartedAt: storedTime(p.StartedAt), FinishedAt: storedTime(p.FinishedAt), OutputBucket: p.OutputBucket, OutputPrefix: p.OutputPrefix}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteReplyIDs(w.ctx, id); err != nil {
		return err
	}
	for i, reply := range v.ReplyIDs {
		if err := w.q.PutReplyIDs(w.ctx, sqlcgen.PutReplyIDsParams{InvocationID: id, Position: int64(i), ReplyID: reply}); err != nil {
			return err
		}
	}
	return nil
}
