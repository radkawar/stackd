package ssmcommands

import (
	"database/sql"

	"stackd/storage/sqlite/ssmcommands/internal/sqlcgen"
	domain "stackd/storage/ssmcommands"
)

func (r reader) Command(k domain.Key) (domain.Command, error) {
	row, err := r.q.GetCommand(r.ctx, sqlcgen.GetCommandParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, CommandID: k.ID})
	if err != nil {
		return domain.Command{}, missing(err)
	}
	return r.command(row)
}
func (r reader) Commands(scope domain.Scope) ([]domain.Command, error) {
	rows, err := r.q.ListCommands(r.ctx, sqlcgen.ListCommandsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Command, 0, len(rows))
	for _, row := range rows {
		v, err := r.command(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) NextDeadline() (domain.Command, error) {
	row, err := r.q.NextDeadline(r.ctx)
	if err != nil {
		return domain.Command{}, missing(err)
	}
	return r.command(row)
}
func (r reader) command(row sqlcgen.SsmCommand) (domain.Command, error) {
	out := domain.Command{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.CommandID}, DocumentName: row.DocumentName, DocumentVersion: row.DocumentVersion, DocumentHash: row.DocumentHash, Content: row.Content, Comment: row.Comment, RequestedAt: row.RequestedAt, DeliveryDeadline: row.DeliveryDeadline, EmptyTargetReadyAt: row.EmptyTargetReadyAt.Time, TimeoutSeconds: int32(row.TimeoutSeconds), MaxConcurrency: row.MaxConcurrency, MaxErrors: row.MaxErrors, Concurrency: int(row.Concurrency), ErrorBudget: int(row.ErrorBudget), OutputBucket: row.OutputBucket, OutputPrefix: row.OutputPrefix, OutputRegion: row.OutputRegion, LogGroup: row.LogGroup, CloudWatchEnabled: row.CloudWatchEnabled, Status: row.Status, StatusDetails: row.StatusDetails, ParentEventID: row.ParentEventID}
	if row.ParametersPresent {
		parameters, err := r.q.ListParameters(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Parameters = make(map[string][]string, len(parameters))
		for _, parameter := range parameters {
			var values []string
			if parameter.ValuesPresent {
				rows, err := r.q.ListParameterValues(r.ctx, sqlcgen.ListParameterValuesParams{CommandID: row.ID, Name: parameter.Name})
				if err != nil {
					return out, err
				}
				values = make([]string, 0, len(rows))
				for _, value := range rows {
					values = append(values, value.Value)
				}
			}
			out.Parameters[parameter.Name] = values
		}
	}
	if row.InstanceIdsPresent {
		rows, err := r.q.ListInstanceIDs(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.InstanceIDs = make([]string, 0, len(rows))
		for _, value := range rows {
			out.InstanceIDs = append(out.InstanceIDs, value.NodeID)
		}
	}
	if row.TargetsPresent {
		rows, err := r.q.ListTargets(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Targets = make([]domain.Target, 0, len(rows))
		for _, target := range rows {
			v := domain.Target{Key: target.TargetKey}
			if target.ValuesPresent {
				values, err := r.q.ListTargetValues(r.ctx, sqlcgen.ListTargetValuesParams{CommandID: row.ID, TargetPosition: target.Position})
				if err != nil {
					return out, err
				}
				v.Values = make([]string, 0, len(values))
				for _, value := range values {
					v.Values = append(v.Values, value.Value)
				}
			}
			out.Targets = append(out.Targets, v)
		}
	}
	if err := r.notificationConfig(row.ID, &out); err != nil {
		return out, err
	}
	if err := r.alarmConfig(row.ID, &out); err != nil {
		return out, err
	}
	return out, nil
}
func (w writer) PutCommand(v domain.Command) error {
	k := v.Key
	id, err := w.q.PutCommand(w.ctx, sqlcgen.PutCommandParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, CommandID: k.ID, DocumentName: v.DocumentName, DocumentVersion: v.DocumentVersion, DocumentHash: v.DocumentHash, Content: v.Content, Comment: v.Comment, ParametersPresent: v.Parameters != nil, InstanceIdsPresent: v.InstanceIDs != nil, TargetsPresent: v.Targets != nil, RequestedAt: v.RequestedAt.UTC(), DeliveryDeadline: v.DeliveryDeadline.UTC(), EmptyTargetReadyAt: sql.NullTime{Time: v.EmptyTargetReadyAt.UTC(), Valid: !v.EmptyTargetReadyAt.IsZero()}, TimeoutSeconds: int64(v.TimeoutSeconds), MaxConcurrency: v.MaxConcurrency, MaxErrors: v.MaxErrors, Concurrency: int64(v.Concurrency), ErrorBudget: int64(v.ErrorBudget), OutputBucket: v.OutputBucket, OutputPrefix: v.OutputPrefix, OutputRegion: v.OutputRegion, LogGroup: v.LogGroup, CloudWatchEnabled: v.CloudWatchEnabled, Status: v.Status, StatusDetails: v.StatusDetails, ParentEventID: v.ParentEventID})
	if err != nil {
		return err
	}
	if err := w.q.DeleteParameters(w.ctx, id); err != nil {
		return err
	}
	for name, values := range v.Parameters {
		if err := w.q.PutParameters(w.ctx, sqlcgen.PutParametersParams{CommandID: id, Name: name, ValuesPresent: values != nil}); err != nil {
			return err
		}
		for i, value := range values {
			if err := w.q.PutParameterValues(w.ctx, sqlcgen.PutParameterValuesParams{CommandID: id, Name: name, Position: int64(i), Value: value}); err != nil {
				return err
			}
		}
	}
	if err := w.q.DeleteInstanceIDs(w.ctx, id); err != nil {
		return err
	}
	for i, nodeID := range v.InstanceIDs {
		if err := w.q.PutInstanceIDs(w.ctx, sqlcgen.PutInstanceIDsParams{CommandID: id, Position: int64(i), NodeID: nodeID}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteTargets(w.ctx, id); err != nil {
		return err
	}
	for i, target := range v.Targets {
		if err := w.q.PutTargets(w.ctx, sqlcgen.PutTargetsParams{CommandID: id, Position: int64(i), TargetKey: target.Key, ValuesPresent: target.Values != nil}); err != nil {
			return err
		}
		for j, value := range target.Values {
			if err := w.q.PutTargetValues(w.ctx, sqlcgen.PutTargetValuesParams{CommandID: id, TargetPosition: int64(i), Position: int64(j), Value: value}); err != nil {
				return err
			}
		}
	}
	if err := w.putAlarmConfig(id, v); err != nil {
		return err
	}
	return w.putNotificationConfig(id, v)
}
