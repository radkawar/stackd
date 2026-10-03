package cloudformation

import (
	"database/sql"
	domain "stackd/storage/cloudformation"
	"stackd/storage/sqlite/cloudformation/internal/sqlcgen"
)

func (r reader) ChangeSet(id string) (domain.ChangeSetRecord, error) {
	row, err := r.q.ChangeSet(r.ctx, id)
	if err != nil {
		return domain.ChangeSetRecord{}, missing(err)
	}
	return r.decodeChangeSet(row)
}

func (r reader) ChangeSets(stack string) ([]domain.ChangeSetRecord, error) {
	rows, err := r.q.ChangeSets(r.ctx, stack)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ChangeSetRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.decodeChangeSet(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) decodeChangeSet(row sqlcgen.CloudformationChangeSet) (domain.ChangeSetRecord, error) {
	var out domain.ChangeSetRecord
	out.ID = row.ID
	out.Scope.Partition = row.Partition
	out.Scope.Account = row.Account
	out.Scope.Region = row.Region
	out.Name = row.Name
	out.StackID = row.StackID
	out.StackName = row.StackName
	out.Type = row.Type
	out.Status = row.Status
	out.ExecutionStatus = row.ExecutionStatus
	out.Reason = row.Reason
	out.Description = row.Description
	out.Template = row.Template
	out.RoleARN = row.RoleArn
	out.Token = row.Token
	out.RequestHash = row.RequestHash
	out.Created = row.Created.UTC()
	out.DisableRollback = row.DisableRollback
	if row.ParametersPresent {
		values, err := r.q.ChangeSetParameters(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Parameters = make(map[string]string, len(values))
		for _, v := range values {
			out.Parameters[v.Key] = v.Value
			if v.ResolvedValue.Valid {
				if out.ResolvedParameters == nil {
					out.ResolvedParameters = map[string]string{}
				}
				out.ResolvedParameters[v.Key] = v.ResolvedValue.String
			}
		}
	}
	if row.TagsPresent {
		values, err := r.q.ChangeSetTags(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Tags = make(map[string]string, len(values))
		for _, v := range values {
			out.Tags[v.Key] = v.Value
		}
	}
	if row.CapabilitiesPresent {
		values, err := r.q.ChangeSetCapabilities(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Capabilities = make([]string, len(values))
		for i, v := range values {
			out.Capabilities[i] = v.Value
		}
	}
	if row.ChangesPresent {
		values, err := r.q.Changes(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Changes = make([]domain.ChangeRecord, len(values))
		for i, v := range values {
			out.Changes[i] = domain.ChangeRecord{LogicalID: v.LogicalID, Type: v.Type, Action: v.Action, Replacement: v.Replacement, PhysicalID: v.PhysicalID, BeforeContext: v.BeforeContext, AfterContext: v.AfterContext}
		}
	}
	return out, nil
}

func encodeChangeSet(v domain.ChangeSetRecord) (sqlcgen.PutChangeSetParams, error) {
	var p sqlcgen.PutChangeSetParams
	p.ID = v.ID
	p.Partition = v.Scope.Partition
	p.Account = v.Scope.Account
	p.Region = v.Scope.Region
	p.Name = v.Name
	p.StackID = v.StackID
	p.StackName = v.StackName
	p.Type = v.Type
	p.Status = v.Status
	p.ExecutionStatus = v.ExecutionStatus
	p.Reason = v.Reason
	p.Description = v.Description
	p.Template = v.Template
	p.RoleArn = v.RoleARN
	p.Token = v.Token
	p.RequestHash = v.RequestHash
	p.ParametersPresent = v.Parameters != nil
	p.TagsPresent = v.Tags != nil
	p.CapabilitiesPresent = v.Capabilities != nil
	p.ChangesPresent = v.Changes != nil
	p.Created = v.Created.UTC()
	p.DisableRollback = v.DisableRollback
	return p, nil
}

func (w writer) PutChangeSet(v domain.ChangeSetRecord) error {
	p, err := encodeChangeSet(v)
	if err != nil {
		return err
	}
	if err := w.q.PutChangeSet(w.ctx, p); err != nil {
		return err
	}
	if err := w.q.DeleteChangeSetParameters(w.ctx, v.ID); err != nil {
		return err
	}
	for key, value := range v.Parameters {
		resolved, present := v.ResolvedParameters[key]
		if err := w.q.PutChangeSetParameter(w.ctx, sqlcgen.PutChangeSetParameterParams{ParentID: v.ID, Key: key, Value: value, ResolvedValue: sql.NullString{String: resolved, Valid: present}}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteChangeSetTags(w.ctx, v.ID); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutChangeSetTag(w.ctx, sqlcgen.PutChangeSetTagParams{ParentID: v.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteChangeSetCapabilities(w.ctx, v.ID); err != nil {
		return err
	}
	for i, value := range v.Capabilities {
		if err := w.q.PutChangeSetCapability(w.ctx, sqlcgen.PutChangeSetCapabilityParams{ParentID: v.ID, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteChanges(w.ctx, v.ID); err != nil {
		return err
	}
	for i, value := range v.Changes {
		if err := w.q.PutChange(w.ctx, sqlcgen.PutChangeParams{ParentID: v.ID, Position: int64(i), LogicalID: value.LogicalID, Type: value.Type, Action: value.Action, Replacement: value.Replacement, PhysicalID: value.PhysicalID, BeforeContext: value.BeforeContext, AfterContext: value.AfterContext}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteChangeSet(id string) error { return w.q.DeleteChangeSet(w.ctx, id) }
