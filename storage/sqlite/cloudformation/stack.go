package cloudformation

import (
	"database/sql"
	domain "stackd/storage/cloudformation"
	"stackd/storage/sqlite/cloudformation/internal/sqlcgen"
)

func (r reader) Stack(id string) (domain.StackRecord, error) {
	row, err := r.q.Stack(r.ctx, id)
	if err != nil {
		return domain.StackRecord{}, missing(err)
	}
	return r.decodeStack(row)
}

func (r reader) Stacks(scope domain.Scope) ([]domain.StackRecord, error) {
	rows, err := r.q.Stacks(r.ctx, sqlcgen.StacksParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.StackRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.decodeStack(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) decodeStack(row sqlcgen.CloudformationStack) (domain.StackRecord, error) {
	var out domain.StackRecord
	out.ID = row.ID
	out.Scope.Partition = row.Partition
	out.Scope.Account = row.Account
	out.Scope.Region = row.Region
	out.Name = row.Name
	out.Status = row.Status
	out.StatusReason = row.StatusReason
	out.Description = row.Description
	out.Template = row.Template
	out.RoleARN = row.RoleArn
	out.OperationID = row.OperationID
	out.Created = row.Created.UTC()
	out.Updated = row.Updated.UTC()
	if row.Deleted.Valid {
		out.Deleted = new(row.Deleted.Time.UTC())
	}
	out.DisableRollback = row.DisableRollback
	out.TerminationProtection = row.TerminationProtection
	out.EventSequence = uint64(row.EventSequence)
	if row.ParametersPresent {
		values, err := r.q.StackParameters(r.ctx, row.ID)
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
		values, err := r.q.StackTags(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Tags = make(map[string]string, len(values))
		for _, v := range values {
			out.Tags[v.Key] = v.Value
		}
	}
	if row.CapabilitiesPresent {
		values, err := r.q.StackCapabilities(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Capabilities = make([]string, len(values))
		for i, v := range values {
			out.Capabilities[i] = v.Value
		}
	}
	if row.OutputsPresent {
		values, err := r.q.StackOutputs(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Outputs = make(map[string]domain.OutputValue, len(values))
		for _, v := range values {
			out.Outputs[v.Key] = domain.OutputValue{Value: v.Value, Description: v.Description, ExportName: v.ExportName}
		}
	}
	if row.ImportsPresent {
		values, err := r.q.StackImports(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Imports = make([]string, len(values))
		for i, v := range values {
			out.Imports[i] = v.Value
		}
	}
	return out, nil
}

func encodeStack(v domain.StackRecord) (sqlcgen.PutStackParams, error) {
	var p sqlcgen.PutStackParams
	var err error
	p.ID = v.ID
	p.Partition = v.Scope.Partition
	p.Account = v.Scope.Account
	p.Region = v.Scope.Region
	p.Name = v.Name
	p.Status = v.Status
	p.StatusReason = v.StatusReason
	p.Description = v.Description
	p.Template = v.Template
	p.RoleArn = v.RoleARN
	p.OperationID = v.OperationID
	p.Created = v.Created.UTC()
	p.Updated = v.Updated.UTC()
	p.Deleted = nullableTime(v.Deleted)
	p.ParametersPresent = v.Parameters != nil
	p.TagsPresent = v.Tags != nil
	p.CapabilitiesPresent = v.Capabilities != nil
	p.OutputsPresent = v.Outputs != nil
	p.ImportsPresent = v.Imports != nil
	p.DisableRollback = v.DisableRollback
	p.TerminationProtection = v.TerminationProtection
	p.EventSequence, err = signed(v.EventSequence)
	if err != nil {
		return p, err
	}
	return p, nil
}

func (w writer) PutStack(v domain.StackRecord) error {
	p, err := encodeStack(v)
	if err != nil {
		return err
	}
	if err := w.q.PutStack(w.ctx, p); err != nil {
		return err
	}
	if err := w.q.DeleteStackParameters(w.ctx, v.ID); err != nil {
		return err
	}
	for key, value := range v.Parameters {
		resolved, present := v.ResolvedParameters[key]
		if err := w.q.PutStackParameter(w.ctx, sqlcgen.PutStackParameterParams{ParentID: v.ID, Key: key, Value: value, ResolvedValue: sql.NullString{String: resolved, Valid: present}}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteStackTags(w.ctx, v.ID); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutStackTag(w.ctx, sqlcgen.PutStackTagParams{ParentID: v.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteStackCapabilities(w.ctx, v.ID); err != nil {
		return err
	}
	for i, value := range v.Capabilities {
		if err := w.q.PutStackCapability(w.ctx, sqlcgen.PutStackCapabilityParams{ParentID: v.ID, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteStackOutputs(w.ctx, v.ID); err != nil {
		return err
	}
	for key, value := range v.Outputs {
		if err := w.q.PutStackOutput(w.ctx, sqlcgen.PutStackOutputParams{ParentID: v.ID, Key: key, Value: value.Value, Description: value.Description, ExportName: value.ExportName}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteStackImports(w.ctx, v.ID); err != nil {
		return err
	}
	for i, value := range v.Imports {
		if err := w.q.PutStackImport(w.ctx, sqlcgen.PutStackImportParams{ParentID: v.ID, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	return nil
}
