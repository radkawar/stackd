package ecs

import (
	"database/sql"
	"errors"

	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
	domain "stackd/storage/ecs"
	"stackd/storage/sqlite/ecs/internal/sqlcgen"
)

func (r reader) TaskDefinition(k domain.TaskDefinitionKey) (domain.TaskDefinitionRecord, error) {
	row, err := r.q.GetTaskDefinition(r.ctx, sqlcgen.GetTaskDefinitionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Family: k.Family, Revision: int64(k.Revision)})
	if err != nil {
		return domain.TaskDefinitionRecord{}, missing(err)
	}
	return r.taskDefinition(row)
}
func (r reader) TaskDefinitions(q domain.TaskDefinitionQuery) ([]domain.TaskDefinitionRecord, error) {
	rows, err := r.q.ListTaskDefinitions(r.ctx, sqlcgen.ListTaskDefinitionsParams{
		Partition: q.Partition, AccountID: q.AccountID, Region: q.Region,
		ExactFamily: q.Family, FamilyPrefix: q.FamilyPrefix, TaskStatus: q.Status,
		AfterFamily: q.AfterFamily, AfterRevision: int64(q.AfterRevision), Descending: flag(q.Descending), RowLimit: rowLimit(q.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.TaskDefinitionRecord, 0, len(rows))
	for _, row := range rows {
		record, err := r.taskDefinition(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (r reader) taskDefinition(row sqlcgen.EcsTaskDefinition) (domain.TaskDefinitionRecord, error) {
	k := domain.TaskDefinitionKey{FamilyKey: domain.FamilyKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Family: row.Family}, Revision: int32(row.Revision)}
	out := domain.TaskDefinitionRecord{Key: k, Data: api.TaskDefinition{
		TaskDefinitionArn: stringPointer[api.String](row.TaskDefinitionArn), Family: stringPointer[api.String](row.TaskFamily), Revision: integerPointer[api.Integer](row.TaskRevision),
		Status: stringPointer[api.TaskDefinitionStatus](row.Status), Cpu: stringPointer[api.String](row.Cpu), Memory: stringPointer[api.String](row.Memory),
		NetworkMode: stringPointer[api.NetworkMode](row.NetworkMode), IpcMode: stringPointer[api.IpcMode](row.IpcMode), PidMode: stringPointer[api.PidMode](row.PidMode),
		ExecutionRoleArn: stringPointer[api.String](row.ExecutionRoleArn), TaskRoleArn: stringPointer[api.String](row.TaskRoleArn), RegisteredBy: stringPointer[api.String](row.RegisteredBy),
		RegisteredAt: timePointer(row.RegisteredAt), DeregisteredAt: timePointer(row.DeregisteredAt), DeleteRequestedAt: timePointer(row.DeleteRequestedAt),
		EnableFaultInjection: boolPointer[api.BoxedBoolean](row.EnableFaultInjection),
	}}
	d := &out.Data
	if err := unmarshalFields(
		jsonReadField{row.ContainerDefinitions, &d.ContainerDefinitions}, jsonReadField{row.EphemeralStorage, &d.EphemeralStorage},
		jsonReadField{row.InferenceAccelerators, &d.InferenceAccelerators}, jsonReadField{row.PlacementConstraints, &d.PlacementConstraints},
		jsonReadField{row.ProxyConfiguration, &d.ProxyConfiguration}, jsonReadField{row.RequiresAttributes, &d.RequiresAttributes},
		jsonReadField{row.RuntimePlatform, &d.RuntimePlatform}, jsonReadField{row.Volumes, &d.Volumes},
	); err != nil {
		return out, err
	}
	for _, list := range []struct {
		required, present bool
		target            *api.CompatibilityList
	}{
		{false, row.CompatibilitiesPresent, &d.Compatibilities}, {true, row.RequiresCompatibilitiesPresent, &d.RequiresCompatibilities},
	} {
		if !list.present {
			continue
		}
		values, err := r.q.ListTaskDefinitionCompatibilities(r.ctx, sqlcgen.ListTaskDefinitionCompatibilitiesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Family: k.Family, Revision: int64(k.Revision), Required: list.required})
		if err != nil {
			return out, err
		}
		*list.target = make(api.CompatibilityList, len(values))
		for i, value := range values {
			(*list.target)[i] = api.Compatibility(value)
		}
	}
	return out, nil
}
func (w writer) PutTaskDefinition(v domain.TaskDefinitionRecord) error {
	k, d := v.Key, &v.Data
	params := sqlcgen.PutTaskDefinitionParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Family: k.Family, Revision: int64(k.Revision),
		TaskDefinitionArn: nullableString(d.TaskDefinitionArn), TaskFamily: nullableString(d.Family), TaskRevision: nullableInteger(d.Revision),
		Status: nullableString(d.Status), Cpu: nullableString(d.Cpu), Memory: nullableString(d.Memory),
		NetworkMode: nullableString(d.NetworkMode), IpcMode: nullableString(d.IpcMode), PidMode: nullableString(d.PidMode),
		ExecutionRoleArn: nullableString(d.ExecutionRoleArn), TaskRoleArn: nullableString(d.TaskRoleArn), RegisteredBy: nullableString(d.RegisteredBy),
		RegisteredAt: nullableTime(d.RegisteredAt), DeregisteredAt: nullableTime(d.DeregisteredAt), DeleteRequestedAt: nullableTime(d.DeleteRequestedAt),
		EnableFaultInjection: nullableBool(d.EnableFaultInjection), CompatibilitiesPresent: d.Compatibilities != nil, RequiresCompatibilitiesPresent: d.RequiresCompatibilities != nil,
	}
	if err := marshalFields(
		jsonWriteField{&params.ContainerDefinitions, d.ContainerDefinitions}, jsonWriteField{&params.EphemeralStorage, d.EphemeralStorage},
		jsonWriteField{&params.InferenceAccelerators, d.InferenceAccelerators}, jsonWriteField{&params.PlacementConstraints, d.PlacementConstraints},
		jsonWriteField{&params.ProxyConfiguration, d.ProxyConfiguration}, jsonWriteField{&params.RequiresAttributes, d.RequiresAttributes},
		jsonWriteField{&params.RuntimePlatform, d.RuntimePlatform}, jsonWriteField{&params.Volumes, d.Volumes},
	); err != nil {
		return err
	}
	if err := w.q.PutTaskDefinition(w.ctx, params); err != nil {
		return err
	}
	if err := w.q.DeleteTaskDefinitionCompatibilities(w.ctx, sqlcgen.DeleteTaskDefinitionCompatibilitiesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Family: k.Family, Revision: int64(k.Revision)}); err != nil {
		return err
	}
	for _, list := range []struct {
		required bool
		values   api.CompatibilityList
	}{{false, d.Compatibilities}, {true, d.RequiresCompatibilities}} {
		for i, value := range list.values {
			if err := w.q.PutTaskDefinitionCompatibility(w.ctx, sqlcgen.PutTaskDefinitionCompatibilityParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Family: k.Family, Revision: int64(k.Revision), Required: list.required, Position: int64(i), Compatibility: string(value)}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w writer) DeleteTaskDefinition(k domain.TaskDefinitionKey) error {
	if err := w.q.DeleteTaskDefinition(w.ctx, sqlcgen.DeleteTaskDefinitionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Family: k.Family, Revision: int64(k.Revision)}); err != nil {
		return err
	}
	return w.q.DeleteTagSet(w.ctx, sqlcgen.DeleteTagSetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ARN()})
}
func (w writer) NextTaskDefinitionRevision(k domain.FamilyKey) (int32, error) {
	revision, err := w.q.NextTaskDefinitionRevision(w.ctx, sqlcgen.NextTaskDefinitionRevisionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Family: k.Family})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, &awswire.Error{Code: "ClientException", Message: "Task definition revision limit exceeded.", StatusCode: 400}
	}
	if err != nil {
		return 0, err
	}
	return int32(revision), nil
}
