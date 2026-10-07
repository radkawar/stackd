package lambda

import (
	"database/sql"
	"errors"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) capacityProvider(row sqlcgen.LambdaCapacityProvider) (domain.CapacityProviderRecord, error) {
	key := domain.CapacityProviderKey{Scope: domain.Scope{Partition: row.Partition, Account: row.Account, Region: row.Region}, Name: row.Name}
	out := domain.CapacityProviderRecord{Key: key, Generation: row.Generation, State: row.State, StateReason: row.StateReason, OperatorRoleARN: row.OperatorRoleArn, KMSKeyARN: row.KmsKeyArn, Architecture: row.Architecture, ScalingMode: row.ScalingMode, MaxVCPUs: int32(row.MaxVcpus), TargetCPU: row.TargetCpu, LogGroup: row.LogGroup, SystemLogLevel: row.SystemLogLevel, Modified: row.Modified, Tags: map[string]string{}}
	out.Owner = domain.AdditionalOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}
	if row.PropagateExplicit {
		out.PropagateTags = map[string]string{}
	}
	members, err := r.q.ListCapacityProviderMembers(r.ctx, sqlcgen.ListCapacityProviderMembersParams{Partition: key.Partition, Account: key.Account, Region: key.Region, ProviderName: key.Name})
	if err != nil {
		return out, err
	}
	for _, member := range members {
		switch member.Kind {
		case "subnet":
			out.SubnetIDs = append(out.SubnetIDs, member.Value)
		case "security-group":
			out.SecurityGroupIDs = append(out.SecurityGroupIDs, member.Value)
		case "allowed-instance-type":
			out.AllowedInstanceTypes = append(out.AllowedInstanceTypes, member.Value)
		case "excluded-instance-type":
			out.ExcludedInstanceTypes = append(out.ExcludedInstanceTypes, member.Value)
		}
	}
	tags, err := r.q.ListCapacityProviderTags(r.ctx, sqlcgen.ListCapacityProviderTagsParams{Partition: key.Partition, Account: key.Account, Region: key.Region, ProviderName: key.Name})
	if err != nil {
		return out, err
	}
	for _, tag := range tags {
		if tag.Propagated {
			if out.PropagateTags == nil {
				out.PropagateTags = map[string]string{}
			}
			out.PropagateTags[tag.Key] = tag.Value
		} else {
			out.Tags[tag.Key] = tag.Value
		}
	}
	return out, nil
}
func (r reader) CapacityProvider(key domain.CapacityProviderKey) (domain.CapacityProviderRecord, error) {
	row, err := r.q.GetCapacityProvider(r.ctx, sqlcgen.GetCapacityProviderParams{Partition: key.Partition, Account: key.Account, Region: key.Region, Name: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CapacityProviderRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.CapacityProviderRecord{}, err
	}
	return r.capacityProvider(row)
}
func (r reader) CapacityProviders(scope domain.Scope) ([]domain.CapacityProviderRecord, error) {
	rows, err := r.q.ListCapacityProviders(r.ctx, sqlcgen.ListCapacityProvidersParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	return r.capacityProviders(rows)
}
func (r reader) AllCapacityProviders() ([]domain.CapacityProviderRecord, error) {
	rows, err := r.q.ListAllCapacityProviders(r.ctx)
	if err != nil {
		return nil, err
	}
	return r.capacityProviders(rows)
}
func (r reader) capacityProviders(rows []sqlcgen.LambdaCapacityProvider) ([]domain.CapacityProviderRecord, error) {
	out := make([]domain.CapacityProviderRecord, len(rows))
	for i, row := range rows {
		v, err := r.capacityProvider(row)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}
func (w writer) PutCapacityProvider(v domain.CapacityProviderRecord) error {
	k := v.Key
	if err := w.q.PutCapacityProvider(w.ctx, sqlcgen.PutCapacityProviderParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name, Generation: v.Generation, State: v.State, StateReason: v.StateReason, OperatorRoleArn: v.OperatorRoleARN, KmsKeyArn: v.KMSKeyARN, Architecture: v.Architecture, ScalingMode: v.ScalingMode, MaxVcpus: int64(v.MaxVCPUs), TargetCpu: v.TargetCPU, LogGroup: v.LogGroup, SystemLogLevel: v.SystemLogLevel, PropagateExplicit: v.PropagateTags != nil, Modified: v.Modified, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token}); err != nil {
		return err
	}
	if err := w.q.DeleteCapacityProviderMembers(w.ctx, sqlcgen.DeleteCapacityProviderMembersParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ProviderName: k.Name}); err != nil {
		return err
	}
	for kind, members := range map[string][]string{"subnet": v.SubnetIDs, "security-group": v.SecurityGroupIDs, "allowed-instance-type": v.AllowedInstanceTypes, "excluded-instance-type": v.ExcludedInstanceTypes} {
		for position, value := range members {
			if err := w.q.PutCapacityProviderMember(w.ctx, sqlcgen.PutCapacityProviderMemberParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ProviderName: k.Name, Kind: kind, Position: int64(position), Value: value}); err != nil {
				return err
			}
		}
	}
	if err := w.q.DeleteCapacityProviderTags(w.ctx, sqlcgen.DeleteCapacityProviderTagsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ProviderName: k.Name}); err != nil {
		return err
	}
	for propagated, tags := range map[bool]map[string]string{false: v.Tags, true: v.PropagateTags} {
		for key, value := range tags {
			if err := w.q.PutCapacityProviderTag(w.ctx, sqlcgen.PutCapacityProviderTagParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ProviderName: k.Name, Propagated: propagated, Key: key, Value: value}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w writer) DeleteCapacityProvider(k domain.CapacityProviderKey) error {
	return w.q.DeleteCapacityProvider(w.ctx, sqlcgen.DeleteCapacityProviderParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
}
func (r reader) functionCapacityConfig(k domain.FunctionKey, pending bool, version uint64) (*domain.CapacityFunctionConfig, error) {
	row, err := r.q.GetFunctionCapacityConfig(r.ctx, sqlcgen.GetFunctionCapacityConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(version)})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &domain.CapacityFunctionConfig{ProviderARN: row.ProviderArn, MemoryGiBPerVCPU: row.MemoryGibPerVcpu, MaxConcurrency: int(row.MaxConcurrency)}, nil
}
func (w writer) putFunctionCapacityConfig(v domain.FunctionRecord, pending bool) error {
	k := v.Key
	if v.Capacity == nil {
		return w.q.DeleteFunctionCapacityConfig(w.ctx, sqlcgen.DeleteFunctionCapacityConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version)})
	}
	return w.q.PutFunctionCapacityConfig(w.ctx, sqlcgen.PutFunctionCapacityConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version), ProviderArn: v.Capacity.ProviderARN, MemoryGibPerVcpu: v.Capacity.MemoryGiBPerVCPU, MaxConcurrency: int64(v.Capacity.MaxConcurrency)})
}
func capacityScalingRecord(v sqlcgen.LambdaCapacityScaling) domain.CapacityScalingRecord {
	return domain.CapacityScalingRecord{Key: domain.FunctionReference{FunctionKey: domain.FunctionKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.FunctionName}, Qualifier: v.Qualifier}, Generation: v.Generation, MinEnvironments: int32(v.MinEnvironments), MaxEnvironments: int32(v.MaxEnvironments), AppliedMin: int32(v.AppliedMin), AppliedMax: int32(v.AppliedMax), Modified: v.Modified}
}
func (r reader) CapacityScaling(k domain.FunctionReference) (domain.CapacityScalingRecord, error) {
	v, err := r.q.GetCapacityScaling(r.ctx, sqlcgen.GetCapacityScalingParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CapacityScalingRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.CapacityScalingRecord{}, err
	}
	return capacityScalingRecord(v), nil
}
func (r reader) CapacityScalings(k domain.FunctionKey) ([]domain.CapacityScalingRecord, error) {
	rows, err := r.q.ListCapacityScalings(r.ctx, sqlcgen.ListCapacityScalingsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.CapacityScalingRecord, len(rows))
	for i, row := range rows {
		out[i] = capacityScalingRecord(row)
	}
	return out, nil
}
func (w writer) PutCapacityScaling(v domain.CapacityScalingRecord) error {
	k := v.Key
	return w.q.PutCapacityScaling(w.ctx, sqlcgen.PutCapacityScalingParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier, Generation: v.Generation, MinEnvironments: int64(v.MinEnvironments), MaxEnvironments: int64(v.MaxEnvironments), AppliedMin: int64(v.AppliedMin), AppliedMax: int64(v.AppliedMax), Modified: v.Modified})
}
func (w writer) DeleteCapacityScaling(k domain.FunctionReference) error {
	return w.q.DeleteCapacityScaling(w.ctx, sqlcgen.DeleteCapacityScalingParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier})
}
func capacityGuestRecord(v sqlcgen.LambdaCapacityGuest) domain.CapacityGuestRecord {
	return domain.CapacityGuestRecord{Provider: domain.CapacityProviderKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.ProviderName}, ID: v.ID, Generation: v.Generation, InstanceID: v.InstanceID, SubnetID: v.SubnetID, InstanceType: v.InstanceType, Endpoint: v.Endpoint, AgentToken: v.AgentToken, AgentCertificate: v.AgentCertificate, AgentPrivateKey: v.AgentPrivateKey, CommandID: v.CommandID, State: v.State, Error: v.Error, VCPUs: int32(v.Vcpus), MemoryMB: int32(v.MemoryMb), Modified: v.Modified}
}
func (r reader) CapacityGuests(k domain.CapacityProviderKey) ([]domain.CapacityGuestRecord, error) {
	rows, err := r.q.ListCapacityGuests(r.ctx, sqlcgen.ListCapacityGuestsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ProviderName: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.CapacityGuestRecord, len(rows))
	for i, row := range rows {
		out[i] = capacityGuestRecord(row)
	}
	return out, nil
}
func (w writer) PutCapacityGuest(v domain.CapacityGuestRecord) error {
	k := v.Provider
	return w.q.PutCapacityGuest(w.ctx, sqlcgen.PutCapacityGuestParams{ID: v.ID, Partition: k.Partition, Account: k.Account, Region: k.Region, ProviderName: k.Name, Generation: v.Generation, InstanceID: v.InstanceID, SubnetID: v.SubnetID, InstanceType: v.InstanceType, Endpoint: v.Endpoint, AgentToken: v.AgentToken, AgentCertificate: v.AgentCertificate, AgentPrivateKey: v.AgentPrivateKey, CommandID: v.CommandID, State: v.State, Error: v.Error, Vcpus: int64(v.VCPUs), MemoryMb: int64(v.MemoryMB), Modified: v.Modified})
}
func (w writer) DeleteCapacityGuest(k domain.CapacityProviderKey, id string) error {
	return w.q.DeleteCapacityGuest(w.ctx, sqlcgen.DeleteCapacityGuestParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ProviderName: k.Name, ID: id})
}
func capacityEnvironmentRecord(v sqlcgen.LambdaCapacityEnvironment) domain.CapacityEnvironmentRecord {
	return domain.CapacityEnvironmentRecord{Key: domain.FunctionVersionKey{FunctionKey: domain.FunctionKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.FunctionName}, Version: uint64(v.Version)}, ID: v.ID, Generation: v.Generation, GuestID: v.GuestID, State: v.State, Error: v.Error, CredentialsExpire: v.CredentialsExpire, Modified: v.Modified}
}
func capacityEnvironmentRecords(rows []sqlcgen.LambdaCapacityEnvironment) []domain.CapacityEnvironmentRecord {
	out := make([]domain.CapacityEnvironmentRecord, len(rows))
	for i, row := range rows {
		out[i] = capacityEnvironmentRecord(row)
	}
	return out
}
func (r reader) CapacityEnvironments(k domain.FunctionVersionKey) ([]domain.CapacityEnvironmentRecord, error) {
	rows, err := r.q.ListCapacityEnvironments(r.ctx, sqlcgen.ListCapacityEnvironmentsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Version: int64(k.Version)})
	if err != nil {
		return nil, err
	}
	return capacityEnvironmentRecords(rows), nil
}
func (r reader) AllCapacityEnvironments() ([]domain.CapacityEnvironmentRecord, error) {
	rows, err := r.q.ListAllCapacityEnvironments(r.ctx)
	if err != nil {
		return nil, err
	}
	return capacityEnvironmentRecords(rows), nil
}
func (w writer) PutCapacityEnvironment(v domain.CapacityEnvironmentRecord) error {
	k := v.Key
	return w.q.PutCapacityEnvironment(w.ctx, sqlcgen.PutCapacityEnvironmentParams{ID: v.ID, Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Version: int64(k.Version), Generation: v.Generation, GuestID: v.GuestID, State: v.State, Error: v.Error, CredentialsExpire: v.CredentialsExpire, Modified: v.Modified})
}
func (w writer) DeleteCapacityEnvironment(id string) error {
	return w.q.DeleteCapacityEnvironment(w.ctx, id)
}
func (w writer) SetCapacityDeploymentState(v domain.FunctionRecord) error {
	k := v.Key
	return w.q.SetCapacityDeploymentState(w.ctx, sqlcgen.SetCapacityDeploymentStateParams{State: v.State, StateReason: v.StateReason, StateReasonCode: v.StateReasonCode, Revision: v.Revision, Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name, Version: int64(v.Version), DeploymentRevision: v.DeploymentRevision})
}
