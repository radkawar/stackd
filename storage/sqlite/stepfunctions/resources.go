package stepfunctions

import (
	"database/sql"
	"errors"

	domain "stackd/internal/services/stepfunctions"
	"stackd/storage/sqlite/stepfunctions/internal/sqlcgen"
)

func machineRecord(row sqlcgen.StepfunctionsMachine) domain.MachineRecord {
	return domain.MachineRecord{
		Key: domain.MachineKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name},
		ID:  row.ID, RevisionID: row.RevisionID, Type: row.Type, Status: row.Status, Created: row.Created,
		Version: row.Version, DeleteAt: timePointer(row.DeleteAt), NextVersion: row.NextVersion, Tags: map[string]string{},
		FirstVersionDescription: row.FirstVersionDescription,
	}
}

func (r reader) machine(row sqlcgen.StepfunctionsMachine) (domain.MachineRecord, error) {
	v := machineRecord(row)
	tags, err := r.q.ListMachineTags(r.ctx, sqlcgen.ListMachineTagsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, MachineName: row.Name})
	if err != nil {
		return domain.MachineRecord{}, err
	}
	for _, tag := range tags {
		v.Tags[tag.Key] = tag.Value
	}
	return v, nil
}

func (r reader) Machine(k domain.MachineKey) (domain.MachineRecord, error) {
	row, err := r.q.GetMachine(r.ctx, sqlcgen.GetMachineParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.MachineRecord{}, missing(err)
	}
	return r.machine(row)
}

func (r reader) Machines(k domain.Scope) ([]domain.MachineRecord, error) {
	rows, err := r.q.ListMachines(r.ctx, sqlcgen.ListMachinesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MachineRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.machine(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) MachineCount(k domain.Scope) (int64, error) {
	return r.q.CountMachines(r.ctx, sqlcgen.CountMachinesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
}

func (w writer) PutMachine(v domain.MachineRecord) error {
	k := v.Key
	old, err := w.q.GetMachine(w.ctx, sqlcgen.GetMachineParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	displaced := []string{}
	if err == nil {
		displaced = append(displaced, old.RevisionID)
		if old.ID != v.ID {
			versions, err := w.q.ListVersions(w.ctx, sqlcgen.ListVersionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineName: k.Name, MachineID: old.ID})
			if err != nil {
				return err
			}
			for _, version := range versions {
				displaced = append(displaced, version.RevisionID)
			}
			if _, err := w.q.DeleteMachine(w.ctx, sqlcgen.DeleteMachineParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
				return err
			}
		}
	}
	if err := w.q.PutMachine(w.ctx, sqlcgen.PutMachineParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ID: v.ID, RevisionID: v.RevisionID,
		Type: v.Type, Status: v.Status, Created: v.Created.UTC(), Version: v.Version, DeleteAt: nullableTime(v.DeleteAt), NextVersion: v.NextVersion,
		FirstVersionDescription: v.FirstVersionDescription,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteMachineTags(w.ctx, sqlcgen.DeleteMachineTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineName: k.Name}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutMachineTag(w.ctx, sqlcgen.PutMachineTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineName: k.Name, Key: key, Value: value}); err != nil {
			return err
		}
	}
	for _, id := range displaced {
		if err := w.reclaim(k.Scope, id); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteMachine(k domain.MachineKey) error {
	row, err := w.q.GetMachine(w.ctx, sqlcgen.GetMachineParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return missing(err)
	}
	versions, err := w.q.ListVersions(w.ctx, sqlcgen.ListVersionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineName: k.Name, MachineID: row.ID})
	if err != nil {
		return err
	}
	if err := deleted(w.q.DeleteMachine(w.ctx, sqlcgen.DeleteMachineParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})); err != nil {
		return err
	}
	if err := w.reclaim(k.Scope, row.RevisionID); err != nil {
		return err
	}
	for _, version := range versions {
		if err := w.reclaim(k.Scope, version.RevisionID); err != nil {
			return err
		}
	}
	return nil
}

func revisionRecord(row sqlcgen.StepfunctionsRevision) domain.RevisionRecord {
	scope := domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}
	return domain.RevisionRecord{
		Key: domain.RevisionKey{Scope: scope, ID: row.ID}, Machine: domain.MachineKey{Scope: scope, Name: row.MachineName},
		MachineID: row.MachineID, Created: row.Created, Definition: row.Definition, RoleARN: row.RoleArn, LogGroupARN: row.LogGroupArn,
		Initial: row.Initial, LogLevel: row.LogLevel, IncludeExecutionData: row.IncludeExecutionData, TracingEnabled: row.TracingEnabled,
		EncryptionConfig:   domain.EncryptionConfig{EncryptionType: row.EncryptionType, KMSKeyARN: row.KmsKeyArn, DataKeyReuseSeconds: row.DataKeyReuseSeconds},
		Encrypted:          encryptedPayload(row.EncryptedDataKey, row.EncryptedContent),
		DefinitionIdentity: row.DefinitionIdentity, NeedsNestedSync: row.NeedsNestedSync, NeedsECSSync: row.NeedsEcsSync,
	}
}

func (r reader) Revision(k domain.RevisionKey) (domain.RevisionRecord, error) {
	row, err := r.q.GetRevision(r.ctx, sqlcgen.GetRevisionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID})
	if err != nil {
		return domain.RevisionRecord{}, missing(err)
	}
	return revisionRecord(row), nil
}

func (w writer) PutRevision(v domain.RevisionRecord) error {
	k := v.Key
	dataKey, content := encryptedColumns(v.Encrypted)
	return w.q.PutRevision(w.ctx, sqlcgen.PutRevisionParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID, MachineName: v.Machine.Name,
		MachineID: v.MachineID, Created: v.Created.UTC(), Definition: v.Definition, RoleArn: v.RoleARN, LogGroupArn: v.LogGroupARN,
		Initial: v.Initial, LogLevel: v.LogLevel, IncludeExecutionData: v.IncludeExecutionData, TracingEnabled: v.TracingEnabled,
		EncryptionType: v.EncryptionType, KmsKeyArn: v.KMSKeyARN, DataKeyReuseSeconds: v.DataKeyReuseSeconds,
		EncryptedDataKey: dataKey, EncryptedContent: content,
		DefinitionIdentity: v.DefinitionIdentity, NeedsNestedSync: v.NeedsNestedSync, NeedsEcsSync: v.NeedsECSSync,
	})
}

func versionRecord(row sqlcgen.StepfunctionsVersion) domain.VersionRecord {
	return domain.VersionRecord{
		Key:        domain.VersionKey{Machine: domain.MachineKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.MachineName}, MachineID: row.MachineID, Number: row.Number},
		RevisionID: row.RevisionID, Created: row.Created, Description: row.Description,
	}
}

func (r reader) Version(k domain.VersionKey) (domain.VersionRecord, error) {
	m := k.Machine
	row, err := r.q.GetVersion(r.ctx, sqlcgen.GetVersionParams{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region, MachineName: m.Name, MachineID: k.MachineID, Number: k.Number})
	if err != nil {
		return domain.VersionRecord{}, missing(err)
	}
	return versionRecord(row), nil
}

func (r reader) Versions(k domain.MachineKey, machineID string) ([]domain.VersionRecord, error) {
	rows, err := r.q.ListVersions(r.ctx, sqlcgen.ListVersionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineName: k.Name, MachineID: machineID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.VersionRecord, len(rows))
	for i, row := range rows {
		out[i] = versionRecord(row)
	}
	return out, nil
}

func (w writer) PutVersion(v domain.VersionRecord) error {
	k := v.Key.Machine
	old, err := w.q.GetVersion(w.ctx, sqlcgen.GetVersionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineName: k.Name, MachineID: v.Key.MachineID, Number: v.Key.Number})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	hadOld := err == nil
	if err := w.q.PutVersion(w.ctx, sqlcgen.PutVersionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineName: k.Name, MachineID: v.Key.MachineID, Number: v.Key.Number, RevisionID: v.RevisionID, Created: v.Created.UTC(), Description: v.Description}); err != nil {
		return err
	}
	if hadOld && old.RevisionID != v.RevisionID {
		return w.reclaim(k.Scope, old.RevisionID)
	}
	return nil
}

func (w writer) DeleteVersion(k domain.VersionKey) error {
	old, err := w.Version(k)
	if err != nil {
		return err
	}
	m := k.Machine
	if err := deleted(w.q.DeleteVersion(w.ctx, sqlcgen.DeleteVersionParams{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region, MachineName: m.Name, MachineID: k.MachineID, Number: k.Number})); err != nil {
		return err
	}
	return w.reclaim(m.Scope, old.RevisionID)
}

func (r reader) alias(row sqlcgen.StepfunctionsAlias) (domain.AliasRecord, error) {
	v := domain.AliasRecord{
		Key:         domain.AliasKey{Machine: domain.MachineKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.MachineName}, MachineID: row.MachineID, Name: row.Name},
		Description: row.Description, Created: row.Created, Updated: row.Updated, Routes: []domain.AliasRoute{},
	}
	rows, err := r.q.ListAliasRoutes(r.ctx, sqlcgen.ListAliasRoutesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, MachineName: row.MachineName, MachineID: row.MachineID, AliasName: row.Name})
	if err != nil {
		return domain.AliasRecord{}, err
	}
	for _, route := range rows {
		v.Routes = append(v.Routes, domain.AliasRoute{Version: route.Version, Weight: int32(route.Weight)})
	}
	return v, nil
}

func (r reader) Alias(k domain.AliasKey) (domain.AliasRecord, error) {
	m := k.Machine
	row, err := r.q.GetAlias(r.ctx, sqlcgen.GetAliasParams{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region, MachineName: m.Name, MachineID: k.MachineID, Name: k.Name})
	if err != nil {
		return domain.AliasRecord{}, missing(err)
	}
	return r.alias(row)
}

func (r reader) Aliases(k domain.MachineKey, machineID string) ([]domain.AliasRecord, error) {
	rows, err := r.q.ListAliases(r.ctx, sqlcgen.ListAliasesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineName: k.Name, MachineID: machineID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.AliasRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.alias(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (w writer) PutAlias(v domain.AliasRecord) error {
	k := v.Key.Machine
	if err := w.q.PutAlias(w.ctx, sqlcgen.PutAliasParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineName: k.Name, MachineID: v.Key.MachineID, Name: v.Key.Name, Description: v.Description, Created: v.Created.UTC(), Updated: v.Updated.UTC()}); err != nil {
		return err
	}
	if err := w.q.DeleteAliasRoutes(w.ctx, sqlcgen.DeleteAliasRoutesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineName: k.Name, MachineID: v.Key.MachineID, AliasName: v.Key.Name}); err != nil {
		return err
	}
	for i, route := range v.Routes {
		if err := w.q.PutAliasRoute(w.ctx, sqlcgen.PutAliasRouteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineName: k.Name, MachineID: v.Key.MachineID, AliasName: v.Key.Name, Position: int64(i), Version: route.Version, Weight: int64(route.Weight)}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteAlias(k domain.AliasKey) error {
	m := k.Machine
	return deleted(w.q.DeleteAlias(w.ctx, sqlcgen.DeleteAliasParams{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region, MachineName: m.Name, MachineID: k.MachineID, Name: k.Name}))
}

func (r reader) activity(row sqlcgen.StepfunctionsActivity) (domain.ActivityRecord, error) {
	v := domain.ActivityRecord{
		Key: domain.ActivityKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name},
		ID:  row.ID, Created: row.Created, Tags: map[string]string{},
		EncryptionConfig: domain.EncryptionConfig{EncryptionType: row.EncryptionType, KMSKeyARN: row.KmsKeyArn, DataKeyReuseSeconds: row.DataKeyReuseSeconds},
	}
	tags, err := r.q.ListActivityTags(r.ctx, sqlcgen.ListActivityTagsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ActivityName: row.Name})
	if err != nil {
		return domain.ActivityRecord{}, err
	}
	for _, tag := range tags {
		v.Tags[tag.Key] = tag.Value
	}
	return v, nil
}

func (r reader) Activity(k domain.ActivityKey) (domain.ActivityRecord, error) {
	row, err := r.q.GetActivity(r.ctx, sqlcgen.GetActivityParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.ActivityRecord{}, missing(err)
	}
	return r.activity(row)
}

func (r reader) Activities(k domain.Scope) ([]domain.ActivityRecord, error) {
	rows, err := r.q.ListActivities(r.ctx, sqlcgen.ListActivitiesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ActivityRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.activity(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) ActivityCount(k domain.Scope) (int64, error) {
	return r.q.CountActivities(r.ctx, sqlcgen.CountActivitiesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
}

func (w writer) PutActivity(v domain.ActivityRecord) error {
	k := v.Key
	if err := w.q.PutActivity(w.ctx, sqlcgen.PutActivityParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ID: v.ID, Created: v.Created.UTC(),
		EncryptionType: v.EncryptionType, KmsKeyArn: v.KMSKeyARN, DataKeyReuseSeconds: v.DataKeyReuseSeconds,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteActivityTags(w.ctx, sqlcgen.DeleteActivityTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ActivityName: k.Name}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutActivityTag(w.ctx, sqlcgen.PutActivityTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ActivityName: k.Name, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteActivity(k domain.ActivityKey) error {
	return deleted(w.q.DeleteActivity(w.ctx, sqlcgen.DeleteActivityParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}))
}
