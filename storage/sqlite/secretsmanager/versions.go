package secretsmanager

import (
	domain "stackd/storage/secretsmanager"
	"stackd/storage/sqlite/secretsmanager/internal/sqlcgen"
)

func (r reader) version(v sqlcgen.SecretsmanagerVersion) (domain.VersionRecord, error) {
	out := domain.VersionRecord{
		Key: domain.VersionKey{
			Secret: domain.SecretKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.SecretName},
			ID:     v.ID,
		},
		Binary: v.Binary, Created: v.Created, LastAccessed: timePointer(v.LastAccessed),
	}
	if v.StagesPresent {
		stages, err := r.q.ListVersionStages(r.ctx, sqlcgen.ListVersionStagesParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, SecretName: v.SecretName, VersionID: v.ID})
		if err != nil {
			return domain.VersionRecord{}, err
		}
		out.Stages = stages
	}
	return out, nil
}

func (r reader) Version(k domain.VersionKey) (domain.VersionRecord, error) {
	v, err := r.q.GetVersion(r.ctx, sqlcgen.GetVersionParams{Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, ID: k.ID})
	if err != nil {
		return domain.VersionRecord{}, missing(err)
	}
	return r.version(v)
}

func (r reader) Versions(k domain.SecretKey) ([]domain.VersionRecord, error) {
	rows, err := r.q.ListVersions(r.ctx, sqlcgen.ListVersionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SecretName: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.VersionRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.version(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (w writer) PutVersion(v domain.VersionRecord) error {
	k := v.Key
	if err := w.q.PutVersion(w.ctx, sqlcgen.PutVersionParams{
		Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, ID: k.ID,
		Binary: v.Binary, StagesPresent: v.Stages != nil, Created: v.Created.UTC(), LastAccessed: nullableTime(v.LastAccessed),
	}); err != nil {
		return err
	}
	if err := w.q.DeleteVersionStages(w.ctx, sqlcgen.DeleteVersionStagesParams{Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, VersionID: k.ID}); err != nil {
		return err
	}
	for position, stage := range v.Stages {
		if err := w.q.PutVersionStage(w.ctx, sqlcgen.PutVersionStageParams{
			Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, VersionID: k.ID,
			Position: int64(position), Stage: stage,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteVersion(k domain.VersionKey) error {
	return w.q.DeleteVersion(w.ctx, sqlcgen.DeleteVersionParams{Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, ID: k.ID})
}

func (r reader) EncryptedVersion(k domain.VersionKey) ([]domain.SealedValue, error) {
	present, err := r.q.GetEncryptedVersion(r.ctx, sqlcgen.GetEncryptedVersionParams{Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, VersionID: k.ID})
	if err != nil {
		return nil, missing(err)
	}
	if !present {
		return nil, nil
	}
	rows, err := r.q.ListSealedValues(r.ctx, sqlcgen.ListSealedValuesParams{Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, VersionID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SealedValue, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.SealedValue{KeyID: row.KeyID, WrappedKey: row.WrappedKey, Payload: row.Payload})
	}
	return out, nil
}

func (r reader) VersionKeyIDs(k domain.VersionKey) ([]string, error) {
	present, err := r.q.GetEncryptedVersion(r.ctx, sqlcgen.GetEncryptedVersionParams{Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, VersionID: k.ID})
	if err != nil {
		return nil, missing(err)
	}
	if !present {
		return []string{}, nil
	}
	return r.q.ListVersionKeyIDs(r.ctx, sqlcgen.ListVersionKeyIDsParams{Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, VersionID: k.ID})
}

func (w writer) PutEncryptedVersion(k domain.VersionKey, values []domain.SealedValue) error {
	if err := w.q.PutEncryptedVersion(w.ctx, sqlcgen.PutEncryptedVersionParams{
		Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, VersionID: k.ID,
		ValuesPresent: values != nil,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteSealedValues(w.ctx, sqlcgen.DeleteSealedValuesParams{Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, VersionID: k.ID}); err != nil {
		return err
	}
	for position, value := range values {
		if err := w.q.PutSealedValue(w.ctx, sqlcgen.PutSealedValueParams{
			Partition: k.Secret.Partition, AccountID: k.Secret.AccountID, Region: k.Secret.Region, SecretName: k.Secret.Name, VersionID: k.ID,
			Position: int64(position), KeyID: value.KeyID, WrappedKey: value.WrappedKey, Payload: value.Payload,
		}); err != nil {
			return err
		}
	}
	return nil
}
