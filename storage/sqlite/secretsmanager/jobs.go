package secretsmanager

import (
	domain "stackd/storage/secretsmanager"
	"stackd/storage/sqlite/secretsmanager/internal/sqlcgen"
)

func replica(v sqlcgen.SecretsmanagerReplica) domain.ReplicaRecord {
	return domain.ReplicaRecord{
		Key: domain.ReplicaKey{
			Primary: domain.SecretKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.SecretName},
			Region:  v.ReplicaRegion,
		},
		PrimaryARN: v.PrimaryArn, KMSKeyID: v.KmsKeyID, Status: v.Status, StatusMessage: v.StatusMessage,
		Due: timePointer(v.Due),
	}
}

func (r reader) Replica(k domain.ReplicaKey) (domain.ReplicaRecord, error) {
	v, err := r.q.GetReplica(r.ctx, sqlcgen.GetReplicaParams{Partition: k.Primary.Partition, AccountID: k.Primary.AccountID, Region: k.Primary.Region, SecretName: k.Primary.Name, ReplicaRegion: k.Region})
	if err != nil {
		return domain.ReplicaRecord{}, missing(err)
	}
	return replica(v), nil
}

func (r reader) Replicas(k domain.SecretKey) ([]domain.ReplicaRecord, error) {
	rows, err := r.q.ListReplicas(r.ctx, sqlcgen.ListReplicasParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SecretName: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ReplicaRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, replica(row))
	}
	return out, nil
}

func (r reader) NextReplica() (domain.ReplicaRecord, error) {
	v, err := r.q.NextReplica(r.ctx)
	if err != nil {
		return domain.ReplicaRecord{}, missing(err)
	}
	return replica(v), nil
}

func (w writer) PutReplica(v domain.ReplicaRecord) error {
	k := v.Key
	return w.q.PutReplica(w.ctx, sqlcgen.PutReplicaParams{
		Partition: k.Primary.Partition, AccountID: k.Primary.AccountID, Region: k.Primary.Region, SecretName: k.Primary.Name, ReplicaRegion: k.Region,
		PrimaryArn: v.PrimaryARN, KmsKeyID: v.KMSKeyID, Status: v.Status, StatusMessage: v.StatusMessage,
		Due: nullableTime(v.Due),
	})
}

func (w writer) DeleteReplica(k domain.ReplicaKey) error {
	return w.q.DeleteReplica(w.ctx, sqlcgen.DeleteReplicaParams{Partition: k.Primary.Partition, AccountID: k.Primary.AccountID, Region: k.Primary.Region, SecretName: k.Primary.Name, ReplicaRegion: k.Region})
}

func rotation(v sqlcgen.SecretsmanagerRotation) domain.RotationRecord {
	return domain.RotationRecord{
		Secret: domain.SecretKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.SecretName},
		ARN:    v.Arn, Token: v.Token, InvocationToken: v.InvocationToken,
		Step: int(v.Step), Attempt: int(v.Attempt), TestOnly: v.TestOnly,
		Due: v.Due, Deadline: v.Deadline, LastError: v.LastError,
	}
}

func (r reader) Rotation(k domain.SecretKey) (domain.RotationRecord, error) {
	v, err := r.q.GetRotation(r.ctx, sqlcgen.GetRotationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SecretName: k.Name})
	if err != nil {
		return domain.RotationRecord{}, missing(err)
	}
	return rotation(v), nil
}

func (r reader) NextRotationWork() (domain.RotationRecord, error) {
	v, err := r.q.NextRotationWork(r.ctx)
	if err != nil {
		return domain.RotationRecord{}, missing(err)
	}
	return rotation(v), nil
}

func (w writer) PutRotation(v domain.RotationRecord) error {
	k := v.Secret
	return w.q.PutRotation(w.ctx, sqlcgen.PutRotationParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SecretName: k.Name,
		Arn: v.ARN, Token: v.Token, InvocationToken: v.InvocationToken,
		Step: int64(v.Step), Attempt: int64(v.Attempt), TestOnly: v.TestOnly,
		Due: v.Due.UTC(), Deadline: v.Deadline.UTC(), LastError: v.LastError,
	})
}

func (w writer) DeleteRotation(k domain.SecretKey) error {
	return w.q.DeleteRotation(w.ctx, sqlcgen.DeleteRotationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SecretName: k.Name})
}
