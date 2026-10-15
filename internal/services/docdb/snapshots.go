package docdb

import (
	"context"
	"errors"
	engine "stackd/engine/docdb"
	api "stackd/internal/awsapi/docdb"
	"time"
)

func (s *Service) createSnapshot(ctx context.Context, tx Transaction, in *api.CreateDBClusterSnapshotInput) (*api.CreateDBClusterSnapshotOutput, error) {
	v, e := s.loadCluster(ctx, tx, "CreateDBClusterSnapshot", value(in.DBClusterIdentifier))
	if e != nil {
		return nil, e
	}
	if v.Operation != "" || v.Status != "available" && v.Status != "creating" {
		return nil, stateError("cluster")
	}
	k, e := resourceKey(ctx, "cluster-snapshot", value(in.DBClusterSnapshotIdentifier))
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateDBClusterSnapshot", k, nil, tags); e != nil {
		return nil, e
	}
	if e = s.checkName(ctx, k); e != nil {
		return nil, e
	}
	if _, e = tx.Snapshot(k); e == nil {
		return nil, duplicate(k.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	snap, e := s.captureSnapshot(ctx, tx, v, k, tags, false)
	if e != nil {
		return nil, e
	}
	return &api.CreateDBClusterSnapshotOutput{DBClusterSnapshot: snapshotOutput(snap)}, nil
}

// captureSnapshot commits ownership before the external cold snapshot effect.
func (s *Service) captureSnapshot(ctx context.Context, tx Transaction, v Cluster, k Key, tags map[string]string, automated bool) (Snapshot, error) {
	id, e := incarnation()
	if e != nil {
		return Snapshot{}, e
	}
	user, password, e := s.cipher.Open(ctx, v.Key.ARN(), v.Ciphertext)
	if e != nil {
		return Snapshot{}, e
	}
	cipher, e := s.cipher.Seal(ctx, k.ARN(), user, password)
	if e != nil {
		return Snapshot{}, e
	}
	snap := Snapshot{Key: k, Source: v.Key.Name, SourceRuntimeID: v.RuntimeID, RuntimeID: id, Username: v.Username, EngineVersion: v.EngineVersion, Status: "creating", Operation: "create", Ciphertext: cipher, Version: 1, Created: s.clock.Now(), Due: s.clock.Now(), Tags: tags, Automated: automated}
	if automated {
		snap.Expires = snap.Created.Add(time.Duration(v.BackupRetention) * 24 * time.Hour)
	} else {
		snap.Owner = cloudFormationClaim(ctx, k)
	}
	v.Status = "backing-up"
	v.Endpoint = engine.Endpoint{}
	v.Version++
	v.Due = zeroTime
	if e = tx.PutCluster(v); e != nil {
		return Snapshot{}, e
	}
	if e = s.mirrorMembers(tx, v); e != nil {
		return Snapshot{}, e
	}
	return snap, tx.PutSnapshot(snap)
}
func (s *Service) deleteSnapshot(ctx context.Context, tx Transaction, in *api.DeleteDBClusterSnapshotInput) (*api.DeleteDBClusterSnapshotOutput, error) {
	v, e := s.loadSnapshot(ctx, tx, "DeleteDBClusterSnapshot", value(in.DBClusterSnapshotIdentifier))
	if e != nil {
		return nil, e
	}
	if v.Automated {
		return nil, failure("InvalidDBClusterSnapshotStateFault", "Automated snapshots are retired by the backup retention owner.")
	}
	if v.Status != "available" && v.Status != "failed" {
		return nil, stateError(v.Key.Kind)
	}
	all, e := tx.Clusters()
	if e != nil {
		return nil, e
	}
	for _, c := range all {
		if c.RestoreSnapshot == v.RuntimeID {
			return nil, stateError(v.Key.Kind)
		}
	}
	v.Status = "deleting"
	v.Operation = "delete"
	v.Version++
	v.Due = s.clock.Now()
	if e = tx.PutSnapshot(v); e != nil {
		return nil, e
	}
	return &api.DeleteDBClusterSnapshotOutput{DBClusterSnapshot: snapshotOutput(v)}, nil
}
func (s *Service) restoreCluster(ctx context.Context, tx Transaction, in *api.RestoreDBClusterFromSnapshotInput) (*api.RestoreDBClusterFromSnapshotOutput, error) {
	if e := s.ensureRuntime(); e != nil {
		return nil, e
	}
	if value(in.Engine) != "docdb" || in.EngineVersion != nil && value(in.EngineVersion) != "5.0" {
		return nil, unsupported("Only DocumentDB 5.0 compatibility is supported.")
	}
	if len(in.AvailabilityZones) > 0 || in.DBClusterParameterGroupName != nil || in.DBSubnetGroupName != nil || len(in.EnableCloudwatchLogsExports) > 0 || in.KmsKeyId != nil || in.NetworkType != nil || in.ServerlessV2ScalingConfiguration != nil || in.StorageType != nil || len(in.VpcSecurityGroupIds) > 0 {
		return nil, unsupported("Managed storage, networking, parameters and scaling are not implemented.")
	}
	snap, e := s.loadSnapshot(ctx, tx, "RestoreDBClusterFromSnapshot", value(in.SnapshotIdentifier))
	if e != nil {
		return nil, e
	}
	if snap.Status != "available" {
		return nil, stateError(snap.Key.Kind)
	}
	k, e := resourceKey(ctx, "cluster", value(in.DBClusterIdentifier))
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "RestoreDBClusterFromSnapshot", k, nil, tags); e != nil {
		return nil, e
	}
	if e = s.checkName(ctx, k); e != nil {
		return nil, e
	}
	if _, e = tx.Cluster(k); e == nil {
		return nil, duplicate(k.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	port := int32(0)
	if in.Port != nil {
		port = int32(*in.Port)
		if port < 1150 || port > 65535 {
			return nil, failure("InvalidParameterValue", "Port must be between 1150 and 65535.")
		}
	}
	id, e := incarnation()
	if e != nil {
		return nil, e
	}
	user, password, e := s.cipher.Open(ctx, snap.Key.ARN(), snap.Ciphertext)
	if e != nil {
		return nil, e
	}
	cipher, e := s.cipher.Seal(ctx, k.ARN(), user, password)
	if e != nil {
		return nil, e
	}
	v := Cluster{Key: k, RuntimeID: id, Username: user, EngineVersion: snap.EngineVersion, Status: "available", RestoreSnapshot: snap.RuntimeID, Ciphertext: cipher, RequestedPort: port, Version: 1, Created: s.clock.Now(), DeletionProtection: yes(in.DeletionProtection), Tags: tags, BackupRetention: 1, BackupWindow: defaultBackupWindow, NextBackup: nextBackup(s.clock.Now(), defaultBackupWindow)}
	v.Owner = cloudFormationClaim(ctx, k)
	if e = tx.PutCluster(v); e != nil {
		return nil, e
	}
	out, e := clusterOutput(tx, v)
	return &api.RestoreDBClusterFromSnapshotOutput{DBCluster: out}, e
}
func snapshotOutput(v Snapshot) *api.DBClusterSnapshot {
	kind := "manual"
	if v.Automated {
		kind = "automated"
	}
	progress := api.Integer(0)
	if v.Status == "available" {
		progress = 100
	}
	return &api.DBClusterSnapshot{DBClusterSnapshotArn: new(api.String(v.Key.ARN())), DBClusterSnapshotIdentifier: new(api.String(v.Key.Name)), DBClusterIdentifier: new(api.String(v.Source)), Engine: new(api.String("docdb")), EngineVersion: new(api.String(v.EngineVersion)), MasterUsername: new(api.String(v.Username)), Status: new(api.String(v.Status)), SnapshotCreateTime: new(api.TStamp(v.Created)), SnapshotType: new(api.String(kind)), PercentProgress: &progress, StorageEncrypted: new(api.Boolean(false))}
}
