package rds

import (
	"context"
	"errors"
	"maps"
	"strings"
	"time"

	engine "stackd/engine/rds"
	api "stackd/internal/awsapi/rds"
)

func (s *Service) captureSnapshot(ctx context.Context, tx Transaction, kind, source, name string, tags api.TagList) (Snapshot, error) {
	skind, action := "snapshot", "CreateDBSnapshot"
	if kind == "cluster" {
		skind, action = "cluster-snapshot", "CreateDBClusterSnapshot"
	}
	v, e := s.loadDatabase(ctx, tx, action, kind, source)
	if e != nil {
		return Snapshot{}, e
	}
	if v.Cluster != "" {
		return Snapshot{}, unsupported("Snapshot the cluster, not its writer member.")
	}
	if v.Status != "available" {
		return Snapshot{}, stateError(kind)
	}
	k, e := resourceKey(ctx, skind, name)
	if e != nil {
		return Snapshot{}, e
	}
	if !validName(k.Name, 255) {
		return Snapshot{}, failure("InvalidParameterValue", "Invalid snapshot identifier.")
	}
	if _, e = tx.Snapshot(k); e == nil {
		return Snapshot{}, existsError(skind)
	} else if !errors.Is(e, ErrNotFound) {
		return Snapshot{}, e
	}
	tagged, e := tagsFrom(tags)
	if e != nil {
		return Snapshot{}, e
	}
	if len(tagged) == 0 && v.CopyTags {
		tagged = maps.Clone(v.Tags)
	}
	if e = s.authorize(ctx, action, k, nil, tagged); e != nil {
		return Snapshot{}, e
	}
	id, e := incarnation()
	if e != nil {
		return Snapshot{}, e
	}
	user, password, e := s.cipher.Open(ctx, v.Key.ARN(), v.Ciphertext)
	if e != nil {
		return Snapshot{}, e
	}
	sealed, e := s.cipher.Seal(ctx, k.ARN(), user, password)
	if e != nil {
		return Snapshot{}, e
	}
	snap := Snapshot{Key: k, Source: v.Key.Name, SourceRuntimeID: v.RuntimeID, RuntimeID: id, Engine: v.Engine, EngineVersion: v.EngineVersion, DatabaseName: v.DatabaseName, Username: user, Class: v.Class, Status: "creating", Ciphertext: sealed, Parameters: maps.Clone(v.Parameters), Tags: tagged, Version: 1, Created: s.clock.Now(), Due: s.clock.Now()}
	// Native backup briefly stops the source. Hide its endpoint before that effect,
	// and keep the source blocked until actual restart/authentication succeeds.
	v.Status = "backing-up"
	v.Endpoint = engine.Endpoint{}
	v.Operation = "snapshot"
	v.Version++
	v.Due = time.Time{}
	if e = tx.PutDatabase(v); e != nil {
		return snap, e
	}
	if kind == "cluster" {
		if e = s.mirrorMembers(tx, v); e != nil {
			return snap, e
		}
	}
	if e = tx.PutSnapshot(snap); e != nil {
		return snap, e
	}
	return snap, nil
}

func snapshotDTO(v Snapshot) api.DBSnapshot {
	out := api.DBSnapshot{DBSnapshotIdentifier: new(api.String(v.Key.Name)), DBSnapshotArn: new(api.String(v.Key.ARN())), DBInstanceIdentifier: new(api.String(v.Source)), DbiResourceId: new(api.String("db-" + v.SourceRuntimeID)), Engine: new(api.String(v.Engine)), EngineVersion: new(api.String(v.EngineVersion)), MasterUsername: new(api.String(v.Username)), Status: new(api.String(v.Status)), SnapshotType: new(api.String("manual")), SnapshotCreateTime: new(api.TStamp(v.Created)), Encrypted: new(api.Boolean(false)), TagList: tagList(v.Tags)}
	if v.Status == "available" {
		out.PercentProgress = new(api.Integer(100))
	}
	return out
}

func clusterSnapshotDTO(v Snapshot) api.DBClusterSnapshot {
	out := api.DBClusterSnapshot{DBClusterSnapshotIdentifier: new(api.String(v.Key.Name)), DBClusterSnapshotArn: new(api.String(v.Key.ARN())), DBClusterIdentifier: new(api.String(v.Source)), DbClusterResourceId: new(api.String("cluster-" + v.SourceRuntimeID)), Engine: new(api.String(v.Engine)), EngineVersion: new(api.String(v.EngineVersion)), MasterUsername: new(api.String(v.Username)), Status: new(api.String(v.Status)), SnapshotType: new(api.String("manual")), SnapshotCreateTime: new(api.TStamp(v.Created)), StorageEncrypted: new(api.Boolean(false)), TagList: tagList(v.Tags)}
	if v.Status == "available" {
		out.PercentProgress = new(api.Integer(100))
	}
	return out
}

func (s *Service) createSnapshot(ctx context.Context, tx Transaction, in *api.CreateDBSnapshotMessage) (*api.CreateDBSnapshotResult, error) {
	v, e := s.captureSnapshot(ctx, tx, "db", value(in.DBInstanceIdentifier), value(in.DBSnapshotIdentifier), in.Tags)
	if e != nil {
		return nil, e
	}
	return &api.CreateDBSnapshotResult{DBSnapshot: new(snapshotDTO(v))}, nil
}

func (s *Service) createClusterSnapshot(ctx context.Context, tx Transaction, in *api.CreateDBClusterSnapshotMessage) (*api.CreateDBClusterSnapshotResult, error) {
	v, e := s.captureSnapshot(ctx, tx, "cluster", value(in.DBClusterIdentifier), value(in.DBClusterSnapshotIdentifier), in.Tags)
	if e != nil {
		return nil, e
	}
	return &api.CreateDBClusterSnapshotResult{DBClusterSnapshot: new(clusterSnapshotDTO(v))}, nil
}

func (s *Service) loadSnapshot(ctx context.Context, tx Reader, action, kind, name string) (Snapshot, error) {
	k, e := resourceKey(ctx, kind, name)
	if e != nil {
		return Snapshot{}, e
	}
	v, e := tx.Snapshot(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound(kind)
	}
	if e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}

func (s *Service) removeSnapshot(ctx context.Context, tx Transaction, kind, name string) (Snapshot, error) {
	action := "DeleteDBSnapshot"
	if kind == "cluster-snapshot" {
		action = "DeleteDBClusterSnapshot"
	}
	v, e := s.loadSnapshot(ctx, tx, action, kind, name)
	if e != nil {
		return v, e
	}
	if v.Status != "available" && v.Status != "failed" {
		return v, stateError(kind)
	}
	dbs, e := tx.Databases(v.Key.Scope)
	if e != nil {
		return v, e
	}
	for _, db := range dbs {
		if db.RestoreSnapshot == v.RuntimeID {
			return v, stateError(kind)
		}
	}
	v.Status = "deleting"
	v.Version++
	v.Due = s.clock.Now()
	return v, tx.PutSnapshot(v)
}

func (s *Service) deleteSnapshot(ctx context.Context, tx Transaction, in *api.DeleteDBSnapshotMessage) (*api.DeleteDBSnapshotResult, error) {
	v, e := s.removeSnapshot(ctx, tx, "snapshot", value(in.DBSnapshotIdentifier))
	if e != nil {
		return nil, e
	}
	return &api.DeleteDBSnapshotResult{DBSnapshot: new(snapshotDTO(v))}, nil
}

func (s *Service) deleteClusterSnapshot(ctx context.Context, tx Transaction, in *api.DeleteDBClusterSnapshotMessage) (*api.DeleteDBClusterSnapshotResult, error) {
	v, e := s.removeSnapshot(ctx, tx, "cluster-snapshot", value(in.DBClusterSnapshotIdentifier))
	if e != nil {
		return nil, e
	}
	return &api.DeleteDBClusterSnapshotResult{DBClusterSnapshot: new(clusterSnapshotDTO(v))}, nil
}

func (s *Service) listSnapshots(ctx context.Context, tx Reader, kind, name, source string, marker *api.String, max *api.IntegerOptional, filters api.FilterList) ([]Snapshot, *api.String, error) {
	action := "DescribeDBSnapshots"
	if kind == "cluster-snapshot" {
		action = "DescribeDBClusterSnapshots"
	}
	if e := validateFilters(filters, "engine", "snapshot-type"); e != nil {
		return nil, nil, e
	}
	start, limit, e := pageStart(ctx, action, marker, max)
	if e != nil {
		return nil, nil, e
	}
	if name != "" {

		v, e := s.loadSnapshot(ctx, tx, action, kind, name)
		if e != nil {
			return nil, nil, e
		}
		name = v.Key.Name

	} else if e = s.authorize(ctx, action, Key{}, nil, nil); e != nil {
		return nil, nil, e
	}
	if source != "" {

		skind := "db"
		if kind == "cluster-snapshot" {
			skind = "cluster"
		}
		k, e := resourceKey(ctx, skind, source)
		if e != nil {
			return nil, nil, e
		}
		source = k.Name

	}
	all, e := s.querySnapshots(ctx, tx)
	if e != nil {
		return nil, nil, e
	}
	out := []Snapshot{}
	last := ""
	for _, v := range all {

		if v.Key.Kind != kind || v.Key.Name <= start || name != "" && v.Key.Name != name || source != "" && v.Source != source || !filterMatches(filters, map[string]string{"engine": v.Engine, "snapshot-type": "manual"}) {
			continue
		}
		if len(out) == limit {
			return out, pageMarker(ctx, action, last), nil
		}
		out = append(out, v)
		last = v.Key.Name

	}
	return out, nil, nil
}

func (s *Service) describeSnapshots(ctx context.Context, tx Transaction, in *api.DescribeDBSnapshotsMessage) (*api.DBSnapshotMessage, error) {
	if boolean(in.IncludePublic) || boolean(in.IncludeShared) || in.DbiResourceId != nil {
		return nil, unsupported("Public/shared and resource-ID snapshot selectors are not implemented.")
	}
	if t := value(in.SnapshotType); t != "" && t != "manual" {
		return nil, unsupported("Only manual snapshots are implemented.")
	}
	items, marker, e := s.listSnapshots(ctx, tx, "snapshot", value(in.DBSnapshotIdentifier), value(in.DBInstanceIdentifier), in.Marker, in.MaxRecords, in.Filters)
	if e != nil {
		return nil, e
	}
	out := &api.DBSnapshotMessage{Marker: marker, DBSnapshots: api.DBSnapshotList{}}
	for _, v := range items {
		out.DBSnapshots = append(out.DBSnapshots, snapshotDTO(v))
	}
	return out, nil
}

func (s *Service) describeClusterSnapshots(ctx context.Context, tx Transaction, in *api.DescribeDBClusterSnapshotsMessage) (*api.DBClusterSnapshotMessage, error) {
	if boolean(in.IncludePublic) || boolean(in.IncludeShared) || in.DbClusterResourceId != nil {
		return nil, unsupported("Public/shared and resource-ID snapshot selectors are not implemented.")
	}
	if t := value(in.SnapshotType); t != "" && t != "manual" {
		return nil, unsupported("Only manual snapshots are implemented.")
	}
	items, marker, e := s.listSnapshots(ctx, tx, "cluster-snapshot", value(in.DBClusterSnapshotIdentifier), value(in.DBClusterIdentifier), in.Marker, in.MaxRecords, in.Filters)
	if e != nil {
		return nil, e
	}
	out := &api.DBClusterSnapshotMessage{Marker: marker, DBClusterSnapshots: api.DBClusterSnapshotList{}}
	for _, v := range items {
		out.DBClusterSnapshots = append(out.DBClusterSnapshots, clusterSnapshotDTO(v))
	}
	return out, nil
}

func (s *Service) restoreDatabase(ctx context.Context, tx Transaction, kind, name, snapshot, eng, version, db, class, group string, tags api.TagList, port *api.IntegerOptional) (Database, error) {
	action, skind := "RestoreDBInstanceFromDBSnapshot", "snapshot"
	if kind == "cluster" {
		action, skind = "RestoreDBClusterFromSnapshot", "cluster-snapshot"
	}
	snap, e := s.loadSnapshot(ctx, tx, action, skind, snapshot)
	if e != nil {
		return Database{}, e
	}
	if snap.Status != "available" {
		return Database{}, stateError(skind)
	}
	if eng != "" && eng != snap.Engine || version != "" && version != snap.EngineVersion || db != "" && db != snap.DatabaseName {
		return Database{}, unsupported("Physical restore preserves the snapshot engine version and database names.")
	}
	if e = s.ensureRuntime(); e != nil {
		return Database{}, e
	}
	k, e := resourceKey(ctx, kind, name)
	if e != nil {
		return Database{}, e
	}
	if !validName(k.Name, 63) {
		return Database{}, failure("InvalidParameterValue", "Invalid database identifier.")
	}
	if _, e = tx.Database(k); e == nil {
		return Database{}, existsError(kind)
	} else if !errors.Is(e, ErrNotFound) {
		return Database{}, e
	}
	tagged, e := tagsFrom(tags)
	if e != nil {
		return Database{}, e
	}
	if e = s.authorize(ctx, action, k, nil, tagged); e != nil {
		return Database{}, e
	}
	user, password, e := s.cipher.Open(ctx, snap.Key.ARN(), snap.Ciphertext)
	if e != nil {
		return Database{}, e
	}
	sealed, e := s.cipher.Seal(ctx, k.ARN(), user, password)
	if e != nil {
		return Database{}, e
	}
	id, e := incarnation()
	if e != nil {
		return Database{}, e
	}
	if class == "" {
		class = snap.Class
	}
	if kind == "db" && !strings.HasPrefix(class, "db.") {
		return Database{}, failure("InvalidParameterValue", "DBInstanceClass is required.")
	}
	v := Database{Key: k, Engine: snap.Engine, EngineVersion: snap.EngineVersion, DatabaseName: snap.DatabaseName, Username: user, Class: class, ParameterGroup: group, RuntimeID: id, Status: "creating", Desired: "running", Operation: "restore", RestoreSnapshot: snap.RuntimeID, Ciphertext: sealed, Parameters: maps.Clone(snap.Parameters), Tags: tagged, Version: 1, Created: s.clock.Now(), Due: s.clock.Now()}
	if group != "" {

		v.Parameters, e = s.groupParameters(ctx, tx, kind, group, v.Engine)
		if e != nil {
			return v, e
		}

	}
	if port != nil {

		if *port < 1150 || *port > 65535 {
			return v, failure("InvalidParameterValue", "Port must be between 1150 and 65535.")
		}
		v.RequestedPort = int32(*port)

	}
	if kind == "cluster" {
		v.Due = time.Time{}
	}
	return v, nil
}

func (s *Service) restoreInstance(ctx context.Context, tx Transaction, in *api.RestoreDBInstanceFromDBSnapshotMessage) (*api.RestoreDBInstanceFromDBSnapshotResult, error) {
	if e := validateRestoreDBInstanceFromDBSnapshotMessage(in); e != nil {
		return nil, e
	}
	v, e := s.restoreDatabase(ctx, tx, "db", value(in.DBInstanceIdentifier), value(in.DBSnapshotIdentifier), value(in.Engine), "", value(in.DBName), value(in.DBInstanceClass), value(in.DBParameterGroupName), in.Tags, in.Port)
	if e != nil {
		return nil, e
	}
	v.DeletionProtection = boolean(in.DeletionProtection)
	v.CopyTags = boolean(in.CopyTagsToSnapshot)
	if e = tx.PutDatabase(v); e != nil {
		return nil, e
	}
	return &api.RestoreDBInstanceFromDBSnapshotResult{DBInstance: new(instanceDTO(v))}, nil
}

func (s *Service) restoreCluster(ctx context.Context, tx Transaction, in *api.RestoreDBClusterFromSnapshotMessage) (*api.RestoreDBClusterFromSnapshotResult, error) {
	if e := validateRestoreDBClusterFromSnapshotMessage(in); e != nil {
		return nil, e
	}
	if m := value(in.EngineMode); m != "" && m != "provisioned" {
		return nil, unsupported("Only modeled provisioned Aurora clusters are supported.")
	}
	v, e := s.restoreDatabase(ctx, tx, "cluster", value(in.DBClusterIdentifier), value(in.SnapshotIdentifier), value(in.Engine), value(in.EngineVersion), value(in.DatabaseName), "", value(in.DBClusterParameterGroupName), in.Tags, in.Port)
	if e != nil {
		return nil, e
	}
	v.DeletionProtection = boolean(in.DeletionProtection)
	v.CopyTags = boolean(in.CopyTagsToSnapshot)
	if e = tx.PutDatabase(v); e != nil {
		return nil, e
	}
	return &api.RestoreDBClusterFromSnapshotResult{DBCluster: new(clusterDTO(v, nil))}, nil
}
