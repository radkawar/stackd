package docdb

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/docdb"
)

func (s *Service) createInstance(ctx context.Context, tx Transaction, in *api.CreateDBInstanceInput) (*api.CreateDBInstanceOutput, error) {
	if value(in.Engine) != "docdb" {
		return nil, failure("InvalidParameterValue", "Engine must be docdb.")
	}
	if in.AvailabilityZone != nil || in.CACertificateIdentifier != nil || yes(in.EnablePerformanceInsights) || in.PerformanceInsightsKMSKeyId != nil || in.PreferredMaintenanceWindow != nil || in.PromotionTier != nil || yes(in.AutoMinorVersionUpgrade) || yes(in.CopyTagsToSnapshot) {
		return nil, unsupported("Managed instance placement, maintenance, promotion, monitoring and snapshot-tag settings are not implemented.")
	}
	if value(in.DBInstanceClass) == "" || value(in.DBInstanceClass) == "db.serverless" {
		return nil, unsupported("A provisioned DBInstanceClass is required; serverless capacity is not implemented.")
	}
	v, e := s.loadCluster(ctx, tx, "CreateDBInstance", value(in.DBClusterIdentifier))
	if e != nil {
		return nil, e
	}
	if v.Operation != "" || v.Status != "creating" {
		return nil, stateError("cluster")
	}
	members, e := membersOf(tx, v)
	if e != nil {
		return nil, e
	}
	if len(members) > 0 {
		return nil, unsupported("Only one native writer is implemented; managed replicas and failover are not available.")
	}
	k, e := resourceKey(ctx, "db", value(in.DBInstanceIdentifier))
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateDBInstance", k, nil, tags); e != nil {
		return nil, e
	}
	if e = s.checkName(ctx, k); e != nil {
		return nil, e
	}
	if _, e = tx.Instance(k); e == nil {
		return nil, duplicate("db")
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	id, e := incarnation()
	if e != nil {
		return nil, e
	}
	m := Instance{Key: k, Cluster: v.Key.Name, Class: value(in.DBInstanceClass), RuntimeID: id, Status: "creating", Created: s.clock.Now(), Tags: tags}
	v.Operation = "create"
	if v.RestoreSnapshot != "" {
		v.Operation = "restore"
	}
	v.Due = s.clock.Now()
	v.Version++
	if e = tx.PutInstance(m); e != nil {
		return nil, e
	}
	if e = tx.PutCluster(v); e != nil {
		return nil, e
	}
	return &api.CreateDBInstanceOutput{DBInstance: instanceOutput(m, v)}, nil
}
func (s *Service) deleteInstance(ctx context.Context, tx Transaction, in *api.DeleteDBInstanceInput) (*api.DeleteDBInstanceOutput, error) {
	m, e := s.loadInstance(ctx, tx, "DeleteDBInstance", value(in.DBInstanceIdentifier))
	if e != nil {
		return nil, e
	}
	v, e := tx.Cluster(Key{Scope: m.Key.Scope, Kind: "cluster", Name: m.Cluster})
	if e != nil {
		return nil, e
	}
	if v.Status != "failed" && (v.Operation != "" || v.Status != "available" && v.Status != "stopped") {
		return nil, stateError("db")
	}
	v.Operation = "detach"
	v.Status = "modifying"
	v.Due = s.clock.Now()
	v.Version++
	m.Status = "deleting"
	if e = tx.PutCluster(v); e != nil {
		return nil, e
	}
	if e = tx.PutInstance(m); e != nil {
		return nil, e
	}
	return &api.DeleteDBInstanceOutput{DBInstance: instanceOutput(m, v)}, nil
}
func (s *Service) rebootInstance(ctx context.Context, tx Transaction, in *api.RebootDBInstanceInput) (*api.RebootDBInstanceOutput, error) {
	m, e := s.loadInstance(ctx, tx, "RebootDBInstance", value(in.DBInstanceIdentifier))
	if e != nil {
		return nil, e
	}
	if yes(in.ForceFailover) {
		return nil, unsupported("Managed failover is not implemented.")
	}
	v, e := tx.Cluster(Key{Scope: m.Key.Scope, Kind: "cluster", Name: m.Cluster})
	if e != nil {
		return nil, e
	}
	if v.Status != "available" || m.Status != "available" {
		return nil, stateError("db")
	}
	v.Status = "rebooting"
	v.Operation = "reboot"
	v.Due = s.clock.Now()
	v.Version++
	if e = tx.PutCluster(v); e != nil {
		return nil, e
	}
	if e = s.mirrorMembers(tx, v); e != nil {
		return nil, e
	}
	m.Status = v.Status
	return &api.RebootDBInstanceOutput{DBInstance: instanceOutput(m, v)}, nil
}
func instanceOutput(m Instance, v Cluster) *api.DBInstance {
	out := &api.DBInstance{DBInstanceArn: new(api.String(m.Key.ARN())), DBInstanceIdentifier: new(api.String(m.Key.Name)), DBClusterIdentifier: new(api.String(m.Cluster)), DBInstanceClass: new(api.String(m.Class)), DbiResourceId: new(api.String("db-" + m.RuntimeID)), DBInstanceStatus: new(api.String(m.Status)), Engine: new(api.String("docdb")), EngineVersion: new(api.String(v.EngineVersion)), InstanceCreateTime: new(api.TStamp(m.Created)), PubliclyAccessible: new(api.Boolean(false)), StorageEncrypted: new(api.Boolean(false)), AutoMinorVersionUpgrade: new(api.Boolean(false))}
	if v.Endpoint.Address != "" {
		out.Endpoint = &api.Endpoint{Address: new(api.String(v.Endpoint.Address)), Port: new(api.Integer(v.Endpoint.Port))}
	}
	return out
}
