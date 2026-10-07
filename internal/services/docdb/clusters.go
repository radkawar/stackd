package docdb

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/docdb"
)

func (s *Service) createCluster(ctx context.Context, tx Transaction, in *api.CreateDBClusterInput) (*api.CreateDBClusterOutput, error) {
	if e := s.ensureRuntime(); e != nil {
		return nil, e
	}
	if value(in.Engine) != "docdb" || in.EngineVersion != nil && value(in.EngineVersion) != "5.0" {
		return nil, unsupported("Only the DocumentDB 5.0 compatibility contract is supported by this native backend.")
	}
	if len(in.AvailabilityZones) > 0 || in.BackupRetentionPeriod != nil || in.DBClusterParameterGroupName != nil || in.DBSubnetGroupName != nil || len(in.EnableCloudwatchLogsExports) > 0 || in.GlobalClusterIdentifier != nil || in.KmsKeyId != nil || yes(in.ManageMasterUserPassword) || in.MasterUserSecretKmsKeyId != nil || in.NetworkType != nil || in.PreSignedUrl != nil || in.PreferredBackupWindow != nil || in.PreferredMaintenanceWindow != nil || in.ServerlessV2ScalingConfiguration != nil || yes(in.StorageEncrypted) || in.StorageType != nil || len(in.VpcSecurityGroupIds) > 0 {
		return nil, unsupported("Managed networking, parameters, storage, backups, maintenance and managed credentials are not implemented.")
	}
	user, password := value(in.MasterUsername), value(in.MasterUserPassword)
	if e := validateCredentials(user, password); e != nil {
		return nil, e
	}
	port := int32(0)
	if in.Port != nil {
		port = int32(*in.Port)
		if port < 1150 || port > 65535 {
			return nil, failure("InvalidParameterValue", "Port must be between 1150 and 65535.")
		}
	}
	k, e := resourceKey(ctx, "cluster", value(in.DBClusterIdentifier))
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateDBCluster", k, nil, tags); e != nil {
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
	id, e := incarnation()
	if e != nil {
		return nil, e
	}
	cipher, e := s.cipher.Seal(ctx, k.ARN(), user, password)
	if e != nil {
		return nil, e
	}
	v := Cluster{Key: k, RuntimeID: id, Username: user, EngineVersion: "5.0", Status: "creating", Ciphertext: cipher, RequestedPort: port, Version: 1, Created: s.clock.Now(), DeletionProtection: yes(in.DeletionProtection), Tags: tags}
	v.Owner = cloudFormationClaim(ctx, k)
	if e = tx.PutCluster(v); e != nil {
		return nil, e
	}
	out, e := clusterOutput(tx, v)
	return &api.CreateDBClusterOutput{DBCluster: out}, e
}
func (s *Service) modifyCluster(ctx context.Context, tx Transaction, in *api.ModifyDBClusterInput) (*api.ModifyDBClusterOutput, error) {
	v, e := s.loadCluster(ctx, tx, "ModifyDBCluster", value(in.DBClusterIdentifier))
	if e != nil {
		return nil, e
	}
	if v.Status != "available" && v.Status != "stopped" && !(v.Status == "creating" && v.Operation == "") && !(v.Status == "modifying" && v.Operation == "password") {
		return nil, stateError("cluster")
	}
	if yes(in.AllowMajorVersionUpgrade) || in.BackupRetentionPeriod != nil || in.CloudwatchLogsExportConfiguration != nil || in.DBClusterParameterGroupName != nil || in.EngineVersion != nil || yes(in.ManageMasterUserPassword) || in.MasterUserSecretKmsKeyId != nil || in.NetworkType != nil || in.NewDBClusterIdentifier != nil || in.Port != nil || in.PreferredBackupWindow != nil || in.PreferredMaintenanceWindow != nil || yes(in.RotateMasterUserPassword) || in.ServerlessV2ScalingConfiguration != nil || in.StorageType != nil || len(in.VpcSecurityGroupIds) > 0 {
		return nil, unsupported("Only deletion protection and immediate native password changes are supported.")
	}
	if v.Status == "modifying" {
		if in.MasterUserPassword == nil || !yes(in.ApplyImmediately) {
			return nil, stateError("cluster")
		}
		user, pending, err := s.cipher.Open(ctx, v.Key.ARN(), v.PendingCiphertext)
		if err != nil {
			return nil, err
		}
		if user != v.Username || pending != value(in.MasterUserPassword) || in.DeletionProtection != nil && bool(*in.DeletionProtection) != v.DeletionProtection {
			return nil, stateError("cluster")
		}
		out, err := clusterOutput(tx, v)
		return &api.ModifyDBClusterOutput{DBCluster: out}, err
	}
	if in.DeletionProtection != nil {
		v.DeletionProtection = bool(*in.DeletionProtection)
	}
	if in.MasterUserPassword != nil {
		if !yes(in.ApplyImmediately) {
			return nil, unsupported("Scheduled password application is not implemented; specify ApplyImmediately.")
		}
		if v.Status != "available" {
			return nil, stateError("cluster")
		}
		if e = validateCredentials(v.Username, value(in.MasterUserPassword)); e != nil {
			return nil, e
		}
		v.PendingCiphertext, e = s.cipher.Seal(ctx, v.Key.ARN(), v.Username, value(in.MasterUserPassword))
		if e != nil {
			return nil, e
		}
		v.Status = "modifying"
		v.Operation = "password"
		v.Due = s.clock.Now()
	}
	v.Version++
	if e = tx.PutCluster(v); e != nil {
		return nil, e
	}
	if e = s.mirrorMembers(tx, v); e != nil {
		return nil, e
	}
	out, e := clusterOutput(tx, v)
	return &api.ModifyDBClusterOutput{DBCluster: out}, e
}
func (s *Service) deleteCluster(ctx context.Context, tx Transaction, in *api.DeleteDBClusterInput) (*api.DeleteDBClusterOutput, error) {
	v, e := s.loadCluster(ctx, tx, "DeleteDBCluster", value(in.DBClusterIdentifier))
	if e != nil {
		return nil, e
	}
	if v.DeletionProtection {
		return nil, failure("InvalidParameterCombination", "Disable deletion protection before deleting the cluster.")
	}
	if !yes(in.SkipFinalSnapshot) || in.FinalDBSnapshotIdentifier != nil {
		return nil, unsupported("Create an explicit cluster snapshot before deletion and specify SkipFinalSnapshot.")
	}
	members, e := membersOf(tx, v)
	if e != nil {
		return nil, e
	}
	if len(members) > 0 {
		return nil, stateError("cluster")
	}
	if v.Operation != "" && v.Status != "failed" {
		return nil, stateError("cluster")
	}
	snapshots, e := tx.Snapshots()
	if e != nil {
		return nil, e
	}
	for _, snap := range snapshots {
		if snap.SourceRuntimeID == v.RuntimeID && snap.Status != "available" && snap.Status != "deleting" {
			return nil, stateError("cluster")
		}
	}
	v.Status = "deleting"
	v.Operation = "delete"
	v.Due = s.clock.Now()
	v.Version++
	if e = tx.PutCluster(v); e != nil {
		return nil, e
	}
	out, e := clusterOutput(tx, v)
	return &api.DeleteDBClusterOutput{DBCluster: out}, e
}
func (s *Service) stopCluster(ctx context.Context, tx Transaction, in *api.StopDBClusterInput) (*api.StopDBClusterOutput, error) {
	v, e := s.transition(ctx, tx, "StopDBCluster", value(in.DBClusterIdentifier), "available", "stopping", "stop")
	if e != nil {
		return nil, e
	}
	out, e := clusterOutput(tx, v)
	return &api.StopDBClusterOutput{DBCluster: out}, e
}
func (s *Service) startCluster(ctx context.Context, tx Transaction, in *api.StartDBClusterInput) (*api.StartDBClusterOutput, error) {
	v, e := s.transition(ctx, tx, "StartDBCluster", value(in.DBClusterIdentifier), "stopped", "starting", "start")
	if e != nil {
		return nil, e
	}
	out, e := clusterOutput(tx, v)
	return &api.StartDBClusterOutput{DBCluster: out}, e
}
func (s *Service) transition(ctx context.Context, tx Transaction, action, name, from, status, op string) (Cluster, error) {
	v, e := s.loadCluster(ctx, tx, action, name)
	if e != nil {
		return v, e
	}
	if v.Status != from {
		return v, stateError("cluster")
	}
	v.Status = status
	v.Operation = op
	v.Due = s.clock.Now()
	v.Version++
	if e = tx.PutCluster(v); e != nil {
		return v, e
	}
	return v, s.mirrorMembers(tx, v)
}
func membersOf(r Reader, v Cluster) ([]Instance, error) {
	all, e := r.Instances()
	if e != nil {
		return nil, e
	}
	out := []Instance{}
	for _, m := range all {
		if m.Key.Scope == v.Key.Scope && m.Cluster == v.Key.Name {
			out = append(out, m)
		}
	}
	return out, nil
}
func (s *Service) mirrorMembers(tx Transaction, v Cluster) error {
	members, e := membersOf(tx, v)
	if e != nil {
		return e
	}
	for _, m := range members {
		if m.Status == "deleting" {
			continue
		}
		m.Status = v.Status
		if e = tx.PutInstance(m); e != nil {
			return e
		}
	}
	return nil
}
func clusterOutput(r Reader, v Cluster) (*api.DBCluster, error) {
	members, e := membersOf(r, v)
	if e != nil {
		return nil, e
	}
	out := &api.DBCluster{DBClusterArn: new(api.String(v.Key.ARN())), DBClusterIdentifier: new(api.String(v.Key.Name)), DbClusterResourceId: new(api.String("cluster-" + v.RuntimeID)), Engine: new(api.String("docdb")), EngineVersion: new(api.String(v.EngineVersion)), MasterUsername: new(api.String(v.Username)), Status: new(api.String(v.Status)), ClusterCreateTime: new(api.TStamp(v.Created)), DeletionProtection: new(api.Boolean(v.DeletionProtection)), StorageEncrypted: new(api.Boolean(false)), MultiAZ: new(api.Boolean(false))}
	if v.Endpoint.Address != "" {
		out.Endpoint = new(api.String(v.Endpoint.Address))
		out.Port = new(api.IntegerOptional(v.Endpoint.Port))
	}
	for _, m := range members {
		out.DBClusterMembers = append(out.DBClusterMembers, api.DBClusterMember{DBInstanceIdentifier: new(api.String(m.Key.Name)), IsClusterWriter: new(api.Boolean(true)), DBClusterParameterGroupStatus: new(api.String("in-sync"))})
	}
	return out, nil
}

// CloudFormationRequestedPort retains the distinction between a fixed listener
// and owner-selected allocation even before a writer publishes an endpoint.
// A member has no independently configurable listener; observe its actual row
// and current DescribeDBInstances authority before reporting that distinction.
func (s *Service) CloudFormationRequestedPort(ctx context.Context, kind, name string) (int32, error) {
	if kind == "db" {
		err := s.repository.View(ctx, func(r Reader) error {
			_, err := s.loadInstance(r.Context(), r, "DescribeDBInstances", name)
			return err
		})
		return 0, err
	}
	if kind != "cluster" {
		return 0, failure("InvalidParameterValue", "A cluster owns the DocumentDB port.")
	}
	var port int32
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := s.loadCluster(r.Context(), r, "DescribeDBClusters", name)
		if err != nil {
			return err
		}
		port = v.RequestedPort
		return nil
	})
	return port, err
}

// ResolveCluster rechecks current authority and reports the source incarnation
// separately from native writer readiness. Admission does not open the engine.
func (s *Service) ResolveCluster(ctx context.Context, arn string) (SourceCluster, error) {
	var out SourceCluster
	err := s.repository.View(ctx, func(r Reader) error {
		v, e := s.loadCluster(r.Context(), r, "DescribeDBClusters", arn)
		if e != nil {
			return e
		}
		members, e := membersOf(r, v)
		if e != nil {
			return e
		}
		ready := v.Status == "available" && v.Endpoint.Address != "" && len(members) == 1 && members[0].Status == "available"
		out = SourceCluster{ARN: v.Key.ARN(), RuntimeID: v.RuntimeID, Status: v.Status, Endpoint: v.Endpoint, Ready: ready}
		return nil
	})
	return out, err
}
func (s *Service) WithRDSRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []string) error) error {
	return s.repository.View(ctx, func(r Reader) error {
		all, e := r.Clusters()
		if e != nil {
			return e
		}
		resources := []string{}
		for _, v := range all {
			if v.Key.Partition == partition && v.Key.AccountID == account {
				resources = append(resources, v.Key.ARN())
			}
		}
		snapshots, e := r.Snapshots()
		if e != nil {
			return e
		}
		for _, v := range snapshots {
			if v.Key.Partition == partition && v.Key.AccountID == account {
				resources = append(resources, v.Key.ARN())
			}
		}
		return fn(r.Context(), resources)
	})
}
