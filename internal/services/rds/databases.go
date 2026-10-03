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

func (s *Service) newDatabase(ctx context.Context, tx Transaction, k Key, eng, version, db, user, password, class, group string, tags api.TagList, port *api.IntegerOptional) (Database, error) {
	v := Database{Key: k, Engine: eng, EngineVersion: engineVersion(eng), DatabaseName: db, Username: user, Class: class, ParameterGroup: group, Status: "creating", Desired: "running", Operation: "create", Version: 1, Created: s.clock.Now(), Due: s.clock.Now()}
	if e := s.ensureRuntime(); e != nil {
		return v, e
	}
	if !validName(k.Name, 63) {
		return v, failure("InvalidParameterValue", "Invalid database identifier.")
	}
	if v.EngineVersion == "" || version != "" && version != v.EngineVersion {
		return v, unsupported("Only the pinned native engine version is supported.")
	}
	if k.Kind == "cluster" && !strings.HasPrefix(eng, "aurora-") || k.Kind == "db" && strings.HasPrefix(eng, "aurora-") {
		return v, unsupported("Use standalone postgres/mysql instances or an Aurora cluster with a writer member.")
	}
	if e := validateDBName(db); e != nil {
		return v, e
	}
	if e := validateCredentials(eng, user, password); e != nil {
		return v, e
	}
	if k.Kind == "db" && (class == "" || !strings.HasPrefix(class, "db.")) {
		return v, failure("InvalidParameterValue", "DBInstanceClass is required.")
	}
	var e error
	v.Tags, e = tagsFrom(tags)
	if e != nil {
		return v, e
	}
	action := "CreateDBInstance"
	if k.Kind == "cluster" {
		action = "CreateDBCluster"
	}
	if e = s.authorize(ctx, action, k, nil, v.Tags); e != nil {
		return v, e
	}
	if _, e = tx.Database(k); e == nil {
		return v, existsError(k.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return v, e
	}
	v.Parameters, e = s.groupParameters(ctx, tx, k.Kind, group, eng)
	if e != nil {
		return v, e
	}
	if port != nil {

		if *port < 1150 || *port > 65535 {
			return v, failure("InvalidParameterValue", "Port must be between 1150 and 65535.")
		}
		v.RequestedPort = int32(*port)

	}
	v.RuntimeID, e = incarnation()
	if e != nil {
		return v, e
	}
	v.Ciphertext, e = s.cipher.Seal(ctx, k.ARN(), user, password)
	return v, e
}

func (s *Service) createInstance(ctx context.Context, tx Transaction, in *api.CreateDBInstanceMessage) (*api.CreateDBInstanceResult, error) {
	if e := validateCreateDBInstanceMessage(in); e != nil {
		return nil, e
	}
	k, e := resourceKey(ctx, "db", value(in.DBInstanceIdentifier))
	if e != nil {
		return nil, e
	}
	if value(in.DBClusterIdentifier) != "" {
		return s.createWriter(ctx, tx, k, in)
	}
	v, e := s.newDatabase(ctx, tx, k, value(in.Engine), value(in.EngineVersion), value(in.DBName), value(in.MasterUsername), value(in.MasterUserPassword), value(in.DBInstanceClass), value(in.DBParameterGroupName), in.Tags, in.Port)
	if e != nil {
		return nil, e
	}
	v.DeletionProtection = boolean(in.DeletionProtection)
	v.CopyTags = boolean(in.CopyTagsToSnapshot)
	if e = tx.PutDatabase(v); e != nil {
		return nil, e
	}
	return &api.CreateDBInstanceResult{DBInstance: new(instanceDTO(v))}, nil
}

func (s *Service) createCluster(ctx context.Context, tx Transaction, in *api.CreateDBClusterMessage) (*api.CreateDBClusterResult, error) {
	if e := validateCreateDBClusterMessage(in); e != nil {
		return nil, e
	}
	if m := value(in.EngineMode); m != "" && m != "provisioned" {
		return nil, unsupported("Only modeled provisioned Aurora clusters are supported.")
	}
	k, e := resourceKey(ctx, "cluster", value(in.DBClusterIdentifier))
	if e != nil {
		return nil, e
	}
	v, e := s.newDatabase(ctx, tx, k, value(in.Engine), value(in.EngineVersion), value(in.DatabaseName), value(in.MasterUsername), value(in.MasterUserPassword), "", value(in.DBClusterParameterGroupName), in.Tags, in.Port)
	if e != nil {
		return nil, e
	}
	v.DeletionProtection = boolean(in.DeletionProtection)
	v.CopyTags = boolean(in.CopyTagsToSnapshot)
	v.HTTPEnabled = boolean(in.EnableHttpEndpoint)
	v.Due = time.Time{}
	if e = tx.PutDatabase(v); e != nil {
		return nil, e
	}
	return &api.CreateDBClusterResult{DBCluster: new(clusterDTO(v, nil))}, nil
}

func (s *Service) createWriter(ctx context.Context, tx Transaction, k Key, in *api.CreateDBInstanceMessage) (*api.CreateDBInstanceResult, error) {
	c, e := s.loadDatabase(ctx, tx, "CreateDBInstance", "cluster", value(in.DBClusterIdentifier))
	if e != nil {
		return nil, e
	}
	if c.Status != "creating" && c.Status != "available" {
		return nil, stateError("cluster")
	}
	if value(in.Engine) != c.Engine || value(in.EngineVersion) != "" && value(in.EngineVersion) != c.EngineVersion {
		return nil, failure("InvalidParameterCombination", "Writer engine must match its cluster.")
	}
	if in.MasterUsername != nil || in.MasterUserPassword != nil || in.DBName != nil || in.Port != nil || in.DBParameterGroupName != nil {
		return nil, unsupported("Cluster writer credentials, database, port and parameters are controlled by the cluster.")
	}
	if !validName(k.Name, 63) || value(in.DBInstanceClass) == "" || !strings.HasPrefix(value(in.DBInstanceClass), "db.") {
		return nil, failure("InvalidParameterValue", "Invalid writer identifier or class.")
	}
	dbs, e := tx.Databases(k.Scope)
	if e != nil {
		return nil, e
	}
	for _, v := range dbs {

		if v.Key == k {
			return nil, existsError("db")
		}
		if v.Cluster == c.Key.Name {
			return nil, unsupported("Only one real writer is supported; read replicas and failover are not implemented.")
		}

	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateDBInstance", k, nil, tags); e != nil {
		return nil, e
	}
	v := Database{Key: k, Engine: c.Engine, EngineVersion: c.EngineVersion, DatabaseName: c.DatabaseName, Username: c.Username, Class: value(in.DBInstanceClass), Cluster: c.Key.Name, RuntimeID: c.RuntimeID, Status: "creating", Desired: "running", Version: 1, Created: s.clock.Now(), Tags: tags, DeletionProtection: boolean(in.DeletionProtection), CopyTags: boolean(in.CopyTagsToSnapshot)}
	c.Due = s.clock.Now()
	if c.Operation == "" {
		c.Operation = "start"
	}
	c.Version++
	if e = tx.PutDatabase(c); e != nil {
		return nil, e
	}
	if e = tx.PutDatabase(v); e != nil {
		return nil, e
	}
	return &api.CreateDBInstanceResult{DBInstance: new(instanceDTO(v))}, nil
}

func (s *Service) modifyDatabase(ctx context.Context, tx Transaction, action, kind, name string, password *api.SensitiveString, protection, copyTags *api.BooleanOptional, group *api.String, immediate *api.Boolean) (Database, error) {
	v, e := s.loadDatabase(ctx, tx, action, kind, name)
	if e != nil {
		return v, e
	}
	if v.Cluster != "" && (password != nil || group != nil) {
		return v, unsupported("Modify credentials and parameters through the owning cluster.")
	}
	if v.Status != "available" && v.Status != "stopped" {
		return v, stateError(kind)
	}
	if password != nil {

		if !boolean(immediate) {
			return v, unsupported("Deferred credential modification is not supported; set ApplyImmediately.")
		}
		if v.Status != "available" {
			return v, stateError(kind)
		}
		if e = validateCredentials(v.Engine, v.Username, string(*password)); e != nil {
			return v, e
		}
		v.PendingCiphertext, e = s.cipher.Seal(ctx, v.Key.ARN(), v.Username, string(*password))
		if e != nil {
			return v, e
		}
		v.Status = "modifying"
		v.Operation = "password"
		v.Endpoint = engine.Endpoint{}
		v.Due = s.clock.Now()

	}
	if group != nil {

		parameters, e := s.groupParameters(ctx, tx, kind, string(*group), v.Engine)
		if e != nil {
			return v, e
		}
		v.ParameterGroup = string(*group)
		v.PendingParameters = !maps.Equal(v.Parameters, parameters)

	}
	if protection != nil {
		v.DeletionProtection = bool(*protection)
	}
	if copyTags != nil {
		v.CopyTags = bool(*copyTags)
	}
	v.Version++
	if e = tx.PutDatabase(v); e != nil {
		return v, e
	}
	if kind == "cluster" {
		e = s.mirrorMembers(tx, v)
	}
	return v, e
}

func (s *Service) modifyInstance(ctx context.Context, tx Transaction, in *api.ModifyDBInstanceMessage) (*api.ModifyDBInstanceResult, error) {
	if e := validateModifyDBInstanceMessage(in); e != nil {
		return nil, e
	}
	v, e := s.modifyDatabase(ctx, tx, "ModifyDBInstance", "db", value(in.DBInstanceIdentifier), in.MasterUserPassword, in.DeletionProtection, in.CopyTagsToSnapshot, in.DBParameterGroupName, in.ApplyImmediately)
	if e != nil {
		return nil, e
	}
	return &api.ModifyDBInstanceResult{DBInstance: new(instanceDTO(v))}, nil
}

func (s *Service) modifyCluster(ctx context.Context, tx Transaction, in *api.ModifyDBClusterMessage) (*api.ModifyDBClusterResult, error) {
	if e := validateModifyDBClusterMessage(in); e != nil {
		return nil, e
	}
	v, e := s.modifyDatabase(ctx, tx, "ModifyDBCluster", "cluster", value(in.DBClusterIdentifier), in.MasterUserPassword, in.DeletionProtection, in.CopyTagsToSnapshot, in.DBClusterParameterGroupName, in.ApplyImmediately)
	if e != nil {
		return nil, e
	}
	if in.EnableHttpEndpoint != nil {

		v.HTTPEnabled = bool(*in.EnableHttpEndpoint)
		if e = tx.PutDatabase(v); e != nil {
			return nil, e
		}

	}
	members, e := tx.Databases(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	return &api.ModifyDBClusterResult{DBCluster: new(clusterDTO(v, members))}, nil
}

func (s *Service) transition(ctx context.Context, tx Transaction, action, kind, name, op string) (Database, error) {
	v, e := s.loadDatabase(ctx, tx, action, kind, name)
	if e != nil {
		return v, e
	}
	if v.Cluster != "" {
		return v, unsupported("Start and stop the owning cluster, not its writer member.")
	}
	switch op {

	case "start":
		if v.Status != "stopped" {
			return v, stateError(kind)
		}
		v.Status = "starting"
		v.Desired = "running"
	case "stop":
		if v.Status != "available" {
			return v, stateError(kind)
		}
		v.Status = "stopping"
		v.Desired = "stopped"
	case "reboot":
		if v.Status != "available" {
			return v, stateError(kind)
		}
		v.Status = "rebooting"

	}
	if op == "start" || op == "reboot" {

		v.Parameters, e = s.groupParameters(ctx, tx, kind, v.ParameterGroup, v.Engine)
		if e != nil {
			return v, e
		}

	}
	v.Operation = op
	v.Endpoint = engine.Endpoint{}
	v.Version++
	v.Due = s.clock.Now()
	if e = tx.PutDatabase(v); e != nil {
		return v, e
	}
	if kind == "cluster" {
		e = s.mirrorMembers(tx, v)
	}
	return v, e
}

func (s *Service) startInstance(ctx context.Context, tx Transaction, in *api.StartDBInstanceMessage) (*api.StartDBInstanceResult, error) {
	v, e := s.transition(ctx, tx, "StartDBInstance", "db", value(in.DBInstanceIdentifier), "start")
	if e != nil {
		return nil, e
	}
	return &api.StartDBInstanceResult{DBInstance: new(instanceDTO(v))}, nil
}

func (s *Service) stopInstance(ctx context.Context, tx Transaction, in *api.StopDBInstanceMessage) (*api.StopDBInstanceResult, error) {
	if in.DBSnapshotIdentifier != nil {
		return nil, unsupported("Use CreateDBSnapshot before stopping an instance.")
	}
	v, e := s.transition(ctx, tx, "StopDBInstance", "db", value(in.DBInstanceIdentifier), "stop")
	if e != nil {
		return nil, e
	}
	return &api.StopDBInstanceResult{DBInstance: new(instanceDTO(v))}, nil
}

func (s *Service) startCluster(ctx context.Context, tx Transaction, in *api.StartDBClusterMessage) (*api.StartDBClusterResult, error) {
	v, e := s.transition(ctx, tx, "StartDBCluster", "cluster", value(in.DBClusterIdentifier), "start")
	if e != nil {
		return nil, e
	}
	members, e := tx.Databases(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	return &api.StartDBClusterResult{DBCluster: new(clusterDTO(v, members))}, nil
}

func (s *Service) stopCluster(ctx context.Context, tx Transaction, in *api.StopDBClusterMessage) (*api.StopDBClusterResult, error) {
	v, e := s.transition(ctx, tx, "StopDBCluster", "cluster", value(in.DBClusterIdentifier), "stop")
	if e != nil {
		return nil, e
	}
	members, e := tx.Databases(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	return &api.StopDBClusterResult{DBCluster: new(clusterDTO(v, members))}, nil
}

func (s *Service) rebootInstance(ctx context.Context, tx Transaction, in *api.RebootDBInstanceMessage) (*api.RebootDBInstanceResult, error) {
	if boolean(in.ForceFailover) {
		return nil, unsupported("Failover is not implemented.")
	}
	v, e := s.loadDatabase(ctx, tx, "RebootDBInstance", "db", value(in.DBInstanceIdentifier))
	if e != nil {
		return nil, e
	}
	if v.Cluster != "" {

		c, e := s.transition(ctx, tx, "RebootDBInstance", "cluster", v.Cluster, "reboot")
		if e != nil {
			return nil, e
		}
		v.Status = c.Status
		v.Endpoint = c.Endpoint

	} else {

		v, e = s.transition(ctx, tx, "RebootDBInstance", "db", v.Key.Name, "reboot")
		if e != nil {
			return nil, e
		}

	}
	return &api.RebootDBInstanceResult{DBInstance: new(instanceDTO(v))}, nil
}

func (s *Service) deleteDatabase(ctx context.Context, tx Transaction, kind, name string, skip *api.Boolean, final *api.String, automated *api.BooleanOptional) (Database, error) {
	action := "DeleteDBInstance"
	if kind == "cluster" {
		action = "DeleteDBCluster"
	}
	v, e := s.loadDatabase(ctx, tx, action, kind, name)
	if e != nil {
		return v, e
	}
	if v.DeletionProtection {
		return v, failure("InvalidParameterCombination", "Deletion protection is enabled.")
	}
	if automated != nil && !bool(*automated) {
		return v, unsupported("Retained automated backups are not implemented.")
	}
	if v.Status == "backing-up" || v.Status == "modifying" || v.Status == "deleting" {
		return v, stateError(kind)
	}
	if !boolean(skip) {
		return v, unsupported("Create a manual snapshot first, then set SkipFinalSnapshot; final snapshot deletion is not implemented.")
	}
	if final != nil {
		return v, failure("InvalidParameterCombination", "FinalDBSnapshotIdentifier conflicts with SkipFinalSnapshot.")
	}
	dbs, e := tx.Databases(v.Key.Scope)
	if e != nil {
		return v, e
	}
	if kind == "cluster" {
		for _, m := range dbs {
			if m.Cluster == v.Key.Name {
				return v, stateError(kind)
			}
		}
	}
	if v.Cluster != "" {

		c, e := tx.Database(Key{Scope: v.Key.Scope, Kind: "cluster", Name: v.Cluster})
		if e != nil {
			return v, e
		}
		if c.Status == "backing-up" || c.Status == "modifying" {
			return v, stateError(kind)
		}
		c.Status = "stopping"
		c.Operation = "detach"
		c.Endpoint = engine.Endpoint{}
		c.Version++
		c.Due = s.clock.Now()
		if e = tx.PutDatabase(c); e != nil {
			return v, e
		}

	}
	v.Status = "deleting"
	v.Desired = "deleted"
	v.Operation = "delete"
	v.Endpoint = engine.Endpoint{}
	v.Version++
	v.Due = s.clock.Now()
	if e = tx.PutDatabase(v); e != nil {
		return v, e
	}
	return v, nil
}

func (s *Service) deleteInstance(ctx context.Context, tx Transaction, in *api.DeleteDBInstanceMessage) (*api.DeleteDBInstanceResult, error) {
	v, e := s.deleteDatabase(ctx, tx, "db", value(in.DBInstanceIdentifier), in.SkipFinalSnapshot, in.FinalDBSnapshotIdentifier, in.DeleteAutomatedBackups)
	if e != nil {
		return nil, e
	}
	return &api.DeleteDBInstanceResult{DBInstance: new(instanceDTO(v))}, nil
}

func (s *Service) deleteCluster(ctx context.Context, tx Transaction, in *api.DeleteDBClusterMessage) (*api.DeleteDBClusterResult, error) {
	v, e := s.deleteDatabase(ctx, tx, "cluster", value(in.DBClusterIdentifier), in.SkipFinalSnapshot, in.FinalDBSnapshotIdentifier, in.DeleteAutomatedBackups)
	if e != nil {
		return nil, e
	}
	return &api.DeleteDBClusterResult{DBCluster: new(clusterDTO(v, nil))}, nil
}

func (s *Service) mirrorMembers(tx Transaction, c Database) error {
	dbs, e := tx.Databases(c.Key.Scope)
	if e != nil {
		return e
	}
	for _, v := range dbs {

		if v.Cluster != c.Key.Name || v.Status == "deleting" {
			continue
		}
		v.Status = c.Status
		v.Operation = c.Operation
		v.Endpoint = c.Endpoint
		v.PendingParameters = c.PendingParameters
		v.Version++
		if e = tx.PutDatabase(v); e != nil {
			return e
		}

	}
	return nil
}
