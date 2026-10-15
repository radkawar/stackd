package rds

import (
	"context"
	"errors"
	"strings"

	api "stackd/internal/awsapi/rds"
)

func globalScopeFor(ctx context.Context) GlobalScope {
	sc := scopeFor(ctx)
	return GlobalScope{Partition: sc.Partition, AccountID: sc.AccountID}
}

func globalKey(ctx context.Context, name string) (GlobalKey, error) {
	scope := globalScopeFor(ctx)
	k := GlobalKey{GlobalScope: scope, Name: strings.ToLower(name)}
	if strings.HasPrefix(name, "arn:") {
		prefix := "arn:" + scope.Partition + ":rds::" + scope.AccountID + ":global-cluster:"
		if !strings.HasPrefix(name, prefix) {
			return GlobalKey{}, failure("GlobalClusterNotFoundFault", "The requested global cluster does not exist.")
		}
		k.Name = strings.ToLower(strings.TrimPrefix(name, prefix))
	}
	if !validName(k.Name, 63) {
		return GlobalKey{}, failure("InvalidParameterValue", "Invalid global cluster identifier.")
	}
	return k, nil
}

func (s *Service) loadGlobalCluster(ctx context.Context, tx Reader, action, name string) (GlobalCluster, error) {
	k, err := globalKey(ctx, name)
	if err != nil {
		return GlobalCluster{}, err
	}
	v, err := tx.GlobalCluster(k)
	if errors.Is(err, ErrNotFound) {
		err = failure("GlobalClusterNotFoundFault", "The requested global cluster does not exist.")
	}
	if err != nil {
		return GlobalCluster{}, err
	}
	return v, s.authorize(ctx, action, k.resourceKey(), v.Tags, nil)
}

// These are empty-namespace configuration versions, not native runtime versions.
// In particular, a native MySQL version is not an Aurora MySQL version. Resolving
// AWS's changing default/catalog and performing engine upgrades are not owned.
// https://docs.aws.amazon.com/AmazonRDS/latest/AuroraMySQLReleaseNotes/AuroraMySQL.Updates.3090.html
// https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Concepts.Aurora_Fea_Regions_DB-eng.Feature.GlobalDatabase.html
func globalVersion(engine, requested string) (string, error) {
	switch engine {
	case "docdb":
		if requested == "" || requested == "5.0" {
			return "5.0", nil
		}
	case "aurora-postgresql":
		if requested == "16.6" {
			return requested, nil
		}
	case "aurora-mysql":
		if requested == "8.0.mysql_aurora.3.09.0" {
			return requested, nil
		}
	default:
		return "", failure("InvalidParameterValue", "Engine must be docdb, aurora-postgresql or aurora-mysql for an empty global cluster.")
	}
	return "", unsupported("Empty global clusters support DocDB 5.0, explicit Aurora PostgreSQL 16.6 or explicit Aurora MySQL 8.0.mysql_aurora.3.09.0; AWS default version resolution and other versions are not implemented.")
}

func (s *Service) createGlobalCluster(ctx context.Context, tx Transaction, in *api.CreateGlobalClusterMessage) (*api.CreateGlobalClusterResult, error) {
	if in.SourceDBClusterIdentifier != nil {
		return nil, unsupported("SourceDBClusterIdentifier requires a real global replication engine; only initially empty global clusters are supported.")
	}
	k, err := globalKey(ctx, value(in.GlobalClusterIdentifier))
	if err != nil {
		return nil, err
	}
	// Creation takes a name, never an ARN referring to a pre-existing object.
	if strings.HasPrefix(value(in.GlobalClusterIdentifier), "arn:") {
		return nil, failure("InvalidParameterValue", "A new global cluster requires an identifier, not an ARN.")
	}
	eng := value(in.Engine)
	version, err := globalVersion(eng, value(in.EngineVersion))
	if err != nil {
		return nil, err
	}
	database := value(in.DatabaseName)
	if in.DatabaseName != nil {
		if len(database) == 0 || len(database) > 64 {
			return nil, failure("InvalidParameterValue", "DatabaseName must contain 1 to 64 alphanumeric characters.")
		}
		for _, c := range database {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return nil, failure("InvalidParameterValue", "DatabaseName must contain 1 to 64 alphanumeric characters.")
			}
		}
	}
	lifecycle := ""
	if eng == "aurora-postgresql" {
		lifecycle = "open-source-rds-extended-support"
	}
	if in.EngineLifecycleSupport != nil {
		if eng != "aurora-postgresql" {
			return nil, unsupported("EngineLifecycleSupport applies only to Aurora PostgreSQL global clusters.")
		}
		lifecycle = value(in.EngineLifecycleSupport)
		if lifecycle != "open-source-rds-extended-support" && lifecycle != "open-source-rds-extended-support-disabled" {
			return nil, failure("InvalidParameterValue", "Invalid EngineLifecycleSupport value.")
		}
	}
	tags, err := tagsFrom(in.Tags)
	if err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, "CreateGlobalCluster", k.resourceKey(), nil, tags); err != nil {
		return nil, err
	}
	if _, err = tx.GlobalCluster(k); err == nil {
		return nil, failure("GlobalClusterAlreadyExistsFault", "The global cluster identifier is already in use.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	id, err := incarnation()
	if err != nil {
		return nil, err
	}
	v := GlobalCluster{Key: k, ResourceID: "global-" + id, Engine: eng, EngineVersion: version, DatabaseName: database, EngineLifecycleSupport: lifecycle, DeletionProtection: boolean(in.DeletionProtection), StorageEncrypted: boolean(in.StorageEncrypted), Tags: tags}
	if err = tx.PutGlobalCluster(v); err != nil {
		return nil, err
	}
	return &api.CreateGlobalClusterResult{GlobalCluster: new(globalClusterDTO(v))}, nil
}

func (s *Service) describeGlobalClusters(ctx context.Context, tx Transaction, in *api.DescribeGlobalClustersMessage) (*api.GlobalClustersMessage, error) {
	// Both official SDKs share this Query operation and endpoint. These are the
	// documented RDS and DocDB member filters, not invented engine/name aliases.
	if err := validateFilters(in.Filters, "region", "db-cluster-id"); err != nil {
		return nil, err
	}
	start, limit, err := pageStart(ctx, "DescribeGlobalClusters", in.Marker, in.MaxRecords)
	if err != nil {
		return nil, err
	}
	name := ""
	if in.GlobalClusterIdentifier != nil {
		v, err := s.loadGlobalCluster(ctx, tx, "DescribeGlobalClusters", value(in.GlobalClusterIdentifier))
		if err != nil {
			return nil, err
		}
		name = v.Key.Name
	} else if err = s.authorize(ctx, "DescribeGlobalClusters", Key{}, nil, nil); err != nil {
		return nil, err
	}
	all, err := tx.GlobalClusters(globalScopeFor(ctx))
	if err != nil {
		return nil, err
	}
	out := &api.GlobalClustersMessage{GlobalClusters: api.GlobalClusterList{}}
	last := ""
	for _, v := range all {
		if v.Key.Name <= start || name != "" && name != v.Key.Name {
			continue
		}
		// The lifecycle invariant is zero regional members. Neither region nor
		// db-cluster-id can match an unattached namespace, including its creator's
		// Region. This never infers membership from the request Region.
		if len(in.Filters) != 0 {
			continue
		}
		if len(out.GlobalClusters) == limit {
			out.Marker = pageMarker(ctx, "DescribeGlobalClusters", last)
			break
		}
		out.GlobalClusters = append(out.GlobalClusters, globalClusterDTO(v))
		last = v.Key.Name
	}
	return out, nil
}

func (s *Service) modifyGlobalCluster(ctx context.Context, tx Transaction, in *api.ModifyGlobalClusterMessage) (*api.ModifyGlobalClusterResult, error) {
	v, err := s.loadGlobalCluster(ctx, tx, "ModifyGlobalCluster", value(in.GlobalClusterIdentifier))
	if err != nil {
		return nil, err
	}
	if in.EngineVersion != nil || boolean(in.AllowMajorVersionUpgrade) {
		return nil, unsupported("Global engine upgrades require a real replication engine and are not implemented.")
	}
	if in.DeletionProtection != nil {
		v.DeletionProtection = boolean(in.DeletionProtection)
	}
	if in.NewGlobalClusterIdentifier != nil {
		name := value(in.NewGlobalClusterIdentifier)
		if !validName(strings.ToLower(name), 63) {
			return nil, failure("InvalidParameterValue", "Invalid new global cluster identifier.")
		}
		k, err := globalKey(ctx, name)
		if err != nil {
			return nil, err
		}
		if k != v.Key {
			if _, err = tx.GlobalCluster(k); err == nil {
				return nil, failure("GlobalClusterAlreadyExistsFault", "The global cluster identifier is already in use.")
			} else if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			if err = s.authorize(ctx, "ModifyGlobalCluster", k.resourceKey(), v.Tags, nil); err != nil {
				return nil, err
			}
			if err = tx.DeleteGlobalCluster(v.Key); err != nil {
				return nil, err
			}
			v.Key = k
		}
	}
	if err = tx.PutGlobalCluster(v); err != nil {
		return nil, err
	}
	return &api.ModifyGlobalClusterResult{GlobalCluster: new(globalClusterDTO(v))}, nil
}

func (s *Service) deleteGlobalCluster(ctx context.Context, tx Transaction, in *api.DeleteGlobalClusterMessage) (*api.DeleteGlobalClusterResult, error) {
	v, err := s.loadGlobalCluster(ctx, tx, "DeleteGlobalCluster", value(in.GlobalClusterIdentifier))
	if err != nil {
		return nil, err
	}
	if v.DeletionProtection {
		return nil, failure("InvalidGlobalClusterStateFault", "The global cluster has deletion protection enabled.")
	}
	if err = tx.DeleteGlobalCluster(v.Key); err != nil {
		return nil, err
	}
	out := globalClusterDTO(v)
	out.Status = new(api.String("deleting"))
	return &api.DeleteGlobalClusterResult{GlobalCluster: &out}, nil
}

func globalClusterDTO(v GlobalCluster) api.GlobalCluster {
	out := api.GlobalCluster{GlobalClusterIdentifier: new(api.GlobalClusterIdentifier(v.Key.Name)), GlobalClusterArn: new(api.String(v.Key.ARN())), GlobalClusterResourceId: new(api.String(v.ResourceID)), Engine: new(api.String(v.Engine)), EngineVersion: new(api.String(v.EngineVersion)), Status: new(api.String("available")), DeletionProtection: new(api.BooleanOptional(v.DeletionProtection)), StorageEncrypted: new(api.BooleanOptional(v.StorageEncrypted)), GlobalClusterMembers: api.GlobalClusterMemberList{}, TagList: tagList(v.Tags)}
	if v.DatabaseName != "" {
		out.DatabaseName = new(api.String(v.DatabaseName))
	}
	if v.EngineLifecycleSupport != "" {
		out.EngineLifecycleSupport = new(api.String(v.EngineLifecycleSupport))
	}
	return out
}

func (s *Service) rejectGlobalMemberChange(ctx context.Context, tx Reader, action, name string) error {
	if _, err := s.loadGlobalCluster(ctx, tx, action, name); err != nil {
		return err
	}
	return unsupported("Global membership, replication, failover and switchover require a real replication engine and are not implemented.")
}

func (s *Service) removeFromGlobalCluster(ctx context.Context, tx Transaction, in *api.RemoveFromGlobalClusterMessage) (*api.RemoveFromGlobalClusterResult, error) {
	return nil, s.rejectGlobalMemberChange(ctx, tx, "RemoveFromGlobalCluster", value(in.GlobalClusterIdentifier))
}

func (s *Service) failoverGlobalCluster(ctx context.Context, tx Transaction, in *api.FailoverGlobalClusterMessage) (*api.FailoverGlobalClusterResult, error) {
	return nil, s.rejectGlobalMemberChange(ctx, tx, "FailoverGlobalCluster", value(in.GlobalClusterIdentifier))
}

func (s *Service) switchoverGlobalCluster(ctx context.Context, tx Transaction, in *api.SwitchoverGlobalClusterMessage) (*api.SwitchoverGlobalClusterResult, error) {
	return nil, s.rejectGlobalMemberChange(ctx, tx, "SwitchoverGlobalCluster", value(in.GlobalClusterIdentifier))
}
