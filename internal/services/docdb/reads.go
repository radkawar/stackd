package docdb

import (
	"context"
	api "stackd/internal/awsapi/docdb"
)

func (s *Service) describeClusters(ctx context.Context, tx Transaction, in *api.DescribeDBClustersInput) (*api.DescribeDBClustersOutput, error) {
	if len(in.Filters) > 0 {
		return nil, unsupported("DocumentDB cluster filters are not implemented.")
	}
	out := &api.DescribeDBClustersOutput{}
	if in.DBClusterIdentifier != nil {
		v, e := s.loadCluster(ctx, tx, "DescribeDBClusters", value(in.DBClusterIdentifier))
		if e != nil {
			return nil, e
		}
		item, e := clusterOutput(tx, v)
		if e != nil {
			return nil, e
		}
		out.DBClusters = append(out.DBClusters, *item)
		return out, nil
	}
	sc := scopeFor(ctx)
	if e := s.authorize(ctx, "DescribeDBClusters", Key{Scope: sc}, nil, nil); e != nil {
		return nil, e
	}
	after, limit, e := page(value(in.Marker), in.MaxRecords, sc, "cluster")
	if e != nil {
		return nil, e
	}
	all, e := tx.Clusters()
	if e != nil {
		return nil, e
	}
	var previous Key
	for _, v := range all {
		if v.Key.Scope != sc || v.Key.Name <= after {
			continue
		}
		if len(out.DBClusters) == limit {
			out.Marker = markerFor(previous)
			break
		}
		item, e := clusterOutput(tx, v)
		if e != nil {
			return nil, e
		}
		out.DBClusters = append(out.DBClusters, *item)
		previous = v.Key
	}
	return out, nil
}
func (s *Service) describeInstances(ctx context.Context, tx Transaction, in *api.DescribeDBInstancesInput) (*api.DescribeDBInstancesOutput, error) {
	if len(in.Filters) > 0 {
		return nil, unsupported("DocumentDB instance filters are not implemented.")
	}
	out := &api.DescribeDBInstancesOutput{}
	if in.DBInstanceIdentifier != nil {
		v, e := s.loadInstance(ctx, tx, "DescribeDBInstances", value(in.DBInstanceIdentifier))
		if e != nil {
			return nil, e
		}
		c, e := tx.Cluster(Key{Scope: v.Key.Scope, Kind: "cluster", Name: v.Cluster})
		if e != nil {
			return nil, e
		}
		out.DBInstances = append(out.DBInstances, *instanceOutput(v, c))
		return out, nil
	}
	sc := scopeFor(ctx)
	if e := s.authorize(ctx, "DescribeDBInstances", Key{Scope: sc}, nil, nil); e != nil {
		return nil, e
	}
	after, limit, e := page(value(in.Marker), in.MaxRecords, sc, "db")
	if e != nil {
		return nil, e
	}
	all, e := tx.Instances()
	if e != nil {
		return nil, e
	}
	var previous Key
	for _, v := range all {
		if v.Key.Scope != sc || v.Key.Name <= after {
			continue
		}
		if len(out.DBInstances) == limit {
			out.Marker = markerFor(previous)
			break
		}
		c, e := tx.Cluster(Key{Scope: v.Key.Scope, Kind: "cluster", Name: v.Cluster})
		if e != nil {
			return nil, e
		}
		out.DBInstances = append(out.DBInstances, *instanceOutput(v, c))
		previous = v.Key
	}
	return out, nil
}
func (s *Service) describeSnapshots(ctx context.Context, tx Transaction, in *api.DescribeDBClusterSnapshotsInput) (*api.DescribeDBClusterSnapshotsOutput, error) {
	if len(in.Filters) > 0 || yes(in.IncludePublic) || yes(in.IncludeShared) || in.SnapshotType != nil && value(in.SnapshotType) != "manual" {
		return nil, unsupported("Only owned manual DocumentDB snapshots are implemented.")
	}
	out := &api.DescribeDBClusterSnapshotsOutput{}
	if in.DBClusterSnapshotIdentifier != nil {
		v, e := s.loadSnapshot(ctx, tx, "DescribeDBClusterSnapshots", value(in.DBClusterSnapshotIdentifier))
		if e != nil {
			return nil, e
		}
		out.DBClusterSnapshots = append(out.DBClusterSnapshots, *snapshotOutput(v))
		return out, nil
	}
	sc := scopeFor(ctx)
	if e := s.authorize(ctx, "DescribeDBClusterSnapshots", Key{Scope: sc}, nil, nil); e != nil {
		return nil, e
	}
	after, limit, e := page(value(in.Marker), in.MaxRecords, sc, "cluster-snapshot")
	if e != nil {
		return nil, e
	}
	source := ""
	if in.DBClusterIdentifier != nil {
		k, e := resourceKey(ctx, "cluster", value(in.DBClusterIdentifier))
		if e != nil {
			return nil, e
		}
		source = k.Name
	}
	all, e := tx.Snapshots()
	if e != nil {
		return nil, e
	}
	var previous Key
	for _, v := range all {
		if v.Key.Scope != sc || v.Key.Name <= after || source != "" && v.Source != source {
			continue
		}
		if len(out.DBClusterSnapshots) == limit {
			out.Marker = markerFor(previous)
			break
		}
		out.DBClusterSnapshots = append(out.DBClusterSnapshots, *snapshotOutput(v))
		previous = v.Key
	}
	return out, nil
}
