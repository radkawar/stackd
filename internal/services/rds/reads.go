package rds

import (
	"context"
	"encoding/base64"
	"maps"
	"strings"

	api "stackd/internal/awsapi/rds"
)

func pageStart(ctx context.Context, action string, marker *api.String, max *api.IntegerOptional) (string, int, error) {
	limit := 100
	if max != nil {

		limit = int(*max)
		if limit < 20 || limit > 100 {
			return "", 0, failure("InvalidParameterValue", "MaxRecords must be between 20 and 100.")
		}

	}
	if marker == nil {
		return "", limit, nil
	}
	decoded, e := base64.RawURLEncoding.DecodeString(string(*marker))
	prefix := pagePrefix(ctx, action)
	if e != nil || !strings.HasPrefix(string(decoded), prefix) {
		return "", 0, failure("InvalidParameterValue", "Invalid pagination marker.")
	}
	return strings.TrimPrefix(string(decoded), prefix), limit, nil
}

func pagePrefix(ctx context.Context, action string) string {
	sc := scopeFor(ctx)
	return sc.Partition + "/" + sc.AccountID + "/" + sc.Region + "/" + action + "/"
}

func pageMarker(ctx context.Context, action, last string) *api.String {
	return new(api.String(base64.RawURLEncoding.EncodeToString([]byte(pagePrefix(ctx, action) + last))))
}

func validateFilters(filters api.FilterList, allowed ...string) error {
	for _, f := range filters {

		ok := false
		for _, a := range allowed {
			if value(f.Name) == a {

				ok = true
				break

			}
		}
		if !ok {
			return unsupported("The requested filter is not supported.")
		}
		if len(f.Values) == 0 {
			return failure("InvalidParameterValue", "Filter values must not be empty.")
		}

	}
	return nil
}

func filterMatches(filters api.FilterList, values map[string]string) bool {
	for _, f := range filters {

		found := false
		for _, v := range f.Values {
			if values[value(f.Name)] == string(v) {

				found = true
				break

			}
		}
		if !found {
			return false
		}

	}
	return true
}

func (s *Service) describeInstances(ctx context.Context, tx Transaction, in *api.DescribeDBInstancesMessage) (*api.DBInstanceMessage, error) {
	if e := validateFilters(in.Filters, "db-instance-id", "db-cluster-id", "engine"); e != nil {
		return nil, e
	}
	start, limit, e := pageStart(ctx, "DescribeDBInstances", in.Marker, in.MaxRecords)
	if e != nil {
		return nil, e
	}
	name := ""
	if in.DBInstanceIdentifier != nil {

		k, e := resourceKey(ctx, "db", value(in.DBInstanceIdentifier))
		if e != nil {
			return nil, e
		}
		name = k.Name
		if _, e = s.loadDatabase(ctx, tx, "DescribeDBInstances", "db", value(in.DBInstanceIdentifier)); e != nil {
			return nil, e
		}

	} else if e = s.authorize(ctx, "DescribeDBInstances", Key{}, nil, nil); e != nil {
		return nil, e
	}
	dbs, e := s.queryDatabases(ctx, tx)
	if e != nil {
		return nil, e
	}
	out := &api.DBInstanceMessage{DBInstances: api.DBInstanceList{}}
	last := ""
	for _, v := range dbs {

		if v.Key.Kind != "db" || v.Key.Name <= start || name != "" && v.Key.Name != name || !filterMatches(in.Filters, map[string]string{"db-instance-id": v.Key.Name, "db-cluster-id": v.Cluster, "engine": v.Engine}) {
			continue
		}
		if len(out.DBInstances) == limit {

			out.Marker = pageMarker(ctx, "DescribeDBInstances", last)
			break

		}
		out.DBInstances = append(out.DBInstances, instanceDTO(v))
		last = v.Key.Name

	}
	return out, nil
}

func (s *Service) describeClusters(ctx context.Context, tx Transaction, in *api.DescribeDBClustersMessage) (*api.DBClusterMessage, error) {
	if boolean(in.IncludeShared) {
		return nil, unsupported("Shared clusters are not implemented.")
	}
	if e := validateFilters(in.Filters, "db-cluster-id", "engine"); e != nil {
		return nil, e
	}
	start, limit, e := pageStart(ctx, "DescribeDBClusters", in.Marker, in.MaxRecords)
	if e != nil {
		return nil, e
	}
	name := ""
	if in.DBClusterIdentifier != nil {

		k, e := resourceKey(ctx, "cluster", value(in.DBClusterIdentifier))
		if e != nil {
			return nil, e
		}
		name = k.Name
		if _, e = s.loadDatabase(ctx, tx, "DescribeDBClusters", "cluster", value(in.DBClusterIdentifier)); e != nil {
			return nil, e
		}

	} else if e = s.authorize(ctx, "DescribeDBClusters", Key{}, nil, nil); e != nil {
		return nil, e
	}
	dbs, e := s.queryDatabases(ctx, tx)
	if e != nil {
		return nil, e
	}
	out := &api.DBClusterMessage{DBClusters: api.DBClusterList{}}
	last := ""
	for _, v := range dbs {

		if v.Key.Kind != "cluster" || v.Key.Name <= start || name != "" && v.Key.Name != name || !filterMatches(in.Filters, map[string]string{"db-cluster-id": v.Key.Name, "engine": v.Engine}) {
			continue
		}
		if len(out.DBClusters) == limit {

			out.Marker = pageMarker(ctx, "DescribeDBClusters", last)
			break

		}
		out.DBClusters = append(out.DBClusters, clusterDTO(v, dbs))
		last = v.Key.Name

	}
	return out, nil
}

func (s *Service) describeEngineVersions(ctx context.Context, tx Transaction, in *api.DescribeDBEngineVersionsMessage) (*api.DBEngineVersionMessage, error) {
	if boolean(in.ListSupportedCharacterSets) || boolean(in.ListSupportedTimezones) {
		return nil, unsupported("Character-set and timezone catalog enumeration is not implemented.")
	}
	if e := validateFilters(in.Filters, "engine", "engine-version", "db-parameter-group-family"); e != nil {
		return nil, e
	}
	start, limit, e := pageStart(ctx, "DescribeDBEngineVersions", in.Marker, in.MaxRecords)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "DescribeDBEngineVersions", Key{}, nil, nil); e != nil {
		return nil, e
	}
	out := &api.DBEngineVersionMessage{DBEngineVersions: api.DBEngineVersionList{}}
	last := ""
	for _, eng := range []string{"aurora-mysql", "aurora-postgresql", "mysql", "postgres"} {

		version, family := engineVersion(eng), engineFamily(eng)
		if eng <= start || value(in.Engine) != "" && value(in.Engine) != eng || value(in.EngineVersion) != "" && value(in.EngineVersion) != version || value(in.DBParameterGroupFamily) != "" && value(in.DBParameterGroupFamily) != family || !filterMatches(in.Filters, map[string]string{"engine": eng, "engine-version": version, "db-parameter-group-family": family}) {
			continue
		}
		if len(out.DBEngineVersions) == limit {

			out.Marker = pageMarker(ctx, "DescribeDBEngineVersions", last)
			break

		}
		out.DBEngineVersions = append(out.DBEngineVersions, api.DBEngineVersion{Engine: new(api.String(eng)), EngineVersion: new(api.String(version)), DBParameterGroupFamily: new(api.String(family)), Status: new(api.String("available")), SupportsReadReplica: new(api.Boolean(false))})
		last = eng

	}
	return out, nil
}

func (s *Service) setHTTP(ctx context.Context, tx Transaction, arn string, enabled bool) (Database, error) {
	action := "DisableHttpEndpoint"
	if enabled {
		action = "EnableHttpEndpoint"
	}
	if !strings.HasPrefix(arn, "arn:") {
		return Database{}, failure("InvalidParameterValue", "ResourceArn must be a cluster ARN.")
	}
	v, e := s.loadDatabase(ctx, tx, action, "cluster", arn)
	if e != nil {
		return v, e
	}
	if v.Status == "deleting" {
		return v, stateError("cluster")
	}
	v.HTTPEnabled = enabled
	v.Version++
	return v, tx.PutDatabase(v)
}

func (s *Service) enableHTTP(ctx context.Context, tx Transaction, in *api.EnableHttpEndpointRequest) (*api.EnableHttpEndpointResponse, error) {
	v, e := s.setHTTP(ctx, tx, value(in.ResourceArn), true)
	if e != nil {
		return nil, e
	}
	return &api.EnableHttpEndpointResponse{ResourceArn: new(api.String(v.Key.ARN())), HttpEndpointEnabled: new(api.Boolean(true))}, nil
}

func (s *Service) disableHTTP(ctx context.Context, tx Transaction, in *api.DisableHttpEndpointRequest) (*api.DisableHttpEndpointResponse, error) {
	v, e := s.setHTTP(ctx, tx, value(in.ResourceArn), false)
	if e != nil {
		return nil, e
	}
	return &api.DisableHttpEndpointResponse{ResourceArn: new(api.String(v.Key.ARN())), HttpEndpointEnabled: new(api.Boolean(false))}, nil
}

// ResolveDataCluster does not borrow DescribeDBClusters authority. Data API
// independently authorizes this exact scoped cluster, including current tags.
func (s *Service) ResolveDataCluster(ctx context.Context, arn string) (DataCluster, error) {
	if !strings.HasPrefix(arn, "arn:") {
		return DataCluster{}, notFound("cluster")
	}
	k, e := resourceKey(ctx, "cluster", arn)
	if e != nil || k.ARN() != arn {

		if e != nil {
			return DataCluster{}, e
		}
		return DataCluster{}, notFound("cluster")

	}
	var v Database
	e = s.repository.View(ctx, func(r Reader) error {
		var e error
		v, e = r.Database(k)
		return e
	})
	if e != nil {
		return DataCluster{}, notFound("cluster")
	}
	if e = s.observeDatabase(ctx, v); e != nil {
		return DataCluster{}, e
	}
	var out DataCluster
	e = s.repository.View(ctx, func(r Reader) error {
		v, e := r.Database(k)
		if e != nil {
			return e
		}
		members, e := r.Databases(k.Scope)
		if e != nil {
			return e
		}
		out = DataCluster{ARN: v.Key.ARN(), Engine: v.Engine, Database: v.DatabaseName, Status: v.Status, HTTPEnabled: v.HTTPEnabled, Tags: maps.Clone(v.Tags)}
		for _, m := range members {
			if m.Cluster == v.Key.Name && m.Status == "available" && v.Status == "available" {

				out.Endpoint = v.Endpoint
				break

			}
		}
		if out.Endpoint.Address == "" && out.Status == "available" {
			out.Status = "creating"
		}
		return nil
	})
	return out, e
}
