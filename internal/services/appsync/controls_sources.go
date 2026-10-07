package appsync

import (
	"context"
	"net/url"
	"regexp"
	api "stackd/internal/awsapi/appsync"
	"strings"
)

var resourceName = regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]*$`)

func registerDataSources(s *Service) {
	register(s, "CreateDataSource", func(ctx context.Context, t Transaction, in *api.CreateDataSourceRequest) (*api.CreateDataSourceResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "CreateDataSource")
		if e != nil {
			return nil, e
		}
		all, e := t.DataSources(p.Key)
		if e != nil {
			return nil, e
		}
		for _, d := range all {
			if value(d.DataSource.Name) == value(in.Name) {
				return nil, bad("A data source with this name already exists.")
			}
		}
		d := api.DataSource{Name: in.Name, Type: in.Type, Description: in.Description, ServiceRoleArn: in.ServiceRoleArn, DynamodbConfig: in.DynamodbConfig, LambdaConfig: in.LambdaConfig, HttpConfig: in.HttpConfig, RelationalDatabaseConfig: in.RelationalDatabaseConfig, ElasticsearchConfig: in.ElasticsearchConfig, OpenSearchServiceConfig: in.OpenSearchServiceConfig, EventBridgeConfig: in.EventBridgeConfig, MetricsConfig: in.MetricsConfig}
		if e = s.validateDataSource(ctx, p.Key, d); e != nil {
			return nil, e
		}
		text(&d.DataSourceArn, p.Key.ARN()+"/datasources/"+value(d.Name))
		if e = t.PutDataSource(DataSourceRecord{API: p.Key, DataSource: d}); e != nil {
			return nil, e
		}
		return &api.CreateDataSourceResponse{DataSource: &d}, nil
	})
	register(s, "UpdateDataSource", func(ctx context.Context, t Transaction, in *api.UpdateDataSourceRequest) (*api.UpdateDataSourceResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "UpdateDataSource")
		if e != nil {
			return nil, e
		}
		if _, e = findDataSource(t, p.Key, value(in.Name)); e != nil {
			return nil, e
		}
		d := api.DataSource{Name: in.Name, Type: in.Type, Description: in.Description, ServiceRoleArn: in.ServiceRoleArn, DynamodbConfig: in.DynamodbConfig, LambdaConfig: in.LambdaConfig, HttpConfig: in.HttpConfig, RelationalDatabaseConfig: in.RelationalDatabaseConfig, ElasticsearchConfig: in.ElasticsearchConfig, OpenSearchServiceConfig: in.OpenSearchServiceConfig, EventBridgeConfig: in.EventBridgeConfig, MetricsConfig: in.MetricsConfig}
		if e = s.validateDataSource(ctx, p.Key, d); e != nil {
			return nil, e
		}
		rs, e := t.Resolvers(p.Key)
		if e != nil {
			return nil, e
		}
		for _, r := range rs {
			if value(r.Resolver.DataSourceName) == value(d.Name) && r.Resolver.Runtime == nil && value(d.Type) != "AWS_LAMBDA" {
				return nil, bad("Direct Lambda resolvers require a Lambda data source.")
			}
		}
		text(&d.DataSourceArn, p.Key.ARN()+"/datasources/"+value(d.Name))
		if e = t.PutDataSource(DataSourceRecord{API: p.Key, DataSource: d}); e != nil {
			return nil, e
		}
		return &api.UpdateDataSourceResponse{DataSource: &d}, nil
	})
	register(s, "GetDataSource", func(ctx context.Context, t Transaction, in *api.GetDataSourceRequest) (*api.GetDataSourceResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "GetDataSource")
		if e != nil {
			return nil, e
		}
		d, e := findDataSource(t, p.Key, value(in.Name))
		if e != nil {
			return nil, e
		}
		return &api.GetDataSourceResponse{DataSource: &d}, nil
	})
	register(s, "DeleteDataSource", func(ctx context.Context, t Transaction, in *api.DeleteDataSourceRequest) (*api.DeleteDataSourceResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "DeleteDataSource")
		if e != nil {
			return nil, e
		}
		rs, e := t.Resolvers(p.Key)
		if e != nil {
			return nil, e
		}
		for _, r := range rs {
			if value(r.Resolver.DataSourceName) == value(in.Name) {
				return nil, bad("Data source is referenced by a resolver.")
			}
		}
		fs, e := t.Functions(p.Key)
		if e != nil {
			return nil, e
		}
		for _, f := range fs {
			if value(f.Function.DataSourceName) == value(in.Name) {
				return nil, bad("Data source is referenced by a function.")
			}
		}
		return &api.DeleteDataSourceResponse{}, t.DeleteDataSource(p.Key, value(in.Name))
	})
	register(s, "ListDataSources", func(ctx context.Context, t Transaction, in *api.ListDataSourcesRequest) (*api.ListDataSourcesResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "ListDataSources")
		if e != nil {
			return nil, e
		}
		all, e := t.DataSources(p.Key)
		if e != nil {
			return nil, e
		}
		out := api.DataSources{}
		for _, d := range all {
			out = append(out, d.DataSource)
		}
		out, next, e := page(out, in.NextToken, in.MaxResults, p.Key.ARN()+"/ListDataSources", func(d api.DataSource) string { return value(d.Name) })
		return &api.ListDataSourcesResponse{DataSources: out, NextToken: next}, e
	})
}
func findDataSource(r Reader, k Key, name string) (api.DataSource, error) {
	all, e := r.DataSources(k)
	if e != nil {
		return api.DataSource{}, e
	}
	for _, d := range all {
		if value(d.DataSource.Name) == name {
			return d.DataSource, nil
		}
	}
	return api.DataSource{}, ErrNotFound
}
func (s *Service) validateDataSource(ctx context.Context, k Key, d api.DataSource) error {
	if !resourceName.MatchString(value(d.Name)) {
		return bad("Invalid data source name.")
	}
	if d.MetricsConfig != nil && value(d.MetricsConfig) != "DISABLED" {
		return unsupported("Data source metrics are not implemented.")
	}
	if d.ElasticsearchConfig != nil || d.OpenSearchServiceConfig != nil || d.EventBridgeConfig != nil {
		return unsupported("OpenSearch and EventBridge data sources are not implemented.")
	}
	kind := value(d.Type)
	configs := 0
	if d.LambdaConfig != nil {
		configs++
	}
	if d.DynamodbConfig != nil {
		configs++
	}
	if d.HttpConfig != nil {
		configs++
	}
	if d.RelationalDatabaseConfig != nil {
		configs++
	}
	if kind == "NONE" {
		if configs != 0 || value(d.ServiceRoleArn) != "" {
			return bad("NONE data sources cannot have external configuration.")
		}
		return nil
	}
	if configs != 1 {
		return bad("Exactly one matching data source configuration is required.")
	}
	switch kind {
	case "AWS_LAMBDA":
		if d.LambdaConfig == nil {
			return bad("lambdaConfig is required.")
		}
		arn := strings.SplitN(value(d.LambdaConfig.LambdaFunctionArn), ":", 7)
		if len(arn) < 7 || arn[0] != "arn" || arn[1] != k.Partition || arn[2] != "lambda" || arn[3] == "" || arn[4] == "" || arn[5] != "function" || arn[6] == "" {
			return bad("Invalid Lambda function ARN.")
		}
	case "AMAZON_DYNAMODB":
		if d.DynamodbConfig == nil || value(d.DynamodbConfig.TableName) == "" || value(d.DynamodbConfig.AwsRegion) == "" {
			return bad("DynamoDB table and region are required.")
		}
		if d.DynamodbConfig.DeltaSyncConfig != nil || boolValue(d.DynamodbConfig.Versioned) || boolValue(d.DynamodbConfig.UseCallerCredentials) {
			return unsupported("DynamoDB versioning, delta sync and caller credentials are not implemented.")
		}
	case "HTTP":
		if d.HttpConfig == nil {
			return bad("httpConfig is required.")
		}
		u, e := url.Parse(value(d.HttpConfig.Endpoint))
		if e != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" {
			return bad("HTTP endpoint must be an HTTP(S) URL without credentials or fragment.")
		}
		if d.HttpConfig.AuthorizationConfig != nil {
			return unsupported("HTTP IAM signing is not implemented.")
		}
		if value(d.ServiceRoleArn) != "" {
			return bad("An unsigned HTTP data source does not use serviceRoleArn.")
		}
		return nil
	case "RELATIONAL_DATABASE":
		if d.RelationalDatabaseConfig == nil || value(d.RelationalDatabaseConfig.RelationalDatabaseSourceType) != "RDS_HTTP_ENDPOINT" || d.RelationalDatabaseConfig.RdsHttpEndpointConfig == nil {
			return unsupported("Only RDS_HTTP_ENDPOINT relational data sources are implemented.")
		}
		c := d.RelationalDatabaseConfig.RdsHttpEndpointConfig
		if value(c.AwsRegion) == "" || value(c.DbClusterIdentifier) == "" || value(c.AwsSecretStoreArn) == "" {
			return bad("RDS region, cluster identifier and secret ARN are required.")
		}
		if value(c.Schema) != "" {
			return unsupported("RDS Data schema selection is not implemented.")
		}
	default:
		return unsupported("Data source type " + kind + " is not implemented.")
	}
	return s.passRole(ctx, k, value(d.ServiceRoleArn))
}
