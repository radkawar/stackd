package appsync

import (
	api "stackd/internal/awsapi/appsync"
	domain "stackd/storage/appsync"
	"stackd/storage/sqlite/appsync/internal/sqlcgen"
)

func (r reader) DataSources(k domain.Key) ([]domain.DataSourceRecord, error) {
	if _, e := r.API(k); e != nil {
		return nil, e
	}
	rows, e := r.q.ListDataSource(r.ctx, k.ID)
	if e != nil {
		return nil, e
	}
	out := make([]domain.DataSourceRecord, 0, len(rows))
	for _, v := range rows {
		d := api.DataSource{}
		text(&d.Name, v.Name)
		text(&d.DataSourceArn, v.Arn)
		text(&d.Type, v.Kind)
		readString(&d.Description, v.Description)
		readString(&d.ServiceRoleArn, v.RoleArn)
		readString(&d.MetricsConfig, v.Metrics)
		if v.LambdaArn.Valid {
			d.LambdaConfig = &api.LambdaDataSourceConfig{}
			readString(&d.LambdaConfig.LambdaFunctionArn, v.LambdaArn)
		}
		if v.DdbTable.Valid {
			d.DynamodbConfig = &api.DynamodbDataSourceConfig{}
			readString(&d.DynamodbConfig.AwsRegion, v.DdbRegion)
			readString(&d.DynamodbConfig.TableName, v.DdbTable)
			readBoolean(&d.DynamodbConfig.UseCallerCredentials, v.DdbCaller)
			readBoolean(&d.DynamodbConfig.Versioned, v.DdbVersioned)
		}
		if v.HttpEndpoint.Valid {
			d.HttpConfig = &api.HttpDataSourceConfig{}
			readString(&d.HttpConfig.Endpoint, v.HttpEndpoint)
		}
		if v.RdsType.Valid {
			c := &api.RdsHttpEndpointConfig{}
			d.RelationalDatabaseConfig = &api.RelationalDatabaseDataSourceConfig{RdsHttpEndpointConfig: c}
			readString(&d.RelationalDatabaseConfig.RelationalDatabaseSourceType, v.RdsType)
			readString(&c.AwsRegion, v.RdsRegion)
			readString(&c.AwsSecretStoreArn, v.RdsSecret)
			readString(&c.DatabaseName, v.RdsDatabase)
			readString(&c.DbClusterIdentifier, v.RdsCluster)
			readString(&c.Schema, v.RdsSchema)
		}
		out = append(out, domain.DataSourceRecord{API: k, DataSource: d, Ownership: v.Ownership})
	}
	return out, nil
}
func (r writer) PutDataSource(p domain.DataSourceRecord) error {
	if _, e := r.API(p.API); e != nil {
		return e
	}
	d := p.DataSource
	v := sqlcgen.PutDataSourceParams{ApiID: p.API.ID, Name: val(d.Name), Arn: val(d.DataSourceArn), Kind: val(d.Type), Description: str(d.Description), RoleArn: str(d.ServiceRoleArn), Metrics: str(d.MetricsConfig)}
	v.Ownership = p.Ownership
	if d.LambdaConfig != nil {
		v.LambdaArn = str(d.LambdaConfig.LambdaFunctionArn)
	}
	if d.DynamodbConfig != nil {
		v.DdbRegion = str(d.DynamodbConfig.AwsRegion)
		v.DdbTable = str(d.DynamodbConfig.TableName)
		v.DdbCaller = boolean(d.DynamodbConfig.UseCallerCredentials)
		v.DdbVersioned = boolean(d.DynamodbConfig.Versioned)
	}
	if d.HttpConfig != nil {
		v.HttpEndpoint = str(d.HttpConfig.Endpoint)
	}
	if d.RelationalDatabaseConfig != nil {
		v.RdsType = str(d.RelationalDatabaseConfig.RelationalDatabaseSourceType)
		if c := d.RelationalDatabaseConfig.RdsHttpEndpointConfig; c != nil {
			v.RdsRegion = str(c.AwsRegion)
			v.RdsSecret = str(c.AwsSecretStoreArn)
			v.RdsDatabase = str(c.DatabaseName)
			v.RdsCluster = str(c.DbClusterIdentifier)
			v.RdsSchema = str(c.Schema)
		}
	}
	return r.q.PutDataSource(r.ctx, v)
}
func (r reader) Functions(k domain.Key) ([]domain.FunctionRecord, error) {
	if _, e := r.API(k); e != nil {
		return nil, e
	}
	rows, e := r.q.ListFunction(r.ctx, k.ID)
	if e != nil {
		return nil, e
	}
	out := make([]domain.FunctionRecord, 0, len(rows))
	for _, v := range rows {
		f := api.FunctionConfiguration{}
		text(&f.FunctionId, v.FunctionID)
		text(&f.FunctionArn, v.Arn)
		text(&f.Name, v.Name)
		text(&f.DataSourceName, v.SourceName)
		readString(&f.Description, v.Description)
		readString(&f.Code, v.Code)
		readString(&f.FunctionVersion, v.FunctionVersion)
		readString(&f.RequestMappingTemplate, v.RequestTemplate)
		readString(&f.ResponseMappingTemplate, v.ResponseTemplate)
		readNumber(&f.MaxBatchSize, v.MaxBatchSize)
		if v.RuntimeName.Valid {
			f.Runtime = &api.AppSyncRuntime{}
			readString(&f.Runtime.Name, v.RuntimeName)
			readString(&f.Runtime.RuntimeVersion, v.RuntimeVersion)
		}
		out = append(out, domain.FunctionRecord{API: k, Function: f, Ownership: v.Ownership})
	}
	return out, nil
}
func (r writer) PutFunction(p domain.FunctionRecord) error {
	if _, e := r.API(p.API); e != nil {
		return e
	}
	if e := domain.CheckFunctionReferences(r, p); e != nil {
		return e
	}
	f := p.Function
	v := sqlcgen.PutFunctionParams{ApiID: p.API.ID, FunctionID: val(f.FunctionId), Arn: val(f.FunctionArn), Name: val(f.Name), SourceName: val(f.DataSourceName), Description: str(f.Description), Code: str(f.Code), FunctionVersion: str(f.FunctionVersion), RequestTemplate: str(f.RequestMappingTemplate), ResponseTemplate: str(f.ResponseMappingTemplate), MaxBatchSize: number(f.MaxBatchSize)}
	v.Ownership = p.Ownership
	if f.Runtime != nil {
		v.RuntimeName = str(f.Runtime.Name)
		v.RuntimeVersion = str(f.Runtime.RuntimeVersion)
	}
	return r.q.PutFunction(r.ctx, v)
}
func (r reader) Resolvers(k domain.Key) ([]domain.ResolverRecord, error) {
	if _, e := r.API(k); e != nil {
		return nil, e
	}
	rows, e := r.q.ListResolver(r.ctx, k.ID)
	if e != nil {
		return nil, e
	}
	pipeline, e := r.q.ListPipeline(r.ctx, k.ID)
	if e != nil {
		return nil, e
	}
	byField := map[[2]string]api.FunctionsIds{}
	for _, f := range pipeline {
		key := [2]string{f.TypeName, f.FieldName}
		byField[key] = append(byField[key], api.String(f.FunctionID))
	}
	out := make([]domain.ResolverRecord, 0, len(rows))
	for _, v := range rows {
		x := api.Resolver{}
		text(&x.TypeName, v.TypeName)
		text(&x.FieldName, v.FieldName)
		text(&x.ResolverArn, v.Arn)
		text(&x.Kind, v.Kind)
		readString(&x.DataSourceName, v.SourceName)
		readString(&x.Code, v.Code)
		readString(&x.RequestMappingTemplate, v.RequestTemplate)
		readString(&x.ResponseMappingTemplate, v.ResponseTemplate)
		readNumber(&x.MaxBatchSize, v.MaxBatchSize)
		readString(&x.MetricsConfig, v.Metrics)
		if v.RuntimeName.Valid {
			x.Runtime = &api.AppSyncRuntime{}
			readString(&x.Runtime.Name, v.RuntimeName)
			readString(&x.Runtime.RuntimeVersion, v.RuntimeVersion)
		}
		if v.Kind == "PIPELINE" {
			x.PipelineConfig = &api.PipelineConfig{Functions: byField[[2]string{v.TypeName, v.FieldName}]}
		}
		out = append(out, domain.ResolverRecord{API: k, Resolver: x, Ownership: v.Ownership})
	}
	return out, nil
}
func (r writer) PutResolver(p domain.ResolverRecord) error {
	if _, e := r.API(p.API); e != nil {
		return e
	}
	if e := domain.CheckResolverReferences(r, p); e != nil {
		return e
	}
	x := p.Resolver
	v := sqlcgen.PutResolverParams{ApiID: p.API.ID, TypeName: val(x.TypeName), FieldName: val(x.FieldName), Arn: val(x.ResolverArn), Kind: val(x.Kind), SourceName: str(x.DataSourceName), Code: str(x.Code), RequestTemplate: str(x.RequestMappingTemplate), ResponseTemplate: str(x.ResponseMappingTemplate), MaxBatchSize: number(x.MaxBatchSize), Metrics: str(x.MetricsConfig)}
	v.Ownership = p.Ownership
	if x.Runtime != nil {
		v.RuntimeName = str(x.Runtime.Name)
		v.RuntimeVersion = str(x.Runtime.RuntimeVersion)
	}
	if e := r.q.PutResolver(r.ctx, v); e != nil {
		return e
	}
	if e := r.q.ClearPipeline(r.ctx, sqlcgen.ClearPipelineParams{ApiID: p.API.ID, TypeName: v.TypeName, FieldName: v.FieldName}); e != nil {
		return e
	}
	if x.PipelineConfig != nil {
		for i, id := range x.PipelineConfig.Functions {
			if e := r.q.PutPipeline(r.ctx, sqlcgen.PutPipelineParams{ApiID: p.API.ID, TypeName: v.TypeName, FieldName: v.FieldName, Ordinal: int64(i), FunctionID: string(id)}); e != nil {
				return e
			}
		}
	}
	return nil
}
func (r reader) APIKeys(k domain.Key) ([]domain.APIKeyRecord, error) {
	if _, e := r.API(k); e != nil {
		return nil, e
	}
	rows, e := r.q.ListAPIKey(r.ctx, k.ID)
	if e != nil {
		return nil, e
	}
	out := make([]domain.APIKeyRecord, 0, len(rows))
	for _, v := range rows {
		key := api.ApiKey{}
		text(&key.Id, v.KeyID)
		readString(&key.Description, v.Description)
		expires, deletes := api.Long(v.Expires), api.Long(v.Deletes)
		key.Expires = &expires
		key.Deletes = &deletes
		out = append(out, domain.APIKeyRecord{API: k, Key: key, Ownership: v.Ownership})
	}
	return out, nil
}
func (r writer) PutAPIKey(p domain.APIKeyRecord) error {
	if _, e := r.API(p.API); e != nil {
		return e
	}
	return r.q.PutAPIKey(r.ctx, sqlcgen.PutAPIKeyParams{ApiID: p.API.ID, KeyID: val(p.Key.Id), Description: str(p.Key.Description), Expires: number(p.Key.Expires).Int64, Deletes: number(p.Key.Deletes).Int64, Ownership: p.Ownership})
}
