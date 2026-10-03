package appsync

import (
	"context"
	api "stackd/internal/awsapi/appsync"
)

func registerResolvers(s *Service) {
	register(s, "CreateResolver", func(ctx context.Context, t Transaction, in *api.CreateResolverRequest) (*api.CreateResolverResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "CreateResolver")
		if e != nil {
			return nil, e
		}
		all, e := t.Resolvers(p.Key)
		if e != nil {
			return nil, e
		}
		for _, r := range all {
			if value(r.Resolver.TypeName) == value(in.TypeName) && value(r.Resolver.FieldName) == value(in.FieldName) {
				return nil, bad("A resolver is already attached to this field.")
			}
		}
		r := api.Resolver{TypeName: in.TypeName, FieldName: in.FieldName, Kind: in.Kind, DataSourceName: in.DataSourceName, Code: in.Code, Runtime: in.Runtime, PipelineConfig: in.PipelineConfig, RequestMappingTemplate: in.RequestMappingTemplate, ResponseMappingTemplate: in.ResponseMappingTemplate, CachingConfig: in.CachingConfig, SyncConfig: in.SyncConfig, MaxBatchSize: in.MaxBatchSize, MetricsConfig: in.MetricsConfig}
		if e = validateResolver(t, p, &r); e != nil {
			return nil, e
		}
		if e = t.PutResolver(ResolverRecord{p.Key, r}); e != nil {
			return nil, e
		}
		return &api.CreateResolverResponse{Resolver: &r}, nil
	})
	register(s, "UpdateResolver", func(ctx context.Context, t Transaction, in *api.UpdateResolverRequest) (*api.UpdateResolverResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "UpdateResolver")
		if e != nil {
			return nil, e
		}
		previous, e := findResolver(t, p.Key, value(in.TypeName), value(in.FieldName))
		if e != nil {
			return nil, e
		}
		r := api.Resolver{TypeName: in.TypeName, FieldName: in.FieldName, Kind: in.Kind, DataSourceName: in.DataSourceName, Code: in.Code, Runtime: in.Runtime, PipelineConfig: in.PipelineConfig, RequestMappingTemplate: in.RequestMappingTemplate, ResponseMappingTemplate: in.ResponseMappingTemplate, CachingConfig: in.CachingConfig, SyncConfig: in.SyncConfig, MaxBatchSize: in.MaxBatchSize, MetricsConfig: in.MetricsConfig}
		if r.Kind == nil {
			r.Kind = previous.Kind
		}
		if value(r.Kind) != value(previous.Kind) {
			return nil, bad("Resolver kind cannot be changed.")
		}
		if e = validateResolver(t, p, &r); e != nil {
			return nil, e
		}
		if e = t.PutResolver(ResolverRecord{p.Key, r}); e != nil {
			return nil, e
		}
		return &api.UpdateResolverResponse{Resolver: &r}, nil
	})
	register(s, "GetResolver", func(ctx context.Context, t Transaction, in *api.GetResolverRequest) (*api.GetResolverResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "GetResolver")
		if e != nil {
			return nil, e
		}
		r, e := findResolver(t, p.Key, value(in.TypeName), value(in.FieldName))
		if e != nil {
			return nil, e
		}
		return &api.GetResolverResponse{Resolver: &r}, nil
	})
	register(s, "DeleteResolver", func(ctx context.Context, t Transaction, in *api.DeleteResolverRequest) (*api.DeleteResolverResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "DeleteResolver")
		if e != nil {
			return nil, e
		}
		return &api.DeleteResolverResponse{}, t.DeleteResolver(p.Key, value(in.TypeName), value(in.FieldName))
	})
	register(s, "ListResolvers", func(ctx context.Context, t Transaction, in *api.ListResolversRequest) (*api.ListResolversResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "ListResolvers")
		if e != nil {
			return nil, e
		}
		all, e := t.Resolvers(p.Key)
		if e != nil {
			return nil, e
		}
		out := api.Resolvers{}
		for _, r := range all {
			if value(r.Resolver.TypeName) == value(in.TypeName) {
				out = append(out, r.Resolver)
			}
		}
		out, next, e := page(out, in.NextToken, in.MaxResults, p.Key.ARN()+"/ListResolvers/"+value(in.TypeName), resolverID)
		return &api.ListResolversResponse{Resolvers: out, NextToken: next}, e
	})
	register(s, "ListResolversByFunction", func(ctx context.Context, t Transaction, in *api.ListResolversByFunctionRequest) (*api.ListResolversByFunctionResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "ListResolversByFunction")
		if e != nil {
			return nil, e
		}
		if _, e = findFunction(t, p.Key, value(in.FunctionId)); e != nil {
			return nil, e
		}
		all, e := t.Resolvers(p.Key)
		if e != nil {
			return nil, e
		}
		out := api.Resolvers{}
		for _, r := range all {
			if r.Resolver.PipelineConfig != nil {
				for _, id := range r.Resolver.PipelineConfig.Functions {
					if string(id) == value(in.FunctionId) {
						out = append(out, r.Resolver)
						break
					}
				}
			}
		}
		out, next, e := page(out, in.NextToken, in.MaxResults, p.Key.ARN()+"/ListResolversByFunction/"+value(in.FunctionId), resolverID)
		return &api.ListResolversByFunctionResponse{Resolvers: out, NextToken: next}, e
	})
}
func resolverID(r api.Resolver) string { return value(r.TypeName) + "." + value(r.FieldName) }
func findResolver(r Reader, k Key, typeName, fieldName string) (api.Resolver, error) {
	all, e := r.Resolvers(k)
	if e != nil {
		return api.Resolver{}, e
	}
	for _, x := range all {
		if value(x.Resolver.TypeName) == typeName && value(x.Resolver.FieldName) == fieldName {
			return x.Resolver, nil
		}
	}
	return api.Resolver{}, ErrNotFound
}
func validateResolver(t Reader, p APIRecord, r *api.Resolver) error {
	if !resourceName.MatchString(value(r.TypeName)) || !resourceName.MatchString(value(r.FieldName)) {
		return bad("Invalid resolver type or field name.")
	}
	if e := validateResolverField(p.Schema, value(r.TypeName), value(r.FieldName)); e != nil {
		return bad(e.Error())
	}
	if r.CachingConfig != nil || r.SyncConfig != nil || r.MaxBatchSize != nil && *r.MaxBatchSize != 0 || r.MetricsConfig != nil && value(r.MetricsConfig) != "DISABLED" {
		return unsupported("Resolver caching, sync, automatic batching and metrics are not implemented.")
	}
	if r.Kind == nil {
		text(&r.Kind, "UNIT")
	}
	direct := false
	switch value(r.Kind) {
	case "UNIT":
		if r.PipelineConfig != nil {
			return bad("UNIT resolvers cannot have pipelineConfig.")
		}
		d, e := findDataSource(t, p.Key, value(r.DataSourceName))
		if e != nil {
			return e
		}
		direct = value(d.Type) == "AWS_LAMBDA"
	case "PIPELINE":
		if value(r.DataSourceName) != "" {
			return bad("PIPELINE resolvers cannot name a data source.")
		}
		if r.PipelineConfig == nil || len(r.PipelineConfig.Functions) == 0 || len(r.PipelineConfig.Functions) > 10 {
			return bad("A pipeline requires between 1 and 10 functions.")
		}
		for _, id := range r.PipelineConfig.Functions {
			if _, e := findFunction(t, p.Key, string(id)); e != nil {
				return e
			}
		}
	default:
		return bad("Invalid resolver kind.")
	}
	if e := validateMapping(r.Runtime, r.Code, r.RequestMappingTemplate, r.ResponseMappingTemplate, direct); e != nil {
		return e
	}
	text(&r.ResolverArn, p.Key.ARN()+"/types/"+value(r.TypeName)+"/resolvers/"+value(r.FieldName))
	return nil
}
func validateMapping(runtime *api.AppSyncRuntime, code *api.Code, request, response *api.MappingTemplate, direct bool) error {
	// TODO: Comeback: implement VTL evaluation before accepting mapping templates.
	if request != nil || response != nil {
		return unsupported("VTL mapping templates are not implemented; use APPSYNC_JS or a direct Lambda resolver.")
	}
	if runtime == nil {
		if direct && code == nil {
			return nil
		}
		return bad("APPSYNC_JS runtime and code are required.")
	}
	if value(runtime.Name) != "APPSYNC_JS" || value(runtime.RuntimeVersion) != "1.0.0" {
		return unsupported("Only APPSYNC_JS runtime version 1.0.0 is implemented.")
	}
	if value(code) == "" {
		return bad("JavaScript code is required.")
	}
	if _, e := compileMapping(value(code)); e != nil {
		return bad(e.Error())
	}
	return nil
}
