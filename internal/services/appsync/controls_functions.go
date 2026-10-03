package appsync

import (
	"context"
	api "stackd/internal/awsapi/appsync"
)

func registerFunctions(s *Service) {
	register(s, "CreateFunction", func(ctx context.Context, t Transaction, in *api.CreateFunctionRequest) (*api.CreateFunctionResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "CreateFunction")
		if e != nil {
			return nil, e
		}
		f := api.FunctionConfiguration{Name: in.Name, Description: in.Description, DataSourceName: in.DataSourceName, Runtime: in.Runtime, Code: in.Code, FunctionVersion: in.FunctionVersion, RequestMappingTemplate: in.RequestMappingTemplate, ResponseMappingTemplate: in.ResponseMappingTemplate, SyncConfig: in.SyncConfig, MaxBatchSize: in.MaxBatchSize}
		text(&f.FunctionId, randomID())
		if e = validateFunction(t, p, &f); e != nil {
			return nil, e
		}
		if e = t.PutFunction(FunctionRecord{p.Key, f}); e != nil {
			return nil, e
		}
		return &api.CreateFunctionResponse{FunctionConfiguration: &f}, nil
	})
	register(s, "UpdateFunction", func(ctx context.Context, t Transaction, in *api.UpdateFunctionRequest) (*api.UpdateFunctionResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "UpdateFunction")
		if e != nil {
			return nil, e
		}
		if _, e = findFunction(t, p.Key, value(in.FunctionId)); e != nil {
			return nil, e
		}
		f := api.FunctionConfiguration{Name: in.Name, Description: in.Description, DataSourceName: in.DataSourceName, Runtime: in.Runtime, Code: in.Code, FunctionVersion: in.FunctionVersion, RequestMappingTemplate: in.RequestMappingTemplate, ResponseMappingTemplate: in.ResponseMappingTemplate, SyncConfig: in.SyncConfig, MaxBatchSize: in.MaxBatchSize}
		text(&f.FunctionId, value(in.FunctionId))
		if e = validateFunction(t, p, &f); e != nil {
			return nil, e
		}
		if e = t.PutFunction(FunctionRecord{p.Key, f}); e != nil {
			return nil, e
		}
		return &api.UpdateFunctionResponse{FunctionConfiguration: &f}, nil
	})
	register(s, "GetFunction", func(ctx context.Context, t Transaction, in *api.GetFunctionRequest) (*api.GetFunctionResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "GetFunction")
		if e != nil {
			return nil, e
		}
		f, e := findFunction(t, p.Key, value(in.FunctionId))
		if e != nil {
			return nil, e
		}
		return &api.GetFunctionResponse{FunctionConfiguration: &f}, nil
	})
	register(s, "DeleteFunction", func(ctx context.Context, t Transaction, in *api.DeleteFunctionRequest) (*api.DeleteFunctionResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "DeleteFunction")
		if e != nil {
			return nil, e
		}
		rs, e := t.Resolvers(p.Key)
		if e != nil {
			return nil, e
		}
		for _, r := range rs {
			if r.Resolver.PipelineConfig != nil {
				for _, id := range r.Resolver.PipelineConfig.Functions {
					if string(id) == value(in.FunctionId) {
						return nil, bad("Function is referenced by a pipeline resolver.")
					}
				}
			}
		}
		return &api.DeleteFunctionResponse{}, t.DeleteFunction(p.Key, value(in.FunctionId))
	})
	register(s, "ListFunctions", func(ctx context.Context, t Transaction, in *api.ListFunctionsRequest) (*api.ListFunctionsResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "ListFunctions")
		if e != nil {
			return nil, e
		}
		fs, e := t.Functions(p.Key)
		if e != nil {
			return nil, e
		}
		out := api.Functions{}
		for _, f := range fs {
			out = append(out, f.Function)
		}
		out, next, e := page(out, in.NextToken, in.MaxResults, p.Key.ARN()+"/ListFunctions", func(f api.FunctionConfiguration) string { return value(f.FunctionId) })
		return &api.ListFunctionsResponse{Functions: out, NextToken: next}, e
	})
}
func findFunction(r Reader, k Key, id string) (api.FunctionConfiguration, error) {
	fs, e := r.Functions(k)
	if e != nil {
		return api.FunctionConfiguration{}, e
	}
	for _, f := range fs {
		if value(f.Function.FunctionId) == id {
			return f.Function, nil
		}
	}
	return api.FunctionConfiguration{}, ErrNotFound
}
func validateFunction(r Reader, p APIRecord, f *api.FunctionConfiguration) error {
	if !resourceName.MatchString(value(f.Name)) {
		return bad("Invalid function name.")
	}
	if _, e := findDataSource(r, p.Key, value(f.DataSourceName)); e != nil {
		return e
	}
	if f.SyncConfig != nil || f.MaxBatchSize != nil && *f.MaxBatchSize != 0 {
		return unsupported("Function sync and automatic batching are not implemented.")
	}
	if f.FunctionVersion != nil {
		return unsupported("VTL functionVersion is not implemented; use APPSYNC_JS runtime.")
	}
	if e := validateMapping(f.Runtime, f.Code, f.RequestMappingTemplate, f.ResponseMappingTemplate, false); e != nil {
		return e
	}
	text(&f.FunctionArn, p.Key.ARN()+"/functions/"+value(f.FunctionId))
	return nil
}
