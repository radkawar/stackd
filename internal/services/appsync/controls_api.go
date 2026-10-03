package appsync

import (
	"context"
	"net/url"
	"regexp"
	api "stackd/internal/awsapi/appsync"
	"strings"
)

func registerAPIs(s *Service) {
	register(s, "CreateGraphqlApi", func(ctx context.Context, t Transaction, in *api.CreateGraphqlApiRequest) (*api.CreateGraphqlApiResponse, error) {
		k := keyFor(ctx, randomID())
		p := APIRecord{Key: k, SchemaStatus: "NOT_APPLICABLE", API: api.GraphqlApi{AuthenticationType: in.AuthenticationType, AdditionalAuthenticationProviders: in.AdditionalAuthenticationProviders, ApiType: in.ApiType, Visibility: in.Visibility, UserPoolConfig: in.UserPoolConfig, OpenIDConnectConfig: in.OpenIDConnectConfig, LambdaAuthorizerConfig: in.LambdaAuthorizerConfig, LogConfig: in.LogConfig, XrayEnabled: in.XrayEnabled, EnhancedMetricsConfig: in.EnhancedMetricsConfig, MergedApiExecutionRoleArn: in.MergedApiExecutionRoleArn, OwnerContact: in.OwnerContact, QueryDepthLimit: in.QueryDepthLimit, ResolverCountLimit: in.ResolverCountLimit, IntrospectionConfig: in.IntrospectionConfig, Tags: in.Tags}}
		text(&p.API.Name, value(in.Name))
		text(&p.API.ApiId, k.ID)
		text(&p.API.Arn, k.ARN())
		text(&p.API.Owner, k.AccountID)
		if p.API.ApiType == nil {
			text(&p.API.ApiType, "GRAPHQL")
		}
		if p.API.Visibility == nil {
			text(&p.API.Visibility, "GLOBAL")
		}
		if p.API.IntrospectionConfig == nil {
			text(&p.API.IntrospectionConfig, "ENABLED")
		}
		if p.API.QueryDepthLimit == nil {
			p.API.QueryDepthLimit = new(api.QueryDepthLimit)
		}
		if p.API.ResolverCountLimit == nil {
			p.API.ResolverCountLimit = new(api.ResolverCountLimit)
		}
		if p.API.XrayEnabled == nil {
			p.API.XrayEnabled = new(api.Boolean)
		}
		if err := validateAPI(p.API); err != nil {
			return nil, err
		}
		if err := validateTags(p.API.Tags); err != nil {
			return nil, err
		}
		conditions := tagConditions(nil, in.Tags, nil)
		conditions["appsync:Visibility"] = []string{value(p.API.Visibility)}
		if err := s.permissionContext(ctx, "CreateGraphqlApi", "*", conditions); err != nil {
			return nil, err
		}
		if len(in.Tags) > 0 {
			if err := s.permissionContext(ctx, "TagResource", k.ARN(), tagConditions(nil, in.Tags, nil)); err != nil {
				return nil, err
			}
		}
		base := strings.TrimRight(s.endpoint, "/") + "/_stackd/appsync/" + k.ID + "/graphql"
		realtime := "ws" + strings.TrimPrefix(base, "http") + "/realtime"
		p.API.Uris = api.MapOfStringToString{"GRAPHQL": api.String(base), "REALTIME": api.String(realtime)}
		if err := t.PutAPI(p); err != nil {
			return nil, err
		}
		return &api.CreateGraphqlApiResponse{GraphqlApi: &p.API}, nil
	})
	register(s, "GetGraphqlApi", func(ctx context.Context, t Transaction, in *api.GetGraphqlApiRequest) (*api.GetGraphqlApiResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "GetGraphqlApi")
		if e != nil {
			return nil, e
		}
		return &api.GetGraphqlApiResponse{GraphqlApi: &p.API}, nil
	})
	register(s, "UpdateGraphqlApi", func(ctx context.Context, t Transaction, in *api.UpdateGraphqlApiRequest) (*api.UpdateGraphqlApiResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "UpdateGraphqlApi")
		if e != nil {
			return nil, e
		}
		text(&p.API.Name, value(in.Name))
		p.API.AuthenticationType = in.AuthenticationType
		if in.AdditionalAuthenticationProviders != nil {
			p.API.AdditionalAuthenticationProviders = in.AdditionalAuthenticationProviders
		}
		if in.UserPoolConfig != nil {
			p.API.UserPoolConfig = in.UserPoolConfig
		}
		if in.OpenIDConnectConfig != nil {
			p.API.OpenIDConnectConfig = in.OpenIDConnectConfig
		}
		if in.LambdaAuthorizerConfig != nil {
			p.API.LambdaAuthorizerConfig = in.LambdaAuthorizerConfig
		}
		if in.LogConfig != nil {
			p.API.LogConfig = in.LogConfig
		}
		if in.EnhancedMetricsConfig != nil {
			p.API.EnhancedMetricsConfig = in.EnhancedMetricsConfig
		}
		if in.MergedApiExecutionRoleArn != nil {
			p.API.MergedApiExecutionRoleArn = in.MergedApiExecutionRoleArn
		}
		if in.XrayEnabled != nil {
			p.API.XrayEnabled = in.XrayEnabled
		}
		if in.OwnerContact != nil {
			p.API.OwnerContact = in.OwnerContact
		}
		if in.QueryDepthLimit != nil {
			p.API.QueryDepthLimit = in.QueryDepthLimit
		}
		if in.ResolverCountLimit != nil {
			p.API.ResolverCountLimit = in.ResolverCountLimit
		}
		if in.IntrospectionConfig != nil {
			p.API.IntrospectionConfig = in.IntrospectionConfig
		}
		if e = validateAPI(p.API); e != nil {
			return nil, e
		}
		if p.Schema != "" {
			if e = validateSchemaAuthentication(p.Schema, len(p.API.AdditionalAuthenticationProviders) > 0); e != nil {
				return nil, bad(e.Error())
			}
		}
		if e = t.PutAPI(p); e != nil {
			return nil, e
		}
		return &api.UpdateGraphqlApiResponse{GraphqlApi: &p.API}, nil
	})
	register(s, "DeleteGraphqlApi", func(ctx context.Context, t Transaction, in *api.DeleteGraphqlApiRequest) (*api.DeleteGraphqlApiResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "DeleteGraphqlApi")
		if e != nil {
			return nil, e
		}
		return &api.DeleteGraphqlApiResponse{}, t.DeleteAPI(p.Key)
	})
	register(s, "ListGraphqlApis", func(ctx context.Context, t Transaction, in *api.ListGraphqlApisRequest) (*api.ListGraphqlApisResponse, error) {
		if e := s.permission(ctx, "ListGraphqlApis", "*", nil); e != nil {
			return nil, e
		}
		all, e := t.APIs()
		if e != nil {
			return nil, e
		}
		k := keyFor(ctx, "")
		out := api.GraphqlApis{}
		if value(in.Owner) != "" && value(in.Owner) != "CURRENT_ACCOUNT" && value(in.Owner) != "OTHER_ACCOUNTS" {
			return nil, bad("Invalid owner filter.")
		}
		if value(in.ApiType) != "" && value(in.ApiType) != "GRAPHQL" && value(in.ApiType) != "MERGED" {
			return nil, bad("Invalid apiType filter.")
		}
		for _, p := range all {
			if p.Key.Partition == k.Partition && p.Key.AccountID == k.AccountID && p.Key.Region == k.Region && value(in.Owner) != "OTHER_ACCOUNTS" && (in.ApiType == nil || value(in.ApiType) == value(p.API.ApiType)) {
				out = append(out, p.API)
			}
		}
		out, next, e := page(out, in.NextToken, in.MaxResults, k.ARN()+"/ListGraphqlApis/"+value(in.ApiType)+"/"+value(in.Owner), func(p api.GraphqlApi) string { return value(p.ApiId) })
		return &api.ListGraphqlApisResponse{GraphqlApis: out, NextToken: next}, e
	})
	register(s, "StartSchemaCreation", func(ctx context.Context, t Transaction, in *api.StartSchemaCreationRequest) (*api.StartSchemaCreationResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "StartSchemaCreation")
		if e != nil {
			return nil, e
		}
		definition := string(in.Definition)
		e = validateSchema(definition)
		if e == nil {
			e = validateSchemaAuthentication(definition, len(p.API.AdditionalAuthenticationProviders) > 0)
		}
		if e != nil {
			p.SchemaStatus = "FAILED"
			p.SchemaDetails = []byte(e.Error())
		} else {
			resolvers, err := t.Resolvers(p.Key)
			if err != nil {
				return nil, err
			}
			for _, r := range resolvers {
				if err = validateResolverField(definition, value(r.Resolver.TypeName), value(r.Resolver.FieldName)); err != nil {
					return nil, bad("Schema would remove a field with an attached resolver.")
				}
			}
			p.Schema = definition
			p.SchemaStatus = "SUCCESS"
			p.SchemaDetails = nil
		}
		if e = t.PutAPI(p); e != nil {
			return nil, e
		}
		out := &api.StartSchemaCreationResponse{}
		text(&out.Status, p.SchemaStatus)
		return out, nil
	})
	register(s, "GetSchemaCreationStatus", func(ctx context.Context, t Transaction, in *api.GetSchemaCreationStatusRequest) (*api.GetSchemaCreationStatusResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "GetSchemaCreationStatus")
		if e != nil {
			return nil, e
		}
		out := &api.GetSchemaCreationStatusResponse{}
		if len(p.SchemaDetails) > 0 {
			text(&out.Details, string(p.SchemaDetails))
		}
		text(&out.Status, p.SchemaStatus)
		return out, nil
	})
}

func validateAPI(p api.GraphqlApi) error {
	if strings.TrimSpace(value(p.Name)) == "" {
		return bad("name is required.")
	}
	if value(p.ApiType) != "GRAPHQL" || value(p.Visibility) != "GLOBAL" || p.MergedApiExecutionRoleArn != nil {
		return unsupported("Merged and private GraphQL APIs are not implemented.")
	}
	if p.LogConfig != nil || p.EnhancedMetricsConfig != nil || boolValue(p.XrayEnabled) {
		return unsupported("AppSync logs, enhanced metrics and X-Ray are not implemented.")
	}
	if value(p.IntrospectionConfig) != "ENABLED" && value(p.IntrospectionConfig) != "DISABLED" {
		return bad("Invalid introspectionConfig.")
	}
	if p.QueryDepthLimit != nil && (*p.QueryDepthLimit < 0 || *p.QueryDepthLimit > 75) {
		return bad("queryDepthLimit must be between 0 and 75.")
	}
	if p.ResolverCountLimit != nil && (*p.ResolverCountLimit < 0 || *p.ResolverCountLimit > 10000) {
		return bad("resolverCountLimit must be between 0 and 10000.")
	}
	if e := validateAuth(value(p.AuthenticationType), p.UserPoolConfig, p.OpenIDConnectConfig, p.LambdaAuthorizerConfig); e != nil {
		return e
	}
	seen := map[string]bool{}
	primary := value(p.AuthenticationType)
	if primary == "API_KEY" || primary == "AWS_IAM" {
		seen[primary] = true
	}
	for _, a := range p.AdditionalAuthenticationProviders {
		mode := value(a.AuthenticationType)
		if seen[mode] {
			return bad("Duplicate authentication provider.")
		}
		if mode == "API_KEY" || mode == "AWS_IAM" {
			seen[mode] = true
		}
		var pool *api.UserPoolConfig
		if a.UserPoolConfig != nil {
			pool = &api.UserPoolConfig{AppIdClientRegex: a.UserPoolConfig.AppIdClientRegex, AwsRegion: a.UserPoolConfig.AwsRegion, UserPoolId: a.UserPoolConfig.UserPoolId}
			text(&pool.DefaultAction, "ALLOW")
		}
		if e := validateAuth(mode, pool, a.OpenIDConnectConfig, a.LambdaAuthorizerConfig); e != nil {
			return e
		}
	}
	return nil
}
func validateAuth(mode string, pool *api.UserPoolConfig, oidc *api.OpenIDConnectConfig, lambda *api.LambdaAuthorizerConfig) error {
	if lambda != nil || mode == "AWS_LAMBDA" {
		return unsupported("Lambda authorizers are not implemented.")
	}
	switch mode {
	case "API_KEY", "AWS_IAM":
		return nil
	case "AMAZON_COGNITO_USER_POOLS":
		if pool == nil || value(pool.UserPoolId) == "" || value(pool.AwsRegion) == "" {
			return bad("userPoolConfig is required.")
		}
		if a := value(pool.DefaultAction); a != "ALLOW" && a != "DENY" {
			return bad("Invalid userPoolConfig defaultAction.")
		}
		if value(pool.AppIdClientRegex) != "" {
			if _, e := regexp.Compile(value(pool.AppIdClientRegex)); e != nil {
				return bad("Invalid appIdClientRegex.")
			}
		}
	case "OPENID_CONNECT":
		if oidc == nil {
			return bad("openIDConnectConfig is required.")
		}
		u, e := url.Parse(value(oidc.Issuer))
		if e != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return bad("OIDC issuer must be an HTTPS URL.")
		}
		if value(oidc.ClientId) != "" {
			if _, e = regexp.Compile(value(oidc.ClientId)); e != nil {
				return bad("Invalid OIDC clientId expression.")
			}
		}
	default:
		return bad("Invalid authenticationType.")
	}
	return nil
}
