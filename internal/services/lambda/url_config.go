package lambda

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"stackd/internal/endpoints"
)

const functionURLPrefix = "/_stackd/lambda/urls/"

// This deterministic representative delay is not an AWS propagation guarantee.
const functionURLPropagationDelay = time.Minute

func (s *Service) registerFunctionURLs() {
	register(s, "CreateFunctionUrlConfig", s.createFunctionURL)
	register(s, "GetFunctionUrlConfig", s.getFunctionURL)
	register(s, "UpdateFunctionUrlConfig", s.updateFunctionURL)
	register(s, "DeleteFunctionUrlConfig", s.deleteFunctionURL)
	register(s, "ListFunctionUrlConfigs", s.listFunctionURLs)
}

func functionURLCORS(in *api.Cors) (*FunctionURLCORS, *awswire.Error) {
	if in == nil || (in.AllowCredentials == nil && in.AllowHeaders == nil && in.AllowMethods == nil && in.AllowOrigins == nil && in.ExposeHeaders == nil && in.MaxAge == nil) {
		return nil, nil
	}
	if in.AllowOrigins == nil {
		return nil, failure("InvalidParameterValueException", "You can't leave AllowOrigins as empty when Cors is enabled.", 400)
	}
	out := &FunctionURLCORS{AllowHeaders: layerStrings(in.AllowHeaders), AllowMethods: layerStrings(in.AllowMethods), AllowOrigins: layerStrings(in.AllowOrigins), ExposeHeaders: layerStrings(in.ExposeHeaders)}
	if in.AllowCredentials != nil {
		out.AllowCredentials = new(bool(*in.AllowCredentials))
	}
	if in.MaxAge != nil {
		out.MaxAge = new(int32(*in.MaxAge))
	}
	return out, nil
}

func functionURLCORSOutput(in *FunctionURLCORS) *api.Cors {
	if in == nil {
		return nil
	}
	out := &api.Cors{}
	if in.AllowCredentials != nil {
		out.AllowCredentials = new(api.AllowCredentials(*in.AllowCredentials))
	}
	if in.MaxAge != nil {
		out.MaxAge = new(api.MaxAge(*in.MaxAge))
	}
	if in.AllowHeaders != nil {
		out.AllowHeaders = make(api.HeadersList, len(in.AllowHeaders))
		for i, v := range in.AllowHeaders {
			out.AllowHeaders[i] = api.Header(v)
		}
	}
	if in.AllowMethods != nil {
		out.AllowMethods = make(api.AllowMethodsList, len(in.AllowMethods))
		for i, v := range in.AllowMethods {
			out.AllowMethods[i] = api.Method(v)
		}
	}
	if in.AllowOrigins != nil {
		out.AllowOrigins = make(api.AllowOriginsList, len(in.AllowOrigins))
		for i, v := range in.AllowOrigins {
			out.AllowOrigins[i] = api.Origin(v)
		}
	}
	if in.ExposeHeaders != nil {
		out.ExposeHeaders = make(api.HeadersList, len(in.ExposeHeaders))
		for i, v := range in.ExposeHeaders {
			out.ExposeHeaders[i] = api.Header(v)
		}
	}
	return out
}

func (s *Service) functionURLConfiguration(v FunctionURLRecord) (api.FunctionUrlConfig, error) {
	endpoint := s.publicEndpoint + functionURLPrefix + v.ID + "/"
	if s.endpointDomain != "" {
		var err error
		endpoint, err = endpoints.ResourceURL(s.publicEndpoint, s.endpointDomain, "lambda-url", v.Key.Region, v.ID)
		if err != nil {
			return api.FunctionUrlConfig{}, err
		}
	}
	return api.FunctionUrlConfig{
		FunctionUrl:      new(api.FunctionUrl(endpoint)),
		FunctionArn:      new(api.FunctionArn(v.Key.ARN())),
		AuthType:         new(api.FunctionUrlAuthType(v.Settings.AuthType)),
		InvokeMode:       new(api.InvokeMode(v.Settings.InvokeMode)),
		Cors:             functionURLCORSOutput(v.Settings.Cors),
		CreationTime:     new(api.Timestamp(v.Created.UTC().Format(time.RFC3339Nano))),
		LastModifiedTime: new(api.Timestamp(v.Modified.UTC().Format(time.RFC3339Nano))),
	}, nil
}

func functionURLNotFound(err error, function bool) *awswire.Error {
	if errors.Is(err, ErrNotFound) {
		message := "The resource you requested does not exist."
		if function {
			message = "Function does not exist"
		}
		return failure("ResourceNotFoundException", message, 404)
	}
	return wireError(err)
}

func functionURLAuthContext(auth *api.FunctionUrlAuthType) map[string][]string {
	if auth == nil {
		return nil
	}
	return map[string][]string{"lambda:FunctionUrlAuthType": {string(*auth)}}
}

func (s *Service) createFunctionURL(ctx context.Context, in *api.CreateFunctionUrlConfigInput) (*api.CreateFunctionUrlConfigOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	cors, wire := functionURLCORS(in.Cors)
	if wire != nil {
		return nil, wire
	}
	var out *api.CreateFunctionUrlConfigOutput
	err := s.repository.Update(ctx, func(tx Transaction) error {
		f, err := loadFunction(tx, ref)
		if err != nil {
			return functionURLNotFound(err, true)
		}
		if wire := s.authorizeFunction(tx, "CreateFunctionUrlConfig", ref, f, functionURLAuthContext(in.AuthType)); wire != nil {
			return wire
		}
		owner, _, err := additionalOwnerFor(tx.Context())
		if err != nil {
			return err
		}
		if current, err := tx.FunctionURL(ref); err == nil {
			if owner == (AdditionalOwner{}) {
				return failure("ResourceConflictException", "FunctionUrlConfig exists for this Lambda function.", 409)
			}
			if err := requireAdditionalOwner(tx.Context(), current.Owner); err != nil {
				return err
			}
			config, err := s.functionURLConfiguration(current)
			if err != nil {
				return err
			}
			out = &api.CreateFunctionUrlConfigOutput{FunctionUrl: config.FunctionUrl, FunctionArn: config.FunctionArn, AuthType: config.AuthType, InvokeMode: config.InvokeMode, Cors: config.Cors, CreationTime: config.CreationTime}
			return s.recordCall(tx.Context(), "CreateFunctionUrlConfig", in, out, nil)
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		if s.publicEndpoint == "" {
			return unsupported("Function URLs require a configured PublicEndpoint.")
		}
		now := s.clock.Now()
		v := FunctionURLRecord{Key: ref, ID: uuid.NewString(), Created: now, Modified: now, AppliesAt: now, Settings: FunctionURLSettings{AuthType: value(in.AuthType), InvokeMode: "BUFFERED", Cors: cors}}
		v.Owner = owner
		if in.InvokeMode != nil {
			v.Settings.InvokeMode = value(in.InvokeMode)
		}
		v.Effective = v.Settings
		if err := tx.PutFunctionURL(v); err != nil {
			return err
		}
		config, err := s.functionURLConfiguration(v)
		if err != nil {
			return err
		}
		out = &api.CreateFunctionUrlConfigOutput{FunctionUrl: config.FunctionUrl, FunctionArn: config.FunctionArn, AuthType: config.AuthType, Cors: config.Cors, CreationTime: config.CreationTime}
		if in.InvokeMode != nil {
			out.InvokeMode = config.InvokeMode
		}
		return s.recordCall(tx.Context(), "CreateFunctionUrlConfig", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) getFunctionURL(ctx context.Context, in *api.GetFunctionUrlConfigInput) (*api.GetFunctionUrlConfigOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	var v FunctionURLRecord
	err := s.repository.View(ctx, func(r Reader) error {
		f, err := r.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(r, "GetFunctionUrlConfig", ref, f, nil); wire != nil {
			return wire
		}
		v, err = r.FunctionURL(ref)
		if err == nil {
			return requireAdditionalOwner(r.Context(), v.Owner)
		}
		return err
	})
	if err != nil {
		return nil, functionURLNotFound(err, false)
	}
	config, err := s.functionURLConfiguration(v)
	if err != nil {
		return nil, wireError(err)
	}
	out := api.GetFunctionUrlConfigOutput(config)
	return &out, nil
}

func (s *Service) updateFunctionURL(ctx context.Context, in *api.UpdateFunctionUrlConfigInput) (*api.UpdateFunctionUrlConfigOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	cors, wire := functionURLCORS(in.Cors)
	if wire != nil {
		return nil, wire
	}
	var out *api.UpdateFunctionUrlConfigOutput
	err := s.repository.Update(ctx, func(tx Transaction) error {
		f, err := loadFunction(tx, ref)
		if err != nil {
			return functionURLNotFound(err, true)
		}
		if wire := s.authorizeFunction(tx, "UpdateFunctionUrlConfig", ref, f, functionURLAuthContext(in.AuthType)); wire != nil {
			return wire
		}
		v, err := tx.FunctionURL(ref)
		if err != nil {
			return functionURLNotFound(err, false)
		}
		if err := requireAdditionalOwner(tx.Context(), v.Owner); err != nil {
			return err
		}
		now := s.clock.Now()
		v.Effective = v.EffectiveSettings(now)
		v.Modified, v.AppliesAt = now, now.Add(functionURLPropagationDelay)
		if in.AuthType != nil {
			v.Settings.AuthType = value(in.AuthType)
		}
		if in.InvokeMode != nil {
			v.Settings.InvokeMode = value(in.InvokeMode)
		}
		if in.Cors != nil {
			v.Settings.Cors = cors
		}
		if err := tx.PutFunctionURL(v); err != nil {
			return err
		}
		current, err := s.functionURLConfiguration(v)
		if err != nil {
			return err
		}
		config := api.UpdateFunctionUrlConfigOutput(current)
		if in.InvokeMode == nil {
			config.InvokeMode = nil
		}
		out = &config
		return s.recordCall(tx.Context(), "UpdateFunctionUrlConfig", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) deleteFunctionURL(ctx context.Context, in *api.DeleteFunctionUrlConfigInput) (*api.DeleteFunctionUrlConfigOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		f, err := tx.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, "DeleteFunctionUrlConfig", ref, f, nil); wire != nil {
			return wire
		}
		v, err := tx.FunctionURL(ref)
		if err != nil {
			return err
		}
		if err := requireAdditionalOwner(tx.Context(), v.Owner); err != nil {
			return err
		}
		if err := tx.DeleteFunctionURL(ref); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "DeleteFunctionUrlConfig", in, nil, nil)
	})
	if err != nil {
		return nil, functionURLNotFound(err, false)
	}
	return &api.DeleteFunctionUrlConfigOutput{}, nil
}

func (s *Service) listFunctionURLs(ctx context.Context, in *api.ListFunctionUrlConfigsInput) (*api.ListFunctionUrlConfigsOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	if ref.Qualifier != "" {
		return nil, failure("InvalidParameterValueException", "The function name must not include a version number or alias.", 400)
	}
	after := ""
	if in.Marker != nil {
		decoded, err := base64.RawURLEncoding.DecodeString(value(in.Marker))
		prefix := ref.ARN() + "/url/"
		if err != nil || !strings.HasPrefix(string(decoded), prefix) {
			return nil, failure("InvalidParameterValueException", "Invalid marker value from user.", 400)
		}
		after = strings.TrimPrefix(string(decoded), prefix)
	}
	limit := 50
	if in.MaxItems != nil && int(*in.MaxItems) < limit {
		limit = int(*in.MaxItems)
	}
	out := &api.ListFunctionUrlConfigsOutput{FunctionUrlConfigs: api.FunctionUrlConfigList{}}
	err := s.repository.View(ctx, func(r Reader) error {
		f, err := r.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(r, "ListFunctionUrlConfigs", ref, f, nil); wire != nil {
			return wire
		}
		configs, err := r.FunctionURLs(ref.FunctionKey)
		if err != nil {
			return err
		}
		last := ""
		for _, v := range configs {
			if in.Marker != nil && v.Key.Qualifier <= after {
				continue
			}
			if len(out.FunctionUrlConfigs) == limit {
				out.NextMarker = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(ref.ARN() + "/url/" + last))))
				break
			}
			config, err := s.functionURLConfiguration(v)
			if err != nil {
				return err
			}
			out.FunctionUrlConfigs = append(out.FunctionUrlConfigs, config)
			last = v.Key.Qualifier
		}
		return nil
	})
	if err != nil {
		return nil, functionURLNotFound(err, true)
	}
	return out, nil
}
