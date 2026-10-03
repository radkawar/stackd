package lambda

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"strings"
)

func (s *Service) registerEventInvokeConfig() {
	register(s, "PutFunctionEventInvokeConfig", s.putEventInvokeConfig)
	register(s, "UpdateFunctionEventInvokeConfig", s.updateEventInvokeConfig)
	register(s, "GetFunctionEventInvokeConfig", s.getEventInvokeConfig)
	register(s, "DeleteFunctionEventInvokeConfig", s.deleteEventInvokeConfig)
	register(s, "ListFunctionEventInvokeConfigs", s.listEventInvokeConfigs)
}

// Event-invoke settings use one identity for unqualified and explicit $LATEST
// requests. Numeric and alias requests never fall back to their target or parent.
func eventInvokeConfigReference(ref FunctionReference) FunctionReference {
	if ref.Qualifier == "$LATEST" {
		ref.Qualifier = ""
	}
	return ref
}

func eventInvokeConfiguration(v EventInvokeConfig) *api.FunctionEventInvokeConfig {
	ref := v.Key
	if ref.Qualifier == "" {
		ref.Qualifier = "$LATEST"
	}
	out := &api.FunctionEventInvokeConfig{FunctionArn: new(api.FunctionArn(ref.ARN())), LastModified: new(api.Date(v.Modified)), DestinationConfig: &api.DestinationConfig{OnSuccess: &api.OnSuccess{}, OnFailure: &api.OnFailure{}}}
	if v.HasMaxAge {
		out.MaximumEventAgeInSeconds = new(api.MaximumEventAgeInSeconds(v.MaxAgeSeconds))
	}
	if v.HasMaxRetries {
		out.MaximumRetryAttempts = new(api.MaximumRetryAttempts(v.MaxRetries))
	}
	if v.OnSuccessARN != "" {
		out.DestinationConfig.OnSuccess.Destination = new(api.DestinationArn(v.OnSuccessARN))
	}
	if v.OnFailureARN != "" {
		out.DestinationConfig.OnFailure.Destination = new(api.DestinationArn(v.OnFailureARN))
	}
	return out
}
func (s *Service) putEventInvokeConfig(ctx context.Context, in *api.PutFunctionEventInvokeConfigInput) (*api.PutFunctionEventInvokeConfigOutput, *awswire.Error) {
	return s.writeEventInvokeConfig(ctx, value(in.FunctionName), value(in.Qualifier), in.MaximumEventAgeInSeconds, in.MaximumRetryAttempts, in.DestinationConfig, false)
}
func (s *Service) updateEventInvokeConfig(ctx context.Context, in *api.UpdateFunctionEventInvokeConfigInput) (*api.UpdateFunctionEventInvokeConfigOutput, *awswire.Error) {
	return s.writeEventInvokeConfig(ctx, value(in.FunctionName), value(in.Qualifier), in.MaximumEventAgeInSeconds, in.MaximumRetryAttempts, in.DestinationConfig, true)
}
func (s *Service) writeEventInvokeConfig(ctx context.Context, name, qualifier string, age *api.MaximumEventAgeInSeconds, retries *api.MaximumRetryAttempts, destinations *api.DestinationConfig, patch bool) (*api.FunctionEventInvokeConfig, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, name, qualifier)
	if wire != nil {
		return nil, wire
	}
	key := eventInvokeConfigReference(ref)
	if age == nil && retries == nil && (destinations == nil || (destinations.OnSuccess == nil && destinations.OnFailure == nil)) {
		return nil, failure("InvalidParameterValueException", "You must specify at least one of error handling or destination setting.", 400)
	}
	var v EventInvokeConfig
	action := "PutFunctionEventInvokeConfig"
	if patch {
		action = "UpdateFunctionEventInvokeConfig"
	}
	var input any = &api.PutFunctionEventInvokeConfigInput{FunctionName: new(api.NamespacedFunctionName(name)), MaximumEventAgeInSeconds: age, MaximumRetryAttempts: retries, DestinationConfig: destinations}
	if patch {
		input = &api.UpdateFunctionEventInvokeConfigInput{FunctionName: new(api.NamespacedFunctionName(name)), MaximumEventAgeInSeconds: age, MaximumRetryAttempts: retries, DestinationConfig: destinations}
	}
	if qualifier != "" {
		if patch {
			input.(*api.UpdateFunctionEventInvokeConfigInput).Qualifier = new(api.NumericLatestPublishedOrAliasQualifier(qualifier))
		} else {
			input.(*api.PutFunctionEventInvokeConfigInput).Qualifier = new(api.NumericLatestPublishedOrAliasQualifier(qualifier))
		}
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		f, err := loadFunction(tx, ref)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, action, ref, f, nil); wire != nil {
			return wire
		}
		current, err := tx.EventInvokeConfig(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if patch && (errors.Is(err, ErrNotFound) || current.Deleted) {
			return ErrNotFound
		}
		if errors.Is(err, ErrNotFound) {
			current.Effective = defaultEventInvokeSettings()
		}
		v = EventInvokeConfig{Key: key, Effective: current.Effective, Version: current.Version}
		if patch {
			v.MaxAgeSeconds, v.MaxRetries, v.HasMaxAge, v.HasMaxRetries = current.MaxAgeSeconds, current.MaxRetries, current.HasMaxAge, current.HasMaxRetries
			v.OnSuccessARN, v.OnFailureARN = current.OnSuccessARN, current.OnFailureARN
		}
		if age != nil {
			v.MaxAgeSeconds, v.HasMaxAge = int(*age), true
		}
		if retries != nil {
			v.MaxRetries, v.HasMaxRetries = int(*retries), true
		}
		if destinations != nil {
			if route := destinations.OnSuccess; route != nil && route.Destination != nil {
				v.OnSuccessARN = value(route.Destination)
				if wire := s.checkOutcomeTarget(tx.Context(), ref.FunctionKey, f.Role, v.OnSuccessARN, false, true); wire != nil {
					return wire
				}
			}
			if route := destinations.OnFailure; route != nil && route.Destination != nil {
				v.OnFailureARN = value(route.Destination)
				if wire := s.checkOutcomeTarget(tx.Context(), ref.FunctionKey, f.Role, v.OnFailureARN, false, false); wire != nil {
					return wire
				}
			}
		}
		if err := s.stageEventInvokeConfig(tx, &v); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), action, input, eventInvokeConfiguration(v), nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return eventInvokeConfiguration(v), nil
}
func (s *Service) getEventInvokeConfig(ctx context.Context, in *api.GetFunctionEventInvokeConfigInput) (*api.GetFunctionEventInvokeConfigOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	key := eventInvokeConfigReference(ref)
	var v EventInvokeConfig
	err := s.repository.View(ctx, func(r Reader) error {
		f, err := loadFunction(r, ref)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(r, "GetFunctionEventInvokeConfig", ref, f, nil); wire != nil {
			return wire
		}
		v, err = r.EventInvokeConfig(key)
		if err == nil && v.Deleted {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	return eventInvokeConfiguration(v), nil
}
func (s *Service) deleteEventInvokeConfig(ctx context.Context, in *api.DeleteFunctionEventInvokeConfigInput) (*api.DeleteFunctionEventInvokeConfigOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	key := eventInvokeConfigReference(ref)
	err := s.repository.Update(ctx, func(tx Transaction) error {
		f, err := loadFunction(tx, ref)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, "DeleteFunctionEventInvokeConfig", ref, f, nil); wire != nil {
			return wire
		}
		v, err := tx.EventInvokeConfig(key)
		if err != nil {
			return err
		}
		if v.Deleted {
			return ErrNotFound
		}
		v.Deleted = true
		if err := s.stageEventInvokeConfig(tx, &v); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "DeleteFunctionEventInvokeConfig", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return &api.DeleteFunctionEventInvokeConfigOutput{}, nil
}
func (s *Service) listEventInvokeConfigs(ctx context.Context, in *api.ListFunctionEventInvokeConfigsInput) (*api.ListFunctionEventInvokeConfigsOutput, *awswire.Error) {
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
		prefix := ref.ARN() + "/"
		if err != nil || !strings.HasPrefix(string(decoded), prefix) {
			return nil, failure("InvalidParameterValueException", "Invalid pagination key.", 400)
		}
		after = strings.TrimPrefix(string(decoded), prefix)
	}
	limit := 50
	if in.MaxItems != nil && int(*in.MaxItems) < limit {
		limit = int(*in.MaxItems)
	}
	out := &api.ListFunctionEventInvokeConfigsOutput{FunctionEventInvokeConfigs: api.FunctionEventInvokeConfigList{}}
	err := s.repository.View(ctx, func(r Reader) error {
		f, err := r.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(r, "ListFunctionEventInvokeConfigs", ref, f, nil); wire != nil {
			return wire
		}
		configs, err := r.EventInvokeConfigs(ref.FunctionKey)
		if err != nil {
			return err
		}
		slices.SortFunc(configs, func(a, b EventInvokeConfig) int { return strings.Compare(a.Key.Qualifier, b.Key.Qualifier) })
		last := ""
		for _, v := range configs {
			if v.Deleted || (in.Marker != nil && v.Key.Qualifier <= after) {
				continue
			}
			if len(out.FunctionEventInvokeConfigs) == limit {
				out.NextMarker = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(ref.ARN() + "/" + last))))
				break
			}
			out.FunctionEventInvokeConfigs = append(out.FunctionEventInvokeConfigs, *eventInvokeConfiguration(v))
			last = v.Key.Qualifier
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
