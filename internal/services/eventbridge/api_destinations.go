package eventbridge

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
)

const defaultAPIDestinationRate = 300

func (s *Service) registerAPIDestinations() {
	register(s, "CreateApiDestination", s.createAPIDestination)
	register(s, "DescribeApiDestination", s.describeAPIDestination)
	register(s, "ListApiDestinations", s.listAPIDestinations)
	register(s, "UpdateApiDestination", s.updateAPIDestination)
	register(s, "DeleteApiDestination", s.deleteAPIDestination)
}

func readAPIDestination(r Reader, k APIDestinationKey, action string) (APIDestinationRecord, error) {
	v, err := r.APIDestination(k)
	if errors.Is(err, ErrNotFound) {
		return v, failure("ResourceNotFoundException", "Failed to "+action+" the api-destination(s). An api-destination '"+k.Name+"' does not exist.")
	}
	if err == nil {
		err = cloudFormationCheck(r.Context(), "ApiDestination", v.CFNOwner)
	}
	return v, err
}

func (s *Service) authorizeAPIDestination(r Reader, action string, v APIDestinationRecord) error {
	return s.authorize(r, action, v.ARN(), nil, nil, authorization.BoundPolicy{})
}

func apiDestinationConnection(r Reader, arn, action string) (ConnectionRecord, error) {
	key, id, rejected := parseConnectionARN(r.Context(), arn)
	if rejected != nil {
		return ConnectionRecord{}, failure("ResourceNotFoundException", "Failed to "+action+" the api-destination(s). Connection '"+arn+"' does not exist.")
	}
	v, err := r.Connection(key)
	if errors.Is(err, ErrNotFound) || err == nil && (v.ID != id || v.State == "DELETING") {
		return ConnectionRecord{}, failure("ResourceNotFoundException", "Failed to "+action+" the api-destination(s). Connection '"+arn+"' does not exist.")
	}
	return v, err
}

// State follows the referenced incarnation, not a later Connection with its name.
func apiDestinationState(r Reader, v APIDestinationRecord) (string, error) {
	connection, err := apiDestinationConnection(r, v.ConnectionARN, "describe")
	var wire *awswire.Error
	if errors.As(err, &wire) && wire.Code == "ResourceNotFoundException" {
		return "INACTIVE", nil
	}
	if err != nil {
		return "", err
	}
	if connectionAPIDestinationActive(connection) {
		return "ACTIVE", nil
	}
	return "INACTIVE", nil
}

func validateAPIDestinationEndpoint(endpoint, action string) *awswire.Error {
	parsed := endpoint
	if !strings.Contains(parsed, "://") {
		parsed = "https://" + parsed
	}
	v, err := url.Parse(parsed)
	if err != nil || v.Scheme != "https" || v.Hostname() == "" || strings.Contains(v.Hostname(), "*") || v.User != nil || v.Fragment != "" {
		return failure("ValidationException", "Failed to "+action+" the api-destination(s). Parameter InvocationEndpoint is not valid. Reason: Endpoint '"+endpoint+"' is invalid, please provide a valid HTTPS endpoint URL.")
	}
	return nil
}

func validateAPIDestinationMethod(method string) *awswire.Error {
	switch method {
	case "HEAD", "POST", "PATCH", "DELETE", "PUT", "GET", "OPTIONS":
		return nil
	default:
		return failure("ValidationException", "1 validation error detected: Value '"+method+"' at 'httpMethod' failed to satisfy constraint: Member must satisfy enum value set: [HEAD, POST, PATCH, DELETE, PUT, GET, OPTIONS]")
	}
}

func validateAPIDestinationRate(rate int, name, action string) *awswire.Error {
	if rate < 1 {
		return failure("ValidationException", "InvocationRateLimitPerSecond must be at least 1.")
	}
	if rate > defaultAPIDestinationRate {
		return failure("LimitExceededException", "Failed to "+action+" the api-destination(s). Invalid Invocation Rate Limit: Rate specified '"+strconv.Itoa(rate)+"' for '"+name+"' exceeds maximum allowed of '300'.")
	}
	return nil
}

func apiDestinationSummary(v APIDestinationRecord, state string) api.ApiDestination {
	return api.ApiDestination{
		ApiDestinationArn:   str[api.ApiDestinationArn](v.ARN()),
		ApiDestinationState: str[api.ApiDestinationState](state),
		ConnectionArn:       str[api.ConnectionArn](v.ConnectionARN),
		CreationTime:        connectionTime(v.Created), LastModifiedTime: connectionTime(v.Modified),
		HttpMethod:                   str[api.ApiDestinationHttpMethod](v.Method),
		InvocationEndpoint:           str[api.HttpsEndpoint](v.Endpoint),
		InvocationRateLimitPerSecond: ptr(api.ApiDestinationInvocationRateLimitPerSecond(v.Rate)),
		Name:                         str[api.ApiDestinationName](v.Key.Name),
	}
}

func (s *Service) createAPIDestination(ctx context.Context, in *api.CreateApiDestinationInput) (out *api.CreateApiDestinationOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "CreateApiDestination", in, &out, &rejected, false)
	if rejected := validateAPIDestinationEndpoint(value(in.InvocationEndpoint), "create"); rejected != nil {
		return nil, rejected
	}
	if rejected := validateAPIDestinationMethod(value(in.HttpMethod)); rejected != nil {
		return nil, rejected
	}
	v := APIDestinationRecord{Key: APIDestinationKey{scopeFor(ctx), value(in.Name)}, ID: identifier(), Description: value(in.Description), ConnectionARN: value(in.ConnectionArn), Endpoint: value(in.InvocationEndpoint), Method: value(in.HttpMethod), Rate: defaultAPIDestinationRate, Version: 1}
	v.CFNOwner = cloudFormationClaim(ctx, "ApiDestination")
	if in.InvocationRateLimitPerSecond != nil {
		v.Rate = int(*in.InvocationRateLimitPerSecond)
	}
	if rejected := validateAPIDestinationRate(v.Rate, v.Key.Name, "create"); rejected != nil {
		return nil, rejected
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorizeAPIDestination(tx, "CreateApiDestination", v); err != nil {
			return err
		}
		if err := s.authorize(tx, "CreateApiDestination", v.ConnectionARN, nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		if _, err := tx.APIDestination(v.Key); err == nil {
			return failure("ResourceAlreadyExistsException", "Failed to create the api-destination(s). An api-destination with name '"+v.Key.Name+"' already exists.")
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		connection, err := apiDestinationConnection(tx, v.ConnectionARN, "create")
		if err != nil {
			return err
		}
		v.Created = s.clock.Now().Truncate(time.Second)
		v.Modified = v.Created
		if err := tx.PutAPIDestination(v); err != nil {
			return err
		}
		state := "INACTIVE"
		if connectionAPIDestinationActive(connection) {
			state = "ACTIVE"
		}
		out = &api.CreateApiDestinationOutput{ApiDestinationArn: str[api.ApiDestinationArn](v.ARN()), ApiDestinationState: str[api.ApiDestinationState](state), CreationTime: connectionTime(v.Created), LastModifiedTime: connectionTime(v.Modified)}
		return s.recordCall(tx.Context(), "CreateApiDestination", in, out, nil)
	})
	return out, wireError(err)
}

func (s *Service) describeAPIDestination(ctx context.Context, in *api.DescribeApiDestinationInput) (out *api.DescribeApiDestinationOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DescribeApiDestination", in, &out, &rejected, true)
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := readAPIDestination(r, APIDestinationKey{scopeFor(ctx), value(in.Name)}, "describe")
		if err != nil {
			return err
		}
		if err := s.authorizeAPIDestination(r, "DescribeApiDestination", v); err != nil {
			return err
		}
		state, err := apiDestinationState(r, v)
		if err != nil {
			return err
		}
		summary := apiDestinationSummary(v, state)
		out = &api.DescribeApiDestinationOutput{ApiDestinationArn: summary.ApiDestinationArn, ApiDestinationState: summary.ApiDestinationState, ConnectionArn: summary.ConnectionArn, CreationTime: summary.CreationTime, LastModifiedTime: summary.LastModifiedTime, HttpMethod: summary.HttpMethod, InvocationEndpoint: summary.InvocationEndpoint, InvocationRateLimitPerSecond: summary.InvocationRateLimitPerSecond, Name: summary.Name}
		if v.Description != "" {
			out.Description = str[api.ApiDestinationDescription](v.Description)
		}
		return nil
	})
	return out, wireError(err)
}

func (s *Service) listAPIDestinations(ctx context.Context, in *api.ListApiDestinationsInput) (out *api.ListApiDestinationsOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListApiDestinations", in, &out, &rejected, true)
	if in.NamePrefix != nil && in.ConnectionArn != nil {
		return nil, failure("ValidationException", "Failed to list the api-destination(s). Request failed because only one filter is supported per request, either ConnectionArn or NamePrefix.")
	}
	scope := scopeFor(ctx)
	collection := strings.Join([]string{"api-destinations", scope.Partition, scope.Account, scope.Region, value(in.NamePrefix), value(in.ConnectionArn)}, "\x00")
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorize(r, "ListApiDestinations", "*", nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		rows, err := r.APIDestinations(scope)
		if err != nil {
			return err
		}
		rows = slices.DeleteFunc(rows, func(v APIDestinationRecord) bool {
			return !strings.HasPrefix(v.Key.Name, value(in.NamePrefix)) || in.ConnectionArn != nil && v.ConnectionARN != value(in.ConnectionArn)
		})
		selected, next, rejected := page(rows, func(v APIDestinationRecord) string { return v.Key.Name }, collection, in.Limit, in.NextToken, "ValidationException")
		if rejected != nil {
			return rejected
		}
		out = &api.ListApiDestinationsOutput{ApiDestinations: api.ApiDestinationResponseList{}, NextToken: next}
		for _, v := range selected {
			state, err := apiDestinationState(r, v)
			if err != nil {
				return err
			}
			out.ApiDestinations = append(out.ApiDestinations, apiDestinationSummary(v, state))
		}
		return nil
	})
	return out, wireError(err)
}

func (s *Service) updateAPIDestination(ctx context.Context, in *api.UpdateApiDestinationInput) (out *api.UpdateApiDestinationOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "UpdateApiDestination", in, &out, &rejected, false)
	if in.InvocationEndpoint != nil {
		if rejected := validateAPIDestinationEndpoint(value(in.InvocationEndpoint), "update"); rejected != nil {
			return nil, rejected
		}
	}
	if in.HttpMethod != nil {
		if rejected := validateAPIDestinationMethod(value(in.HttpMethod)); rejected != nil {
			return nil, rejected
		}
	}
	if in.InvocationRateLimitPerSecond != nil {
		if rejected := validateAPIDestinationRate(int(*in.InvocationRateLimitPerSecond), value(in.Name), "update"); rejected != nil {
			return nil, rejected
		}
	}
	id := ""
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := readAPIDestination(tx, APIDestinationKey{scopeFor(ctx), value(in.Name)}, "update")
		if err != nil {
			return err
		}
		if err := s.authorizeAPIDestination(tx, "UpdateApiDestination", v); err != nil {
			return err
		}
		if in.ConnectionArn != nil {
			if _, err := apiDestinationConnection(tx, value(in.ConnectionArn), "update"); err != nil {
				return err
			}
			v.ConnectionARN = value(in.ConnectionArn)
		}
		if in.Description != nil {
			v.Description = value(in.Description)
		}
		if in.InvocationEndpoint != nil {
			v.Endpoint = value(in.InvocationEndpoint)
		}
		if in.HttpMethod != nil {
			v.Method = value(in.HttpMethod)
		}
		if in.InvocationRateLimitPerSecond != nil {
			v.Rate = int(*in.InvocationRateLimitPerSecond)
		}
		v.Modified = s.clock.Now().Truncate(time.Second)
		v.Version++
		state, err := apiDestinationState(tx, v)
		if err != nil {
			return err
		}
		if err := tx.PutAPIDestination(v); err != nil {
			return err
		}
		id = v.ID
		out = &api.UpdateApiDestinationOutput{ApiDestinationArn: str[api.ApiDestinationArn](v.ARN()), ApiDestinationState: str[api.ApiDestinationState](state), CreationTime: connectionTime(v.Created), LastModifiedTime: connectionTime(v.Modified)}
		return s.recordCall(tx.Context(), "UpdateApiDestination", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.cancelAPIDestination(id)
	return out, nil
}

func (s *Service) deleteAPIDestination(ctx context.Context, in *api.DeleteApiDestinationInput) (out *api.DeleteApiDestinationOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DeleteApiDestination", in, &out, &rejected, false)
	id := ""
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := readAPIDestination(tx, APIDestinationKey{scopeFor(ctx), value(in.Name)}, "delete")
		if err != nil {
			return err
		}
		if err := s.authorizeAPIDestination(tx, "DeleteApiDestination", v); err != nil {
			return err
		}
		if err := tx.DeleteAPIDestination(v.Key); err != nil {
			return err
		}
		id = v.ID
		out = &api.DeleteApiDestinationOutput{}
		return s.recordCall(tx.Context(), "DeleteApiDestination", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.cancelAPIDestination(id)
	return out, nil
}
