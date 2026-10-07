package lambda

import (
	"context"
	"encoding/base64"
	"errors"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func codeSigningFunctionReference(ctx context.Context, name string) (FunctionReference, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, name, "")
	if wire != nil {
		return ref, wire
	}
	if ref.Qualifier != "" {
		return ref, failure("InvalidParameterValueException", "Code signing configuration requires an unqualified function name.", 400)
	}
	return ref, nil
}

func (s *Service) putFunctionCodeSigningConfig(ctx context.Context, in *api.PutFunctionCodeSigningConfigInput) (*api.PutFunctionCodeSigningConfigOutput, *awswire.Error) {
	ref, wire := codeSigningFunctionReference(ctx, value(in.FunctionName))
	if wire != nil {
		return nil, wire
	}
	key, wire := parseCodeSigningConfigARN(ctx, value(in.CodeSigningConfigArn))
	if wire != nil {
		return nil, wire
	}
	out := &api.PutFunctionCodeSigningConfigOutput{FunctionName: new(api.FunctionName(ref.Name)), CodeSigningConfigArn: new(api.CodeSigningConfigArn(key.ARN()))}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, err := tx.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, "PutFunctionCodeSigningConfig", ref, function, map[string][]string{"lambda:CodeSigningConfigArn": {key.ARN()}}); wire != nil {
			return wire
		}
		if function.Image != nil {
			return failure("InvalidParameterValueException", "Code signing is supported only for Zip functions.", 400)
		}
		if function.State == "Pending" || function.UpdateStatus == "InProgress" {
			return failure("ResourceConflictException", "An operation is in progress for this function.", 409)
		}
		if _, err := tx.CodeSigningConfig(key); err != nil {
			if errors.Is(err, ErrNotFound) {
				return failure("CodeSigningConfigNotFoundException", "Code signing configuration not found.", 404)
			}
			return err
		}
		if key.Scope != ref.Scope {
			return failure("CodeSigningConfigNotFoundException", "Code signing configuration not found.", 404)
		}
		// Attaching a policy is deliberately non-retroactive. AWS validates code
		// only when a new package or layer is subsequently deployed.
		if err := tx.PutFunctionCodeSigningConfig(ref.FunctionKey, key); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "PutFunctionCodeSigningConfig", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) getFunctionCodeSigningConfig(ctx context.Context, in *api.GetFunctionCodeSigningConfigInput) (*api.GetFunctionCodeSigningConfigOutput, *awswire.Error) {
	ref, wire := codeSigningFunctionReference(ctx, value(in.FunctionName))
	if wire != nil {
		return nil, wire
	}
	out := &api.GetFunctionCodeSigningConfigOutput{}
	err := s.repository.View(ctx, func(r Reader) error {
		function, err := r.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(r, "GetFunctionCodeSigningConfig", ref, function, nil); wire != nil {
			return wire
		}
		key, err := r.FunctionCodeSigningConfig(ref.FunctionKey)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		out.FunctionName, out.CodeSigningConfigArn = new(api.FunctionName(ref.Name)), new(api.CodeSigningConfigArn(key.ARN()))
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) deleteFunctionCodeSigningConfig(ctx context.Context, in *api.DeleteFunctionCodeSigningConfigInput) (*api.DeleteFunctionCodeSigningConfigOutput, *awswire.Error) {
	ref, wire := codeSigningFunctionReference(ctx, value(in.FunctionName))
	if wire != nil {
		return nil, wire
	}
	out := &api.DeleteFunctionCodeSigningConfigOutput{}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, err := tx.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, "DeleteFunctionCodeSigningConfig", ref, function, nil); wire != nil {
			return wire
		}
		if function.State == "Pending" || function.UpdateStatus == "InProgress" {
			return failure("ResourceConflictException", "An operation is in progress for this function.", 409)
		}
		if err := tx.DeleteFunctionCodeSigningConfig(ref.FunctionKey); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "DeleteFunctionCodeSigningConfig", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) listFunctionsByCodeSigningConfig(ctx context.Context, in *api.ListFunctionsByCodeSigningConfigInput) (*api.ListFunctionsByCodeSigningConfigOutput, *awswire.Error) {
	key, wire := parseCodeSigningConfigARN(ctx, value(in.CodeSigningConfigArn))
	if wire != nil {
		return nil, wire
	}
	prefix := "code-signing-functions:" + key.ARN() + ":"
	after, limit, wire := codeSigningCursor(value(in.Marker), prefix, in.MaxItems)
	if wire != nil {
		return nil, wire
	}
	out := &api.ListFunctionsByCodeSigningConfigOutput{FunctionArns: api.FunctionArnList{}}
	err := s.repository.View(ctx, func(r Reader) error {
		if _, err := s.loadCodeSigningConfig(r, key, "ListFunctionsByCodeSigningConfig", nil, nil); err != nil {
			return err
		}
		functions, err := r.FunctionsByCodeSigningConfig(key)
		if err != nil {
			return err
		}
		last := ""
		for _, function := range functions {
			arn := function.ARN()
			if arn <= after {
				continue
			}
			if len(out.FunctionArns) == limit {
				out.NextMarker = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(prefix + last))))
				break
			}
			out.FunctionArns = append(out.FunctionArns, api.FunctionArn(arn))
			last = arn
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
