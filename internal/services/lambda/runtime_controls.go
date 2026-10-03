package lambda

import (
	"context"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func (s *Service) registerRuntimeControls() {
	register(s, "GetFunctionRecursionConfig", s.getFunctionRecursionConfig)
	register(s, "PutFunctionRecursionConfig", s.putFunctionRecursionConfig)
	register(s, "GetRuntimeManagementConfig", s.getRuntimeManagementConfig)
	register(s, "PutRuntimeManagementConfig", s.putRuntimeManagementConfig)
	register(s, "GetProvisionedConcurrencyConfig", s.getProvisionedConcurrencyConfig)
	register(s, "PutProvisionedConcurrencyConfig", s.putProvisionedConcurrencyConfig)
	register(s, "DeleteProvisionedConcurrencyConfig", s.deleteProvisionedConcurrencyConfig)
	register(s, "ListProvisionedConcurrencyConfigs", s.listProvisionedConcurrencyConfigs)
}

func (s *Service) getFunctionRecursionConfig(ctx context.Context, in *api.GetFunctionRecursionConfigInput) (*api.GetFunctionRecursionConfigOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	var mode string
	err := s.repository.View(ctx, func(r Reader) error {
		if _, err := s.concurrencyFunction(r, ref, "GetFunctionRecursionConfig"); err != nil {
			return err
		}
		var err error
		mode, err = r.RecursiveLoop(ref.FunctionKey)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.GetFunctionRecursionConfigOutput{RecursiveLoop: new(api.RecursiveLoop(mode))}, nil
}
func (s *Service) putFunctionRecursionConfig(ctx context.Context, in *api.PutFunctionRecursionConfigInput) (*api.PutFunctionRecursionConfigOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	mode := value(in.RecursiveLoop)
	if mode != "Allow" && mode != "Terminate" {
		return nil, failure("InvalidParameterValueException", "RecursiveLoop must be Allow or Terminate.", 400)
	}
	out := &api.PutFunctionRecursionConfigOutput{RecursiveLoop: new(api.RecursiveLoop(mode))}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if _, err := s.concurrencyFunction(tx, ref, "PutFunctionRecursionConfig"); err != nil {
			return err
		}
		if err := tx.PutRecursiveLoop(ref.FunctionKey, mode); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "PutFunctionRecursionConfig", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) runtimeControlFunction(r Reader, ref FunctionReference, action string) (FunctionRecord, error) {
	base, err := r.Function(ref.FunctionKey)
	if err != nil {
		return FunctionRecord{}, err
	}
	if wire := s.authorizeFunction(r, action, ref, base, nil); wire != nil {
		return FunctionRecord{}, wire
	}
	if err := requireVersionOwner(r, ref); err != nil {
		return FunctionRecord{}, err
	}
	return loadFunction(r, ref)
}
func (s *Service) getRuntimeManagementConfig(ctx context.Context, in *api.GetRuntimeManagementConfigInput) (*api.GetRuntimeManagementConfigOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	out := &api.GetRuntimeManagementConfigOutput{}
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := s.runtimeControlFunction(r, ref, "GetRuntimeManagementConfig")
		if err != nil {
			return err
		}
		key := FunctionVersionKey{FunctionKey: v.Key, Version: v.Version}
		mode, err := r.RuntimeManagement(key)
		if err != nil {
			return err
		}
		out.FunctionArn = new(api.NameSpacedFunctionArn(key.ARN()))
		out.UpdateRuntimeOn = new(api.UpdateRuntimeOn(mode))
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) putRuntimeManagementConfig(ctx context.Context, in *api.PutRuntimeManagementConfigInput) (*api.PutRuntimeManagementConfigOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	mode := value(in.UpdateRuntimeOn)
	if mode != "Auto" && mode != "FunctionUpdate" && mode != "Manual" {
		return nil, failure("InvalidParameterValueException", "Invalid runtime update mode.", 400)
	}
	out := &api.PutRuntimeManagementConfigOutput{UpdateRuntimeOn: new(api.UpdateRuntimeOn(mode))}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.runtimeControlFunction(tx, ref, "PutRuntimeManagementConfig")
		if err != nil {
			return err
		}
		if mode == "Manual" {
			// TODO: Comeback map AWS managed runtime-version ARNs to verified executable images; a local image digest is not an AWS runtime version.
			return unsupported("Manual runtime versions require an executable managed runtime-version catalog; this executor uses operator-pinned runtime/architecture images.")
		}
		if in.RuntimeVersionArn != nil {
			return failure("InvalidParameterValueException", "RuntimeVersionArn is only valid with Manual runtime updates.", 400)
		}
		key := FunctionVersionKey{FunctionKey: v.Key, Version: v.Version}
		out.FunctionArn = new(api.FunctionArn(key.ARN()))
		if err := tx.PutRuntimeManagement(key, mode); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "PutRuntimeManagementConfig", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
