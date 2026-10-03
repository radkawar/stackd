package lambda

import (
	"context"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

// LatestPublishedVersion is reserved for Lambda Managed Instances' mutable
// published deployment. It never advances the ordinary numbered-version counter.
const LatestPublishedVersion uint64 = math.MaxInt64

func capacityFunctionOutput(v *CapacityFunctionConfig) *api.CapacityProviderConfig {
	if v == nil {
		return nil
	}
	return &api.CapacityProviderConfig{LambdaManagedInstancesCapacityProviderConfig: &api.LambdaManagedInstancesCapacityProviderConfig{CapacityProviderArn: new(api.CapacityProviderArn(v.ProviderARN)), ExecutionEnvironmentMemoryGiBPerVCpu: new(api.ExecutionEnvironmentMemoryGiBPerVCpu(v.MemoryGiBPerVCPU)), PerExecutionEnvironmentMaxConcurrency: new(api.PerExecutionEnvironmentMaxConcurrency(v.MaxConcurrency))}}
}
func (s *Service) validateCapacityAssignment(ctx context.Context, in *api.CapacityProviderConfig, functionARN, runtimeName, architecture string, memoryMB int) (*CapacityFunctionConfig, *awswire.Error) {
	if in == nil {
		return nil, nil
	}
	if in.LambdaManagedInstancesCapacityProviderConfig == nil {
		return nil, capacityParameter("LambdaManagedInstancesCapacityProviderConfig is required.")
	}
	configuration := in.LambdaManagedInstancesCapacityProviderConfig
	key, err := capacityKey(ctx, value(configuration.CapacityProviderArn))
	if err != nil {
		return nil, wireError(err)
	}
	config := &CapacityFunctionConfig{ProviderARN: key.ARN(), MemoryGiBPerVCPU: 2}
	if configuration.ExecutionEnvironmentMemoryGiBPerVCpu != nil {
		config.MemoryGiBPerVCPU = float64(*configuration.ExecutionEnvironmentMemoryGiBPerVCpu)
	}
	if config.MemoryGiBPerVCPU != 2 && config.MemoryGiBPerVCPU != 4 && config.MemoryGiBPerVCPU != 8 {
		return nil, capacityParameter("ExecutionEnvironmentMemoryGiBPerVCpu must be 2, 4, or 8.")
	}
	cpus := float64(memoryMB) / (1024 * config.MemoryGiBPerVCPU)
	if memoryMB < 2048 || cpus < 1 || math.Trunc(cpus) != cpus {
		return nil, capacityParameter("Managed function memory must allocate an integral number of vCPUs, at least one vCPU and 2048 MB.")
	}
	config.MaxConcurrency = int(cpus) * 8
	if configuration.PerExecutionEnvironmentMaxConcurrency != nil {
		config.MaxConcurrency = int(*configuration.PerExecutionEnvironmentMaxConcurrency)
	}
	if config.MaxConcurrency < 1 || config.MaxConcurrency > 64*int(cpus) {
		return nil, capacityParameter("Managed concurrency must be between 1 and 64 per vCPU.")
	}
	if runtimeName == "python3.12" {
		return nil, capacityParameter("Python managed-instance runtimes require Python 3.13 or newer.")
	}
	if s.capacityBackend == nil {
		return nil, unsupported("A real managed EC2 guest backend is required.")
	}
	err = s.repository.View(ctx, func(r Reader) error {
		provider, err := r.CapacityProvider(key)
		if err != nil {
			return err
		}
		if provider.State != "Active" {
			return failure("ResourceConflictException", "Capacity provider is not active.", 409)
		}
		if provider.Architecture != architecture {
			return capacityParameter("Function architecture does not match the capacity provider.")
		}
		if rejected := s.authorizeCapacity(r.Context(), "PassCapacityProvider", provider); rejected != nil {
			return rejected
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return config, nil
}

// validateCapacityFunction repeats the current provider and caller authority
// under the function command's final storage transaction after external checks.
func (s *Service) validateCapacityFunction(r Reader, v FunctionRecord) error {
	if v.Capacity == nil {
		return nil
	}
	if err := validateCapacityDeployment(v); err != nil {
		return err
	}
	key, err := capacityKey(r.Context(), v.Capacity.ProviderARN)
	if err != nil {
		return err
	}
	provider, err := r.CapacityProvider(key)
	if err != nil {
		return err
	}
	if provider.State != "Active" {
		return failure("ResourceConflictException", "Capacity provider is not active.", 409)
	}
	if provider.Architecture != v.Architecture {
		return capacityParameter("Function architecture does not match the capacity provider.")
	}
	if rejected := s.authorizeCapacity(r.Context(), "PassCapacityProvider", provider); rejected != nil {
		return rejected
	}
	return nil
}
func validateCapacityDeployment(v FunctionRecord) error {
	c := v.Capacity
	if c == nil {
		return nil
	}
	if c.MemoryGiBPerVCPU != 2 && c.MemoryGiBPerVCPU != 4 && c.MemoryGiBPerVCPU != 8 {
		return capacityParameter("ExecutionEnvironmentMemoryGiBPerVCpu must be 2, 4, or 8.")
	}
	cpus := float64(v.MemoryMB) / (1024 * c.MemoryGiBPerVCPU)
	if v.MemoryMB < 2048 || v.MemoryMB > 32768 || cpus < 1 || math.Trunc(cpus) != cpus {
		return capacityParameter("Managed memory must be 2048-32768 MB and allocate an integral number of vCPUs.")
	}
	if c.MaxConcurrency < 1 || c.MaxConcurrency > 64*int(cpus) {
		return capacityParameter("Managed concurrency must be between 1 and 64 per vCPU.")
	}
	if v.Timeout < 1 || v.Timeout > 5400 {
		return capacityParameter("Managed function timeout must be between 1 and 5400 seconds.")
	}
	switch v.Runtime {
	case "python3.13", "python3.14", "nodejs22.x", "nodejs24.x", "java21", "java25", "dotnet8", "dotnet10", "provided.al2023":
	default:
		return capacityParameter("Runtime does not support Lambda Managed Instances.")
	}
	if v.EphemeralMB != 512 {
		return unsupported("Managed guest ephemeral storage sizes other than 512 MB are not implemented.")
	}
	if v.Durable != nil {
		return unsupported("Durable execution on managed instances is not implemented.")
	}
	return nil
}
func publishCapacitySnapshot(tx Transaction, latest FunctionRecord, description *api.Description) (FunctionRecord, bool, error) {
	if latest.Capacity == nil {
		return FunctionRecord{}, false, publishToError()
	}
	if err := validateCapacityPublication(tx, latest, LatestPublishedVersion); err != nil {
		return FunctionRecord{}, false, err
	}
	published := latest
	published.Version = LatestPublishedVersion
	published.Revision = uuid.NewString()
	published.Tags = nil
	published.State = "Pending"
	published.StateReason = "Provisioning Lambda managed execution environments."
	published.StateReasonCode = "Creating"
	published.UpdateStatus = ""
	published.UpdateReason = ""
	if description != nil {
		published.Description = string(*description)
	}
	if err := tx.ReplaceCapacityPublishedFunction(published); err != nil {
		return FunctionRecord{}, false, err
	}
	return published, true, nil
}
func capacityScalingReference(ctx context.Context, name, qualifier string) (FunctionReference, *awswire.Error) {
	ref, rejected := parseFunctionReference(ctx, name, qualifier)
	if rejected != nil {
		return ref, rejected
	}
	if ref.Qualifier == "$LATEST.PUBLISHED" {
		return ref, nil
	}
	version, err := strconv.ParseUint(ref.Qualifier, 10, 64)
	if err != nil || version == 0 || version >= LatestPublishedVersion {
		return ref, capacityParameter("Function scaling requires a numbered version or $LATEST.PUBLISHED.")
	}
	return ref, nil
}
func requestedCapacityScaling(in *api.FunctionScalingConfig) (int32, int32, error) {
	minimum, maximum := int32(3), int32(15000)
	if in != nil {
		if in.MinExecutionEnvironments != nil {
			minimum = int32(*in.MinExecutionEnvironments)
		}
		if in.MaxExecutionEnvironments != nil {
			maximum = int32(*in.MaxExecutionEnvironments)
		}
	}
	if minimum < 0 || maximum < 0 || minimum > 15000 || maximum > 15000 || minimum > maximum || (minimum == 0 && maximum != 0) || (minimum > 0 && minimum < 3) {
		return 0, 0, capacityParameter("Invalid managed execution environment bounds; zero minimum requires zero maximum.")
	}
	return minimum, maximum, nil
}
func capacityScalingOutput(minimum, maximum int32) *api.FunctionScalingConfig {
	return &api.FunctionScalingConfig{MinExecutionEnvironments: new(api.FunctionScalingConfigExecutionEnvironments(minimum)), MaxExecutionEnvironments: new(api.FunctionScalingConfigExecutionEnvironments(maximum))}
}
func effectiveCapacityScaling(r Reader, f FunctionRecord) (CapacityScalingRecord, error) {
	ref := FunctionReference{FunctionKey: f.Key, Qualifier: versionName(f.Version)}
	v, err := r.CapacityScaling(ref)
	if errors.Is(err, ErrNotFound) {
		return CapacityScalingRecord{Key: ref, Generation: f.DeploymentRevision, MinEnvironments: 3, MaxEnvironments: 15000}, nil
	}
	return v, err
}
func (s *Service) getCapacityScaling(ctx context.Context, in *api.GetFunctionScalingConfigRequest) (*api.GetFunctionScalingConfigResponse, *awswire.Error) {
	ref, rejected := capacityScalingReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if rejected != nil {
		return nil, rejected
	}
	var out *api.GetFunctionScalingConfigResponse
	err := s.repository.View(ctx, func(r Reader) error {
		f, err := loadFunction(r, ref)
		if err != nil {
			return err
		}
		authFunction := f
		if _, constrained := r.Context().Value(versionOwnerContextKey{}).(VersionOwner); constrained {
			authFunction, err = r.Function(ref.FunctionKey)
			if err != nil {
				return err
			}
		}
		if rejected := s.authorizeFunction(r, "GetFunctionScalingConfig", ref, authFunction, nil); rejected != nil {
			return rejected
		}
		if err := requireVersionOwner(r, ref); err != nil {
			return err
		}
		if f.Capacity == nil {
			return capacityParameter("Function scaling is available only for Lambda Managed Instances.")
		}
		v, err := effectiveCapacityScaling(r, f)
		if err != nil {
			return err
		}
		out = &api.GetFunctionScalingConfigResponse{FunctionArn: new(api.FunctionArn(ref.ARN())), RequestedFunctionScalingConfig: capacityScalingOutput(v.MinEnvironments, v.MaxEnvironments), AppliedFunctionScalingConfig: capacityScalingOutput(v.AppliedMin, v.AppliedMax)}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) putCapacityScaling(ctx context.Context, in *api.PutFunctionScalingConfigRequest) (*api.PutFunctionScalingConfigResponse, *awswire.Error) {
	ref, rejected := capacityScalingReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if rejected != nil {
		return nil, rejected
	}
	minimum, maximum, err := requestedCapacityScaling(in.FunctionScalingConfig)
	if err != nil {
		return nil, wireError(err)
	}
	var out *api.PutFunctionScalingConfigResponse
	err = s.repository.Update(ctx, func(tx Transaction) error {
		f, err := loadFunction(tx, ref)
		if err != nil {
			return err
		}
		authFunction := f
		if _, constrained := tx.Context().Value(versionOwnerContextKey{}).(VersionOwner); constrained {
			authFunction, err = tx.Function(ref.FunctionKey)
			if err != nil {
				return err
			}
		}
		if rejected := s.authorizeFunction(tx, "PutFunctionScalingConfig", ref, authFunction, nil); rejected != nil {
			return rejected
		}
		if err := requireVersionOwner(tx, ref); err != nil {
			return err
		}
		if f.Capacity == nil {
			return capacityParameter("Function scaling is available only for Lambda Managed Instances.")
		}
		v, err := effectiveCapacityScaling(tx, f)
		if err != nil {
			return err
		}
		v.Generation = uuid.NewString()
		v.MinEnvironments, v.MaxEnvironments = minimum, maximum
		v.Modified = s.clock.Now().UTC()
		if err = tx.PutCapacityScaling(v); err != nil {
			return err
		}
		out = &api.PutFunctionScalingConfigResponse{FunctionState: new(api.State(f.State))}
		return s.recordCall(tx.Context(), "PutFunctionScalingConfig", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func (s *Service) activateManaged(v FunctionRecord) {
	// $LATEST is deployment metadata, not an executable managed version. This
	// validates the real backend before activation; published readiness is owned
	// exclusively by capacityJobs after guest Runtime API initialization.
	ctx, cancel := context.WithTimeout(ownerContext(s.lifetime, v.Key), 30*time.Second)
	defer cancel()
	var provider CapacityProviderRecord
	err := s.repository.View(ctx, func(r Reader) error {
		key, err := capacityKey(r.Context(), v.Capacity.ProviderARN)
		if err != nil {
			return err
		}
		provider, err = r.CapacityProvider(key)
		return err
	})
	if err == nil && s.capacityBackend == nil {
		err = unsupported("A managed EC2 guest backend is required.")
	}
	if err == nil {
		err = s.capacityBackend.Validate(ctx, provider)
	}
	_ = s.repository.Update(ctx, func(tx Transaction) error {
		current, loadErr := tx.Function(v.Key)
		if loadErr != nil {
			return loadErr
		}
		if current.DeploymentRevision != v.DeploymentRevision {
			return nil
		}
		current.Revision = uuid.NewString()
		if err == nil {
			current.State = "Active"
			current.StateReason = ""
			current.StateReasonCode = ""
		} else {
			current.State = "Failed"
			current.StateReason = err.Error()
			current.StateReasonCode = "InternalError"
		}
		return tx.PutFunction(current)
	})
	s.jobs.Wake()
}
