package lambda

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func provisionedReference(ctx context.Context, name, qualifier string) (FunctionReference, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, name, qualifier)
	if wire == nil && (ref.Qualifier == "" || ref.Qualifier == "$LATEST") {
		wire = failure("InvalidParameterValueException", "Provisioned Concurrency is not supported for $LATEST.", 400)
	}
	return ref, wire
}

func (s *Service) provisionedCountsLocked(v ProvisionedConcurrencyRecord) (int32, int32) {
	var allocated, available int32
	for key, pool := range s.environments {
		if key.FunctionKey != v.Key.FunctionKey {
			continue
		}
		for _, slot := range pool {
			if slot.provisioned != v.Key || slot.provisionedGeneration != v.Generation || slot.retiring {
				continue
			}
			if slot.provisionedReady {
				allocated++
				if !slot.leased {
					available++
				}
			}
		}
	}
	return allocated, available
}
func (s *Service) provisionedOutputLocked(v ProvisionedConcurrencyRecord) *api.GetProvisionedConcurrencyConfigOutput {
	a, available := s.provisionedCountsLocked(v)
	status := v.Status
	if status == "READY" && a < v.Requested {
		status = "IN_PROGRESS"
	}
	out := &api.GetProvisionedConcurrencyConfigOutput{RequestedProvisionedConcurrentExecutions: new(api.PositiveInteger(v.Requested)), AllocatedProvisionedConcurrentExecutions: new(api.NonNegativeInteger(a)), AvailableProvisionedConcurrentExecutions: new(api.NonNegativeInteger(available)), Status: new(api.ProvisionedConcurrencyStatusEnum(status)), LastModified: new(api.Timestamp(v.Modified.UTC().Format("2006-01-02T15:04:05-0700")))}
	if v.StatusReason != "" {
		out.StatusReason = new(api.String(v.StatusReason))
	}
	return out
}
func (s *Service) getProvisionedConcurrencyConfig(ctx context.Context, in *api.GetProvisionedConcurrencyConfigInput) (*api.GetProvisionedConcurrencyConfigOutput, *awswire.Error) {
	ref, wire := provisionedReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var v ProvisionedConcurrencyRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if _, err := s.runtimeControlFunction(r, ref, "GetProvisionedConcurrencyConfig"); err != nil {
			return err
		}
		if err := requireAliasOwner(r, ref); err != nil {
			return err
		}
		var err error
		v, err = r.ProvisionedConcurrency(ref)
		if errors.Is(err, ErrNotFound) {
			return failure("ProvisionedConcurrencyConfigNotFoundException", "No Provisioned Concurrency Config found for this function.", 404)
		}
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	return s.provisionedOutputLocked(v), nil
}
func (s *Service) putProvisionedConcurrencyConfig(ctx context.Context, in *api.PutProvisionedConcurrencyConfigInput) (*api.PutProvisionedConcurrencyConfigOutput, *awswire.Error) {
	ref, wire := provisionedReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	requested := int32(*in.ProvisionedConcurrentExecutions)
	if requested <= 0 {
		return nil, failure("InvalidParameterValueException", "ProvisionedConcurrentExecutions must be positive.", 400)
	}
	v := ProvisionedConcurrencyRecord{Key: ref, Requested: requested, Generation: uuid.NewString(), Status: "IN_PROGRESS", Modified: s.clock.Now()}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &api.PutProvisionedConcurrencyConfigOutput{RequestedProvisionedConcurrentExecutions: new(api.PositiveInteger(requested)), AllocatedProvisionedConcurrentExecutions: new(api.NonNegativeInteger(0)), AvailableProvisionedConcurrentExecutions: new(api.NonNegativeInteger(0)), Status: new(api.ProvisionedConcurrencyStatusEnumIN_PROGRESS), LastModified: new(api.Timestamp(v.Modified.UTC().Format("2006-01-02T15:04:05-0700")))}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, err := s.runtimeControlFunction(tx, ref, "PutProvisionedConcurrencyConfig")
		if err != nil {
			return err
		}
		if err := requireAliasOwner(tx, ref); err != nil {
			return err
		}
		if function.Capacity != nil {
			return failure("InvalidParameterValueException", "Lambda Managed Instances do not support provisioned concurrency.", 400)
		}
		if function.Version == 0 {
			return failure("InvalidParameterValueException", "Provisioned Concurrency is not supported for $LATEST.", 400)
		}
		if function.State != "Active" {
			return failure("ResourceConflictException", "The function is not active.", 409)
		}
		if s.executor == nil || s.roles == nil {
			return unsupported("No Lambda container executor is configured.")
		}
		if err := tx.PutProvisionedConcurrency(v); err != nil {
			return err
		}
		if err := validateProvisionedReservations(tx, ref.FunctionKey); err != nil {
			return err
		}
		if err := validateProvisionedOverlap(tx, ref.FunctionKey); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "PutProvisionedConcurrencyConfig", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.provisionedChangedLocked()
	return out, nil
}
func (s *Service) deleteProvisionedConcurrencyConfig(ctx context.Context, in *api.DeleteProvisionedConcurrencyConfigInput) (*api.DeleteProvisionedConcurrencyConfigOutput, *awswire.Error) {
	ref, wire := provisionedReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	s.mu.Lock()
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if _, err := s.runtimeControlFunction(tx, ref, "DeleteProvisionedConcurrencyConfig"); err != nil {
			return err
		}
		if err := requireAliasOwner(tx, ref); err != nil {
			return err
		}
		if err := tx.DeleteProvisionedConcurrency(ref); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "DeleteProvisionedConcurrencyConfig", in, nil, nil)
	})
	var idle []*execution
	if err == nil {
		idle = s.retireProvisionedLocked(ref)
		s.provisionedChangedLocked()
	}
	s.mu.Unlock()
	s.closeIdleExecutions(idle)
	if err != nil {
		return nil, wireError(err)
	}
	return &api.DeleteProvisionedConcurrencyConfigOutput{}, nil
}
func (s *Service) listProvisionedConcurrencyConfigs(ctx context.Context, in *api.ListProvisionedConcurrencyConfigsInput) (*api.ListProvisionedConcurrencyConfigsOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	out := &api.ListProvisionedConcurrencyConfigsOutput{ProvisionedConcurrencyConfigs: api.ProvisionedConcurrencyConfigList{}}
	limit := 50
	if in.MaxItems != nil {
		limit = int(*in.MaxItems)
	}
	marker := value(in.Marker)
	prefix := ref.ARN() + "/provisioned/"
	if marker != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(marker)
		if err != nil || !strings.HasPrefix(string(decoded), prefix) {
			return nil, failure("InvalidParameterValueException", "Invalid pagination marker.", 400)
		}
		marker = strings.TrimPrefix(string(decoded), prefix)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.repository.View(ctx, func(r Reader) error {
		if _, err := s.concurrencyFunction(r, ref, "ListProvisionedConcurrencyConfigs"); err != nil {
			return err
		}
		rows, err := r.AllProvisionedConcurrency()
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Key.FunctionKey != ref.FunctionKey || row.Key.Qualifier <= marker {
				continue
			}
			if len(out.ProvisionedConcurrencyConfigs) == limit {
				out.NextMarker = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(prefix + marker))))
				break
			}
			v := s.provisionedOutputLocked(row)
			out.ProvisionedConcurrencyConfigs = append(out.ProvisionedConcurrencyConfigs, api.ProvisionedConcurrencyConfigListItem{FunctionArn: new(api.FunctionArn(row.Key.ARN())), RequestedProvisionedConcurrentExecutions: v.RequestedProvisionedConcurrentExecutions, AllocatedProvisionedConcurrentExecutions: v.AllocatedProvisionedConcurrentExecutions, AvailableProvisionedConcurrentExecutions: v.AvailableProvisionedConcurrentExecutions, Status: v.Status, StatusReason: v.StatusReason, LastModified: v.LastModified})
			marker = row.Key.Qualifier
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

// committedProvisioned excludes reservations already covered by a function's
// reserved concurrency, so capacity is never charged twice.
func committedProvisioned(r Reader, scope Scope) (map[string]int64, int64, error) {
	rows, err := r.AllProvisionedConcurrency()
	if err != nil {
		return nil, 0, err
	}
	counts := map[string]int64{}
	for _, row := range rows {
		if row.Key.Scope == scope {
			counts[row.Key.Name] += int64(row.Requested)
		}
	}
	var unreserved int64
	for name, n := range counts {
		_, present, err := r.FunctionConcurrency(FunctionKey{Scope: scope, Name: name})
		if err != nil {
			return nil, 0, err
		}
		if !present {
			unreserved += n
		}
	}
	return counts, unreserved, nil
}
func validateProvisionedReservations(r Reader, key FunctionKey) error {
	counts, unreserved, err := committedProvisioned(r, key.Scope)
	if err != nil {
		return err
	}
	reserved, present, err := r.FunctionConcurrency(key)
	if err != nil {
		return err
	}
	if present && counts[key.Name] > int64(reserved) {
		return failure("InvalidParameterValueException", "Provisioned Concurrency cannot exceed Reserved Concurrency for the function.", 400)
	}
	usage, err := r.AccountUsage(key.Scope)
	if err != nil {
		return err
	}
	if usage.ReservedConcurrency+unreserved > lambdaConcurrentExecutions-lambdaUnreservedMinimum {
		return failure("InvalidParameterValueException", "Insufficient unreserved concurrency; at least 100 executions must remain unreserved.", 400)
	}
	return nil
}

func provisionedVersion(ref FunctionReference) (uint64, bool) {
	v, err := strconv.ParseUint(ref.Qualifier, 10, 64)
	return v, err == nil && v != 0
}

func validateProvisionedOverlap(r Reader, key FunctionKey) error {
	rows, err := r.AllProvisionedConcurrency()
	if err != nil {
		return err
	}
	direct := map[uint64]bool{}
	for _, row := range rows {
		if row.Key.FunctionKey != key {
			continue
		}
		if version, numeric := provisionedVersion(row.Key); numeric {
			direct[version] = true
		}
	}
	for _, row := range rows {
		if row.Key.FunctionKey != key {
			continue
		}
		if _, numeric := provisionedVersion(row.Key); numeric {
			continue
		}
		alias, err := r.Alias(row.Key)
		if err != nil {
			return err
		}
		if alias.FunctionVersion == 0 {
			return failure("InvalidParameterValueException", "Provisioned Concurrency Configs cannot be applied to unpublished function versions.", 400)
		}
		if direct[alias.FunctionVersion] || alias.AdditionalVersion != 0 && direct[alias.AdditionalVersion] {
			return failure("ResourceConflictException", "Alias can't be used for Provisioned Concurrency configuration on an already Provisioned version", 409)
		}
	}
	return nil
}
