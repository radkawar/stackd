package lambda

import (
	"context"
	"errors"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func (s *Service) authorizeUpdate(ctx context.Context, ref FunctionReference, action string, extra map[string][]string) (FunctionRecord, *awswire.Error) {
	var current FunctionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		current, err = r.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(r, action, ref, current, extra); wire != nil {
			return wire
		}
		return nil
	})
	if err != nil {
		return current, wireError(err)
	}
	return current, nil
}

func (s *Service) updateCode(ctx context.Context, in *api.UpdateFunctionCodeInput) (*api.UpdateFunctionCodeOutput, *awswire.Error) {
	if in.ImageUri != nil || in.SourceKMSKeyArn != nil {
		return nil, unsupported("ECR deployment and customer-key encryption are not implemented.")
	}
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	if ref.Qualifier != "" && ref.Qualifier != "$LATEST" {
		return nil, failure("InvalidParameterValueException", "Published versions are immutable; update $LATEST.", 400)
	}
	key := ref.FunctionKey
	current, wire := s.authorizeUpdate(ctx, ref, "UpdateFunctionCode", nil)
	if wire != nil {
		return nil, wire
	}
	archive, reference, wire := s.loadCode(ctx, key.Scope, key.ARN(), in.ZipFile, value(in.S3Bucket), value(in.S3Key), value(in.S3ObjectVersion), value(in.S3ObjectStorageMode))
	if wire != nil {
		return nil, wire
	}
	signing, wire := s.prepareCodeSigning(ctx, key, "", archive.Code, current.Layers)
	if wire != nil {
		return nil, wire
	}
	dryRun := in.DryRun != nil && bool(*in.DryRun)
	return s.stageUpdate(ctx, in, ref, "UpdateFunctionCode", in.RevisionId, false, dryRun, in.Publish != nil && bool(*in.Publish), in.PublishTo, func(tx Transaction, v *FunctionRecord) *awswire.Error {
		if current.DeploymentRevision != v.DeploymentRevision {
			return failure("ResourceConflictException", "The function deployment changed during signature verification.", 409)
		}
		if err := signing.commit(tx, false); err != nil {
			return wireError(err)
		}
		signing.applyFunction(v)
		v.CodeSHA256, v.CodeSize, v.Reference = archive.Key.SHA256, int64(len(archive.Code)), reference
		s.scheduleCodeSourceCheck(v)
		if wire := validateDeploymentCode(tx, archive.Code, v.Layers); wire != nil {
			return wire
		}
		if !dryRun {
			if err := tx.PutCodeArchive(archive); err != nil {
				return wireError(err)
			}
		}
		if len(in.Architectures) > 0 {
			v.Architecture = string(in.Architectures[0])
		}
		return nil
	})
}
func (s *Service) updateConfiguration(ctx context.Context, in *api.UpdateFunctionConfigurationInput) (*api.UpdateFunctionConfigurationOutput, *awswire.Error) {
	if in.VpcConfig != nil || in.KMSKeyArn != nil || in.FileSystemConfigs != nil || in.ImageConfig != nil || in.SnapStart != nil {
		return nil, unsupported("The requested advanced Lambda deployment configuration is not implemented.")
	}
	if wire := validateTracingConfiguration(in.TracingConfig); wire != nil {
		return nil, wire
	}
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	if ref.Qualifier != "" && ref.Qualifier != "$LATEST" {
		return nil, failure("InvalidParameterValueException", "Published versions are immutable; update $LATEST.", 400)
	}
	current, wire := s.authorizeUpdate(ctx, ref, "UpdateFunctionConfiguration", layerConditions(in.Layers))
	if wire != nil {
		return nil, wire
	}
	if current.State == "Inactive" && current.Reference != nil {
		if s.codeSource == nil {
			return nil, unsupported("S3 deployment sources require configured S3 commands.")
		}
		if _, wire := s.codeSource.ReadReference(ctx, current.Key.Scope, current.Key.ARN(), *current.Reference); wire != nil {
			return nil, wire
		}
	}
	var layers []LayerAttachment
	if in.Layers != nil {
		layers, wire = s.prepareLayers(ctx, ref.FunctionKey, layerStrings(in.Layers))
		if wire != nil {
			return nil, wire
		}
	}
	var vars map[string]string
	if in.Environment != nil {
		vars, wire = variables(in.Environment)
		if wire != nil {
			return nil, wire
		}
	}
	var signing *codeSigningAdmission
	if in.Layers != nil {
		signing, wire = s.prepareCodeSigning(ctx, ref.FunctionKey, "", nil, layers)
		if wire != nil {
			return nil, wire
		}
	}
	capacity := cloneCapacityFunction(current.Capacity)
	if in.CapacityProviderConfig != nil {
		runtime, memory := current.Runtime, current.MemoryMB
		if in.Runtime != nil {
			runtime = value(in.Runtime)
		}
		if in.MemorySize != nil {
			memory = int(*in.MemorySize)
		}
		capacity, wire = s.validateCapacityAssignment(ctx, in.CapacityProviderConfig, current.Key.ARN(), runtime, current.Architecture, memory)
		if wire != nil {
			return nil, wire
		}
	}
	durable := current
	if in.Runtime != nil {
		durable.Runtime = value(in.Runtime)
	}
	if wire := applyDurableConfig(&durable, in.DurableConfig, false); wire != nil {
		return nil, wire
	}
	if in.DurableConfig != nil {
		if wire := s.validateDurableEncryption(ctx, &durable); wire != nil {
			return nil, wire
		}
	}
	return s.stageUpdate(ctx, in, ref, "UpdateFunctionConfiguration", in.RevisionId, in.Role != nil, false, false, nil, func(tx Transaction, v *FunctionRecord) *awswire.Error {
		// Preflight source access cannot authorize a different deployment, or a
		// function that became inactive after the preflight selected an active one.
		if !sameCodeSourceDeployment(current, *v) || current.State != v.State {
			return failure("ResourceConflictException", "The function deployment changed during source preparation.", 409)
		}
		if err := signing.commit(tx, false); err != nil {
			return wireError(err)
		}
		v.Capacity = capacity
		if wire := configureLogging(v, in.LoggingConfig); wire != nil {
			return wire
		}
		if in.Runtime != nil {
			v.Runtime = value(in.Runtime)
		}
		v.Durable = cloneDurableConfig(durable.Durable)
		if in.Handler != nil {
			v.Handler = value(in.Handler)
		}
		if in.Role != nil {
			v.Role = value(in.Role)
		}
		if in.DeadLetterConfig != nil && in.DeadLetterConfig.TargetArn != nil {
			v.DeadLetterARN = value(in.DeadLetterConfig.TargetArn)
		}
		if in.Description != nil {
			v.Description = value(in.Description)
		}
		if in.Timeout != nil {
			v.Timeout = int(*in.Timeout)
		}
		if in.MemorySize != nil {
			v.MemoryMB = int(*in.MemorySize)
		}
		if in.EphemeralStorage != nil {
			v.EphemeralMB = int(*in.EphemeralStorage.Size)
		}
		if in.Environment != nil {
			v.Variables = vars
		}
		if in.Layers != nil {
			if wire := requireLayerCatalog(tx, layers); wire != nil {
				return wire
			}
			v.Layers = layers
		}
		if in.Layers != nil && len(v.Layers) != 0 {
			archive, err := tx.CodeArchive(CodeArchiveKey{Scope: v.Key.Scope, SHA256: v.CodeSHA256})
			if err != nil {
				return wireError(err)
			}
			if wire := validateDeploymentCode(tx, archive.Code, v.Layers); wire != nil {
				return wire
			}
		}
		return validateDeployment(*v)
	})
}
func (s *Service) stageUpdate(ctx context.Context, input any, ref FunctionReference, action string, revision *api.String, passRole, dryRun, publish bool, publishTo *api.FunctionVersionLatestPublished, change func(Transaction, *FunctionRecord) *awswire.Error) (*api.FunctionConfiguration, *awswire.Error) {
	key := ref.FunctionKey
	if s.executor == nil {
		return nil, unsupported("No Lambda container executor is configured.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return nil, failure("ServiceException", "Lambda service is shutting down.", 503)
	}
	var candidate FunctionRecord
	var response *api.FunctionConfiguration
	var publicationError *awswire.Error
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Function(key)
		if err != nil {
			return err
		}
		if current.State == "Pending" || current.UpdateStatus == "InProgress" {
			return failure("ResourceConflictException", "A function deployment is already in progress.", 409)
		}
		if !dryRun && revision != nil && value(revision) != current.Revision {
			return failure("PreconditionFailedException", "The RevisionId does not match the current function revision.", 412)
		}
		candidate = current
		if wire := change(tx, &candidate); wire != nil {
			return wire
		}
		if err := s.validateCapacityFunction(tx, candidate); err != nil {
			return wireError(err)
		}
		if dryRun && publish {
			return failure("InvalidParameterValueException", "Publish and DryRun are mutually exclusive parameters. Please provide only one of the two parameters and try again.", 400)
		}
		if passRole {
			if wire := s.roles.Validate(tx.Context(), candidate.Role, key.ARN()); wire != nil {
				return wire
			}
		}
		if candidate.DeadLetterARN != current.DeadLetterARN {
			if wire := s.checkOutcomeTarget(tx.Context(), key, candidate.Role, candidate.DeadLetterARN, true, false); wire != nil {
				return wire
			}
		}
		if dryRun {
			candidate.State, candidate.StateReason, candidate.StateReasonCode = "Pending", "The function is being restored.", "Restoring"
			candidate.Modified = s.clock.Now()
			response = configuration(candidate)
			return s.recordCall(tx.Context(), action, input, response, nil)
		}
		candidate.Revision = uuid.NewString()
		candidate.DeploymentRevision = candidate.Revision
		candidate.Modified = s.clock.Now()
		candidate.UpdateStatus = "InProgress"
		candidate.UpdateReason = "The function is being updated."
		current.UpdateStatus = candidate.UpdateStatus
		current.UpdateReason = candidate.UpdateReason
		if err := tx.PutFunction(current); err != nil {
			return err
		}
		if err := tx.PutPendingFunction(candidate); err != nil {
			return err
		}
		response = configuration(candidate)
		if publish {
			if publishTo != nil && candidate.Capacity == nil {
				// Native commits the latest-code update before rejecting this
				// publication target. Keep the deployment and its readiness work.
				publicationError = publishToError()
				return s.recordCall(tx.Context(), action, input, nil, publicationError)
			}
			var published FunctionRecord
			var err error
			if publishTo != nil {
				published, _, err = publishCapacitySnapshot(tx, candidate, nil)
			} else {
				published, _, err = publishSnapshot(tx, candidate, nil)
			}
			if err != nil {
				return err
			}
			response = configuration(published)
		}
		if action == "UpdateFunctionCode" && candidate.Reference != nil {
			// Native REFERENCE code updates omit the in-progress response digest.
			response.CodeSha256 = nil
		}
		return s.recordCall(tx.Context(), action, input, response, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	if !dryRun {
		s.work.Add(1)
		go func() { defer s.work.Done(); s.deployUpdate(candidate) }()
	}
	if publicationError != nil {
		return response, publicationError
	}
	return response, nil
}
func (s *Service) deployUpdate(candidate FunctionRecord) {
	if candidate.Capacity != nil {
		s.deployManagedUpdate(candidate)
		return
	}
	ctx := ownerContext(s.lifetime, candidate.Key)
	// Preparation and old-environment cleanup never hold the service lock or
	// wait for an active customer invocation. Existing calls finish on their code.
	environment, expiration, prepareErr := s.prepare(ctx, candidate)
	// The prepared replacement owns its own slot. Publishing readiness must not
	// wait for cleanup of an old idle environment or expose an unavailable pool.
	slot := &execution{key: FunctionVersionKey{FunctionKey: candidate.Key}, environment: environment, expires: expiration, revision: candidate.DeploymentRevision, lastUse: s.clock.Now(), leased: true}
	slot.mu.Lock()
	s.mu.Lock()
	s.environments[slot.key] = append(s.environments[slot.key], slot)
	err := s.repository.Update(ctx, func(tx Transaction) error {
		pending, err := tx.PendingFunction(candidate.Key)
		if err != nil {
			return err
		}
		if pending.DeploymentRevision != candidate.DeploymentRevision {
			return errors.New("deployment was superseded")
		}
		current, err := tx.Function(candidate.Key)
		if err != nil {
			return err
		}
		if prepareErr != nil {
			current.UpdateStatus, current.UpdateReason = "Failed", prepareErr.Error()
			if err := tx.PutFunction(current); err != nil {
				return err
			}
			pending.State, pending.StateReason, pending.StateReasonCode = "Failed", prepareErr.Error(), "InternalError"
			pending.UpdateStatus, pending.UpdateReason = "Failed", prepareErr.Error()
			pending.Revision = uuid.NewString()
			if err := tx.SetPublishedDeploymentState(pending); err != nil {
				return err
			}
		} else {
			// Metadata may have changed while the real runtime was preparing.
			candidate = pending
			candidate.State, candidate.StateReason, candidate.StateReasonCode = "Active", "", ""
			candidate.UpdateStatus, candidate.UpdateReason = "Successful", ""
			candidate.Revision = uuid.NewString()
			if err := tx.PutFunction(candidate); err != nil {
				return err
			}
			candidate.Revision = uuid.NewString()
			if err := tx.SetPublishedDeploymentState(candidate); err != nil {
				return err
			}
		}
		return tx.DeletePendingFunction(candidate.Key)
	})
	var idle []*execution
	released := false
	if err == nil && prepareErr == nil {
		idle = s.retireExecutionsLocked(slot.key, slot)
		if s.keepAlive != 0 {
			s.releaseExecutionLocked(slot)
			released = true
		}
	} else {
		slot.retiring = true
	}
	s.mu.Unlock()
	if !released {
		s.releaseExecution(slot)
	}
	slot.mu.Unlock()
	s.jobs.Wake()
	s.closeIdleExecutions(idle)
}
