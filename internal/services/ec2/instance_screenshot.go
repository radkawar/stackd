package ec2

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
)

func (s *Service) getConsoleScreenshot(ctx context.Context, in *api.GetConsoleScreenshotRequest) (*api.GetConsoleScreenshotResult, error) {
	// Serialize with native lifecycle effects, not with the state transaction.
	// No screen bytes or WakeUp intent are persisted; this is an immediate read.
	s.instanceWorkMu.Lock()
	defer s.instanceWorkMu.Unlock()
	var record InstanceRecord
	err := s.repository.View(ctx, func(tx Reader) error {
		var err error
		record, err = s.admitConsoleScreenshot(tx.Context(), tx, in)
		return err
	})
	if err != nil {
		return nil, err
	}
	handle := s.instanceHandles[record.Key]
	if handle == nil {
		if s.instanceRuntime == nil || s.instanceVolumes == nil {
			return nil, unsupported("The native instance runtime is not configured.")
		}
		child := instanceServiceContext(ctx, record.Key)
		spec, err := s.instanceSpecification(child, record)
		if err != nil {
			return nil, err
		}
		handle, err = s.reopenInstanceController(child, record, &spec)
		if err != nil {
			return nil, screenshotRuntimeError(err)
		}
		if s.instanceHandles == nil {
			s.instanceHandles = make(map[ResourceKey]native.Instance)
		}
		s.instanceHandles[record.Key] = handle
		if err := s.limitInstanceCreditReconnect(child, record.Key, handle); err != nil {
			return nil, err
		}
	}
	image, err := handle.Screenshot(ctx, boolValue(in.WakeUp))
	if err != nil {
		return nil, screenshotRuntimeError(err)
	}
	out := &api.GetConsoleScreenshotResult{InstanceId: record.Data.InstanceId, ImageData: new(api.String(base64.StdEncoding.EncodeToString(image)))}
	// Unlike an asynchronous command there is no admitted resource mutation to
	// record before capture. Record only the actual completed read; recordCall's
	// shared read projection omits the sensitive screenshot response entirely.
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		return RecordExternalSuccess(tx.Context(), out)
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) admitConsoleScreenshot(ctx context.Context, tx Reader, in *api.GetConsoleScreenshotRequest) (InstanceRecord, error) {
	id := str(in.InstanceId)
	if boolValue(in.DryRun) {
		// Native DryRun checks authority before instance-ID syntax, existence or
		// running state. Existing targets still supply their ordinary IAM tags
		// and instance conditions through the shared target admission owner.
		_, err := tx.Instance(key(ctx, id))
		if errors.Is(err, ErrNotFound) {
			if err := s.authorizeWith(ctx, "GetConsoleScreenshot", "instance", id, nil, map[string][]string{"ec2:InstanceID": {id}}); err != nil {
				return InstanceRecord{}, err
			}
			return InstanceRecord{}, dryRun(in.DryRun)
		}
		if err != nil {
			return InstanceRecord{}, err
		}
	}
	records, err := s.instanceCommandTargets(ctx, tx, "GetConsoleScreenshot", api.InstanceIdStringList{api.InstanceId(id)}, in.DryRun)
	if err != nil {
		return InstanceRecord{}, err
	}
	record := records[0]
	switch instanceState(record) {
	case "stopped", "terminated":
		return InstanceRecord{}, failure("InvalidInstanceID.NotFound", "")
	case "running", "stopping", "shutting-down":
		// Native capture remains available while the guest's VMM still exists.
	default:
		return InstanceRecord{}, unsupported("instance is not running")
	}
	if str(record.Data.Architecture) != "x86_64" || strings.Contains(str(record.Data.InstanceType), ".metal") {
		return InstanceRecord{}, unsupported("Console screenshots are not supported for this instance hardware.")
	}
	scope := scopeFor(ctx)
	if scope.Partition == "aws-us-gov" || scope.Region == "ap-southeast-7" || scope.Region == "mx-central-1" {
		return InstanceRecord{}, unsupported("Console screenshots are not supported in this Region.")
	}
	return record, nil
}

func screenshotRuntimeError(err error) error {
	if errors.Is(err, native.ErrNotFound) {
		return failure("InvalidInstanceID.NotFound", "")
	}
	var capability *native.CapabilityError
	if errors.As(err, &capability) {
		return unsupported(capability.Error())
	}
	return err
}
