package cloudcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/google/uuid"
	api "stackd/internal/awsapi/cloudcontrol"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
)

func document(raw string) (cloudformation.Properties, error) {
	var properties cloudformation.Properties
	if err := json.Unmarshal([]byte(raw), &properties); err != nil || properties == nil {
		return nil, failure("ValidationException", "Resource properties must be a JSON object.")
	}
	return properties, nil
}
func encode(v any) string { raw, _ := json.Marshal(v); return string(raw) }
func requestHash(v any) string {
	sum := sha256.Sum256([]byte(encode(v)))
	return hex.EncodeToString(sum[:])
}
func requestARN(scope Scope, token string) string {
	return fmt.Sprintf("arn:%s:cloudformation:%s:%s:resource-request/%s", scope.Partition, scope.Region, scope.Account, token)
}
func resourceRequest(op RequestRecord) cloudformation.ResourceRequest {
	properties, _ := document(op.Desired)
	previous, _ := document(op.Before)
	return cloudformation.ResourceRequest{StackID: requestARN(op.Scope, op.Token), StackName: "cloudcontrol", LogicalID: "Resource", Type: op.TypeName, PhysicalID: op.Identifier, Token: op.Token, Scope: op.Scope, Properties: properties, Previous: previous, CloudControl: true}
}
func (s *Service) replay(ctx context.Context, op RequestRecord) (RequestRecord, bool, error) {
	var out RequestRecord
	var found bool
	err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		out, found, err = s.findReplay(tx, op)
		if err != nil || !found {
			return err
		}
		return s.recordMutation(tx.Context(), progress(out))
	})
	return out, found, err
}
func (s *Service) findReplay(r Reader, op RequestRecord) (RequestRecord, bool, error) {
	if op.ClientToken == "" {
		return RequestRecord{}, false, nil
	}
	rows, err := r.Requests(op.Scope)
	if err != nil {
		return RequestRecord{}, false, err
	}
	for _, v := range rows {
		if v.ClientToken != op.ClientToken || !s.clock.Now().Before(v.Created.Add(36*time.Hour)) {
			continue
		}
		if v.RequestHash != op.RequestHash {
			return RequestRecord{}, false, failure("ClientTokenConflictException", "ClientToken is already associated with a different operation.")
		}
		return v, true, nil
	}
	return RequestRecord{}, false, nil
}
func (s *Service) admit(ctx context.Context, op RequestRecord) (*api.ProgressEvent, error) {
	op.Token = uuid.NewString()
	op.Caller = awsctx.FromContext(ctx)
	op.Status = "IN_PROGRESS"
	op.Phase = "APPLY"
	op.Revision = 1
	op.Created = s.clock.Now()
	op.EventTime = op.Created
	op.Due = op.Created
	var result RequestRecord
	err := s.repository.Update(ctx, func(tx Transaction) error {
		previous, found, err := s.findReplay(tx, op)
		if err != nil {
			return err
		}
		if found {
			result = previous
			return s.recordMutation(tx.Context(), progress(previous))
		}
		rows, err := tx.Requests(op.Scope)
		if err != nil {
			return err
		}
		for _, v := range rows {
			if active(v.Status) && v.TypeName == op.TypeName && op.Identifier != "" && v.Identifier == op.Identifier {
				return failure("ConcurrentOperationException", "A resource operation is already in progress for this identifier.")
			}
		}
		result = op
		if err := tx.PutRequest(op); err != nil {
			return err
		}
		return s.recordMutation(tx.Context(), progress(op))
	})
	if err != nil {
		return nil, err
	}
	return progress(result), nil
}
func (s *Service) create(ctx context.Context, in *api.CreateResourceInput) (*api.CreateResourceOutput, error) {
	op := RequestRecord{Scope: scopeFor(ctx), TypeName: text(in.TypeName), ClientToken: text(in.ClientToken), Desired: text(in.DesiredState), RoleARN: text(in.RoleArn), Operation: "CREATE"}
	op.RequestHash = requestHash(in)
	if old, found, err := s.replay(ctx, op); err != nil {
		return nil, err
	} else if found {
		return &api.CreateResourceOutput{ProgressEvent: progress(old)}, nil
	}
	h, _, err := s.handler(op.TypeName, text(in.TypeVersionId))
	if err != nil {
		return nil, err
	}
	p, err := document(op.Desired)
	if err != nil {
		return nil, err
	}
	if err = cloudformation.ValidateResourceProperties(op.TypeName, p); err != nil {
		return nil, err
	}
	if err = h.Validate(p); err != nil {
		return nil, err
	}
	op.Identifier, _ = cloudformation.ResourceIdentifier(op.TypeName, p)
	if _, err = s.roleContext(ctx, "", op.RoleARN); err != nil {
		return nil, err
	}
	event, err := s.admit(ctx, op)
	return &api.CreateResourceOutput{ProgressEvent: event}, err
}
func (s *Service) update(ctx context.Context, in *api.UpdateResourceInput) (*api.UpdateResourceOutput, error) {
	op := RequestRecord{Scope: scopeFor(ctx), TypeName: text(in.TypeName), Identifier: text(in.Identifier), ClientToken: text(in.ClientToken), Patch: text(in.PatchDocument), RoleARN: text(in.RoleArn), Operation: "UPDATE"}
	op.RequestHash = requestHash(in)
	if old, found, err := s.replay(ctx, op); err != nil {
		return nil, err
	} else if found {
		return &api.UpdateResourceOutput{ProgressEvent: progress(old)}, nil
	}
	h, reader, err := s.handler(op.TypeName, text(in.TypeVersionId))
	if err != nil {
		return nil, err
	}
	commandCtx, err := s.roleContext(ctx, "", op.RoleARN)
	if err != nil {
		return nil, err
	}
	current, err := reader.Read(commandCtx, resourceRequest(op))
	if err != nil {
		return nil, readError(err)
	}
	patch, err := jsonpatch.DecodePatch([]byte(op.Patch))
	if err != nil {
		return nil, failure("ValidationException", err.Error())
	}
	for _, operation := range patch {
		if operation.Kind() == "test" {
			continue
		}
		path, e := operation.Path()
		if e != nil {
			return nil, failure("ValidationException", e.Error())
		}
		if e = cloudformation.ValidateResourcePatchPath(op.TypeName, path); e != nil {
			return nil, e
		}
		if operation.Kind() == "move" {
			from, e := operation.From()
			if e != nil {
				return nil, failure("ValidationException", e.Error())
			}
			if e = cloudformation.ValidateResourcePatchPath(op.TypeName, from); e != nil {
				return nil, e
			}
		}
	}
	options := jsonpatch.NewApplyOptions()
	options.SupportNegativeIndices = false
	next, err := patch.ApplyWithOptions([]byte(encode(current)), options)
	if err != nil {
		return nil, failure("ValidationException", err.Error())
	}
	desired, err := document(string(next))
	if err != nil {
		return nil, err
	}
	before := cloudformation.WritableResourceProperties(op.TypeName, current)
	desired = cloudformation.WritableResourceProperties(op.TypeName, desired)
	if err = cloudformation.ValidateResourceUpdate(op.TypeName, before, desired); err != nil {
		return nil, err
	}
	if err = h.Validate(desired); err != nil {
		return nil, err
	}
	replacement, err := cloudformation.RequiresReplacement(h, op.Scope, before, desired)
	if err != nil {
		return nil, err
	}
	if replacement {
		return nil, failure("NotUpdatableException", "The update requires resource replacement.")
	}
	op.Before = encode(before)
	op.Desired = encode(desired)
	event, err := s.admit(ctx, op)
	return &api.UpdateResourceOutput{ProgressEvent: event}, err
}
func (s *Service) delete(ctx context.Context, in *api.DeleteResourceInput) (*api.DeleteResourceOutput, error) {
	op := RequestRecord{Scope: scopeFor(ctx), TypeName: text(in.TypeName), Identifier: text(in.Identifier), ClientToken: text(in.ClientToken), RoleARN: text(in.RoleArn), Operation: "DELETE"}
	op.RequestHash = requestHash(in)
	if old, found, err := s.replay(ctx, op); err != nil {
		return nil, err
	} else if found {
		return &api.DeleteResourceOutput{ProgressEvent: progress(old)}, nil
	}
	if _, _, err := s.handler(op.TypeName, text(in.TypeVersionId)); err != nil {
		return nil, err
	}
	if _, err := s.roleContext(ctx, "", op.RoleARN); err != nil {
		return nil, err
	}
	event, err := s.admit(ctx, op)
	return &api.DeleteResourceOutput{ProgressEvent: event}, err
}
func progress(op RequestRecord) *api.ProgressEvent {
	out := &api.ProgressEvent{TypeName: new(api.TypeName(op.TypeName)), RequestToken: new(api.RequestToken(op.Token)), Operation: new(api.Operation(op.Operation)), OperationStatus: new(api.OperationStatus(op.Status)), EventTime: new(api.Timestamp(op.EventTime))}
	if op.Identifier != "" {
		out.Identifier = new(api.Identifier(op.Identifier))
	}
	if op.Model != "" {
		out.ResourceModel = new(api.Properties(op.Model))
	}
	if op.ErrorCode != "" {
		out.ErrorCode = new(api.HandlerErrorCode(op.ErrorCode))
	}
	if op.Message != "" {
		out.StatusMessage = new(api.StatusMessage(op.Message))
	}
	if active(op.Status) {
		out.RetryAfter = new(api.Timestamp(op.Due.Add(time.Second)))
	}
	return out
}
