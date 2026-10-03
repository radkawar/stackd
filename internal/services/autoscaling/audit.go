package autoscaling

import (
	"context"
	"encoding/json"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

type auditContextKey struct{}
type auditContext struct {
	GroupID                 string
	ProtectionStateRejected bool
}

var auditEmptyWarmPoolReuse = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"InstanceReusePolicy": {Mode: awsapi.OmitField},
}}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("autoscaling")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	readOnly := strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "Get")
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: readOnly}
	warmPool := action == "PutWarmPool" || action == "DescribeWarmPool" || action == "DeleteWarmPool"
	refresh := action == "StartInstanceRefresh" || action == "CancelInstanceRefresh" || action == "RollbackInstanceRefresh"
	if !readOnly && !warmPool {
		projection.Response = &awsapi.DocumentProjection{}
	}
	if input, ok := in.(*api.PutWarmPoolInput); ok && input != nil && input.InstanceReusePolicy != nil && input.InstanceReusePolicy.ReuseOnScaleIn == nil {
		projection.Request = auditEmptyWarmPoolReuse
	}
	if input, ok := in.(*api.CancelInstanceRefreshInput); ok && input != nil && input.WaitForTransitioningInstances == nil {
		copy := *input
		copy.WaitForTransitioningInstances = new(api.BooleanType(true))
		in = &copy
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	if warmPool && rejected != nil && rejected.Code == "AccessDenied" {
		call.RequestParameters = nil
	}
	call.EventID = apievents.EventID(ctx)
	// Native Auto Scaling omits apiVersion and uses ValidationException in the
	// audit document even though the Query error is ValidationError.
	if call.ErrorCode == "ValidationError" {
		call.ErrorCode = "ValidationException"
	}
	if warmPool && call.ErrorCode == "ResourceInUse" {
		call.ErrorCode = "ResourceInUseFault"
	}
	if refresh && (call.ErrorCode == "InstanceRefreshInProgress" || call.ErrorCode == "ActiveInstanceRefreshNotFound") {
		call.ErrorCode += "Fault"
	}
	if details, ok := ctx.Value(auditContextKey{}).(*auditContext); ok && details.ProtectionStateRejected && rejected != nil {
		// Native protection-state rejection has a different audit exception
		// from its diagnostic Query ValidationError response.
		call.ErrorCode = "InvalidParameterValueException"
		call.ErrorMessage = "An unknown error occurred"
	}
	if action == "CreateAutoScalingGroup" && rejected == nil {
		if details, ok := ctx.Value(auditContextKey{}).(*auditContext); ok {
			call.AdditionalEventData, err = json.Marshal(struct {
				GroupID string `json:"GroupId"`
			}{details.GroupID})
			if err != nil {
				return err
			}
		}
	}
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
