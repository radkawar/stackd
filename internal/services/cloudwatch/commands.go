package cloudwatch

import (
	"context"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

// PutMetricAlarm admits a service-owned alarm through the same authorization,
// configuration, event and audit boundary used by the generated frontend.
func (s *Service) PutMetricAlarm(ctx context.Context, in *api.PutMetricAlarmInput) (*api.PutMetricAlarmOutput, *awswire.Error) {
	return runCommand[api.PutMetricAlarmOutput](s, ctx, "PutMetricAlarm", in)
}

// DeleteAlarms removes service-owned alarms under the current service identity.
func (s *Service) DeleteAlarms(ctx context.Context, in *api.DeleteAlarmsInput) (*api.DeleteAlarmsOutput, *awswire.Error) {
	return runCommand[api.DeleteAlarmsOutput](s, ctx, "DeleteAlarms", in)
}

// GetMetricData evaluates the existing query engine under the caller's authority.
func (s *Service) GetMetricData(ctx context.Context, in *api.GetMetricDataInput) (*api.GetMetricDataOutput, *awswire.Error) {
	return runCommand[api.GetMetricDataOutput](s, ctx, "GetMetricData", in)
}

// DescribeAlarms reads the authoritative alarm state under the caller's authority.
func (s *Service) DescribeAlarms(ctx context.Context, in *api.DescribeAlarmsInput) (*api.DescribeAlarmsOutput, *awswire.Error) {
	return runCommand[api.DescribeAlarmsOutput](s, ctx, "DescribeAlarms", in)
}

func runCommand[O any](s *Service, ctx context.Context, action string, in any) (*O, *awswire.Error) {
	model, _ := awscatalog.LookupService("cloudwatch")
	operation, _ := model.Operation(action)
	out, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: in})
	if rejected != nil {
		return nil, rejected
	}
	return out.(*O), nil
}
