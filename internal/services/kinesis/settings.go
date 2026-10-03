package kinesis

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	api "stackd/internal/awsapi/kinesis"
)

func streamMode(stream StreamRecord) api.StreamMode {
	if stream.Data.StreamModeDetails == nil || stream.Data.StreamModeDetails.StreamMode == nil {
		return api.StreamModePROVISIONED
	}
	return *stream.Data.StreamModeDetails.StreamMode
}

func validMode(mode api.StreamMode) error {
	if mode != api.StreamModePROVISIONED && mode != api.StreamModeON_DEMAND {
		return failure("ValidationException", "StreamMode must be ON_DEMAND or PROVISIONED")
	}
	return nil
}

func validRecordSize(size int32) error {
	if size < 1024 || size > 10240 {
		return failure("ValidationException", "MaxRecordSizeInKiB must be between 1024 and 10240")
	}
	return nil
}

func beginStreamUpdate(tx Transaction, stream StreamRecord, update StreamUpdate) error {
	stream.Pending = &update
	stream.Data.StreamStatus = new(api.StreamStatusUPDATING)
	return tx.PutStream(stream)
}

func (s *Service) retention(ctx context.Context, tx Transaction, name, arn string, hours int32, increase bool) (*api.Unit, error) {
	action := "DecreaseStreamRetentionPeriod"
	if increase {
		action = "IncreaseStreamRetentionPeriod"
	}
	stream, err := s.stream(ctx, tx, name, arn, action)
	if err != nil {
		return nil, err
	}
	if err = requireActive(stream); err != nil {
		return nil, err
	}
	if hours < 24 {
		return nil, failure("InvalidArgumentException", fmt.Sprintf("Minimum allowed retention period is 24 hours. Requested retention period (%d hours) is too short.", hours))
	}
	if hours > 8760 {
		return nil, failure("InvalidArgumentException", fmt.Sprintf("Maximum allowed retention period is 8760 hours. Requested retention period (%d hours) is too long.", hours))
	}
	current := int32(*stream.Data.RetentionPeriodHours)
	if increase && hours < current {
		return nil, failure("InvalidArgumentException", fmt.Sprintf("Requested retention period (%d hours) for stream %s can not be shorter than existing retention period (%d hours). Use DecreaseRetentionPeriod API.", hours, stream.Key.Name, current))
	}
	if !increase && hours > current {
		return nil, failure("InvalidArgumentException", fmt.Sprintf("Requested retention period (%d hours) for stream %s can not be longer than existing retention period (%d hours). Use IncreaseRetentionPeriod API.", hours, stream.Key.Name, current))
	}
	if hours != current {
		if err = beginStreamUpdate(tx, stream, StreamUpdate{AcceptedAt: s.clock.Now(), RetentionHours: hours}); err != nil {
			return nil, err
		}
	}
	return &api.Unit{}, nil
}

func (s *Service) increaseStreamRetentionPeriod(ctx context.Context, tx Transaction, in *api.IncreaseStreamRetentionPeriodInput) (*api.IncreaseStreamRetentionPeriodOutput, error) {
	return s.retention(ctx, tx, value(in.StreamName), value(in.StreamARN), int32(*in.RetentionPeriodHours), true)
}

func (s *Service) decreaseStreamRetentionPeriod(ctx context.Context, tx Transaction, in *api.DecreaseStreamRetentionPeriodInput) (*api.DecreaseStreamRetentionPeriodOutput, error) {
	return s.retention(ctx, tx, value(in.StreamName), value(in.StreamARN), int32(*in.RetentionPeriodHours), false)
}

func (s *Service) updateStreamMode(ctx context.Context, tx Transaction, in *api.UpdateStreamModeInput) (*api.UpdateStreamModeOutput, error) {
	mode := *in.StreamModeDetails.StreamMode
	if err := validMode(mode); err != nil {
		return nil, err
	}
	stream, err := s.stream(ctx, tx, "", value(in.StreamARN), "UpdateStreamMode")
	if err != nil {
		return nil, err
	}
	if err = requireActive(stream); err != nil {
		return nil, err
	}
	if in.WarmThroughputMiBps != nil {
		if err = s.validateWarmThroughput(tx, stream.Key.Scope, mode, int32(*in.WarmThroughputMiBps)); err != nil {
			return nil, err
		}
	}
	changed := streamMode(stream) != mode
	now := s.clock.Now()
	if changed {
		history, readErr := tx.ModeSwitches(stream.Key)
		if readErr != nil && !errors.Is(readErr, ErrNotFound) {
			return nil, readErr
		}
		recent := make([]time.Time, 0, len(history)+1)
		for _, at := range history {
			if at.After(now.Add(-24 * time.Hour)) {
				recent = append(recent, at)
			}
		}
		if len(recent) >= 2 {
			return nil, failure("LimitExceededException", fmt.Sprintf("Rate exceeded for stream %s under account %s.", stream.Key.Name, stream.Key.AccountID))
		}
		count := int32(0)
		if mode == api.StreamModePROVISIONED && stream.Data.OpenShardCount != nil {
			count = int32(*stream.Data.OpenShardCount)
		}
		if err = checkStreamCapacity(tx, stream.Key.Scope, mode, count, false); err != nil {
			return nil, err
		}
		if err = tx.PutModeSwitches(stream.Key, append(recent, now)); err != nil {
			return nil, err
		}
	}
	update := StreamUpdate{AcceptedAt: now, Mode: mode}
	if in.WarmThroughputMiBps != nil {
		update.WarmMiBps = new(int32(*in.WarmThroughputMiBps))
		if err = s.scheduleReshard(tx, stream, max(4, int32(*in.WarmThroughputMiBps)), update); err != nil {
			return nil, err
		}
	} else if changed {
		if err = beginStreamUpdate(tx, stream, update); err != nil {
			return nil, err
		}
	}
	return &api.UpdateStreamModeOutput{}, nil
}

func (s *Service) updateMaxRecordSize(ctx context.Context, tx Transaction, in *api.UpdateMaxRecordSizeInput) (*api.UpdateMaxRecordSizeOutput, error) {
	size := int32(*in.MaxRecordSizeInKiB)
	if err := validRecordSize(size); err != nil {
		return nil, err
	}
	stream, err := s.stream(ctx, tx, "", value(in.StreamARN), "UpdateMaxRecordSize")
	if err != nil {
		return nil, err
	}
	if err = requireActive(stream); err != nil {
		return nil, err
	}
	if stream.Data.MaxRecordSizeInKiB == nil || int32(*stream.Data.MaxRecordSizeInKiB) != size {
		if err = beginStreamUpdate(tx, stream, StreamUpdate{AcceptedAt: s.clock.Now(), MaxRecordSizeKiB: size}); err != nil {
			return nil, err
		}
	}
	return &api.UpdateMaxRecordSizeOutput{}, nil
}

// Keep metric-set responses deterministic, including native OutgoingRecords
// before IncomingRecords ordering.
var enhancedMetrics = api.MetricsNameList{
	api.MetricsNameINCOMING_BYTES, api.MetricsNameOUTGOING_RECORDS, api.MetricsNameITERATOR_AGE_MILLISECONDS,
	api.MetricsNameINCOMING_RECORDS, api.MetricsNameREAD_PROVISIONED_THROUGHPUT_EXCEEDED,
	api.MetricsNameWRITE_PROVISIONED_THROUGHPUT_EXCEEDED, api.MetricsNameOUTGOING_BYTES,
}

func (s *Service) monitoring(ctx context.Context, tx Transaction, name, arn string, requested api.MetricsNameList, enable bool) (*api.EnhancedMonitoringOutput, error) {
	action := "DisableEnhancedMonitoring"
	if enable {
		action = "EnableEnhancedMonitoring"
	}
	stream, err := s.stream(ctx, tx, name, arn, action)
	if err != nil {
		return nil, err
	}
	if err = requireActive(stream); err != nil {
		return nil, err
	}
	if len(requested) == 0 {
		return nil, failure("ValidationException", "ShardLevelMetrics must not be empty")
	}
	for _, metric := range requested {
		if metric != api.MetricsNameALL && !slices.Contains(enhancedMetrics, metric) {
			return nil, failure("ValidationException", "Invalid shard level metric")
		}
	}
	current := api.MetricsNameList{}
	for _, monitoring := range stream.Data.EnhancedMonitoring {
		current = append(current, monitoring.ShardLevelMetrics...)
	}
	desired := api.MetricsNameList{}
	all := slices.Contains(requested, api.MetricsNameALL)
	for _, metric := range enhancedMetrics {
		selected := all || slices.Contains(requested, metric)
		if enable && (selected || slices.Contains(current, metric)) || !enable && !selected && slices.Contains(current, metric) {
			desired = append(desired, metric)
		}
	}
	if !slices.Equal(current, desired) {
		if err = beginStreamUpdate(tx, stream, StreamUpdate{AcceptedAt: s.clock.Now(), Monitoring: desired}); err != nil {
			return nil, err
		}
	}
	return &api.EnhancedMonitoringOutput{StreamName: stream.Data.StreamName, StreamARN: stream.Data.StreamARN, CurrentShardLevelMetrics: current, DesiredShardLevelMetrics: desired}, nil
}

func (s *Service) enableEnhancedMonitoring(ctx context.Context, tx Transaction, in *api.EnableEnhancedMonitoringInput) (*api.EnableEnhancedMonitoringOutput, error) {
	return s.monitoring(ctx, tx, value(in.StreamName), value(in.StreamARN), in.ShardLevelMetrics, true)
}

func (s *Service) disableEnhancedMonitoring(ctx context.Context, tx Transaction, in *api.DisableEnhancedMonitoringInput) (*api.DisableEnhancedMonitoringOutput, error) {
	return s.monitoring(ctx, tx, value(in.StreamName), value(in.StreamARN), in.ShardLevelMetrics, false)
}
