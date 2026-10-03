package kinesis

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/kinesis"
)

// accountSettings settles deferred disablement against the service clock. The
// stored commitment retains its interval even when no request runs at its end.
func accountSettings(r Reader, scope Scope, now time.Time) (AccountRecord, error) {
	account, err := r.Account(scope)
	if errors.Is(err, ErrNotFound) {
		return AccountRecord{Scope: scope, Commitment: api.MinimumThroughputBillingCommitmentOutput{Status: new(api.MinimumThroughputBillingCommitmentOutputStatusDISABLED)}}, nil
	}
	if err != nil {
		return AccountRecord{}, err
	}
	if value(account.Commitment.Status) == "ENABLED_UNTIL_EARLIEST_ALLOWED_END" && account.Commitment.EarliestAllowedEndAt != nil && !now.Before(*account.Commitment.EarliestAllowedEndAt) {
		account.Commitment.Status = new(api.MinimumThroughputBillingCommitmentOutputStatusDISABLED)
		account.Commitment.EndedAt = account.Commitment.EarliestAllowedEndAt
	}
	return account, nil
}

func (s *Service) describeAccountSettings(ctx context.Context, tx Transaction, in *api.DescribeAccountSettingsInput) (*api.DescribeAccountSettingsOutput, error) {
	if err := s.authorize(ctx, "DescribeAccountSettings", "*", nil); err != nil {
		return nil, err
	}
	account, err := accountSettings(tx, scopeFor(ctx), s.clock.Now())
	if err != nil {
		return nil, err
	}
	return &api.DescribeAccountSettingsOutput{MinimumThroughputBillingCommitment: &account.Commitment}, nil
}

// AWS MinimumThroughputBillingCommitmentInput defines a 24-hour minimum,
// deferred disablement before that end, and cancellation by enabling again.
func (s *Service) updateAccountSettings(ctx context.Context, tx Transaction, in *api.UpdateAccountSettingsInput) (*api.UpdateAccountSettingsOutput, error) {
	if in.MinimumThroughputBillingCommitment == nil || in.MinimumThroughputBillingCommitment.Status == nil {
		return nil, failure("ValidationException", "MinimumThroughputBillingCommitment.Status is required")
	}
	desired := value(in.MinimumThroughputBillingCommitment.Status)
	if desired != "ENABLED" && desired != "DISABLED" {
		return nil, failure("ValidationException", "MinimumThroughputBillingCommitment.Status must be ENABLED or DISABLED")
	}
	if err := s.authorize(ctx, "UpdateAccountSettings", "*", nil); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	account, err := accountSettings(tx, scopeFor(ctx), now)
	if err != nil {
		return nil, err
	}
	commitment := &account.Commitment
	if desired == "ENABLED" {
		if value(commitment.Status) == "DISABLED" {
			commitment.StartedAt = &now
			commitment.EarliestAllowedEndAt = new(now.Add(24 * time.Hour))
		}
		commitment.EndedAt = nil
		commitment.Status = new(api.MinimumThroughputBillingCommitmentOutputStatusENABLED)
	} else if value(commitment.Status) != "DISABLED" {
		if commitment.EarliestAllowedEndAt != nil && now.Before(*commitment.EarliestAllowedEndAt) {
			commitment.Status = new(api.MinimumThroughputBillingCommitmentOutputStatusENABLED_UNTIL_EARLIEST_ALLOWED_END)
		} else {
			commitment.Status = new(api.MinimumThroughputBillingCommitmentOutputStatusDISABLED)
			commitment.EndedAt = &now
		}
	}
	if err = tx.PutAccount(account); err != nil {
		return nil, err
	}
	return &api.UpdateAccountSettingsOutput{MinimumThroughputBillingCommitment: commitment}, nil
}

func (s *Service) validateWarmThroughput(r Reader, scope Scope, mode api.StreamMode, throughput int32) error {
	account, err := accountSettings(r, scope, s.clock.Now())
	if err != nil {
		return err
	}
	if value(account.Commitment.Status) == "DISABLED" {
		return failure("ValidationException", "Account "+scope.AccountID+" is not enabled for minimum throughput billing commitment")
	}
	if mode != api.StreamModeON_DEMAND {
		return failure("ValidationException", "Warm throughput is only supported for ON_DEMAND streams")
	}
	if throughput < 0 {
		return failure("ValidationException", "WarmThroughputMiBps must be greater than or equal to 0")
	}
	if throughput > 10240 {
		return failure("LimitExceededException", "Warm throughput cannot exceed 10240 MiBps")
	}
	return nil
}

func (s *Service) updateStreamWarmThroughput(ctx context.Context, tx Transaction, in *api.UpdateStreamWarmThroughputInput) (*api.UpdateStreamWarmThroughputOutput, error) {
	stream, err := s.stream(ctx, tx, value(in.StreamName), value(in.StreamARN), "UpdateStreamWarmThroughput")
	if err != nil {
		return nil, err
	}
	throughput := int32(*in.WarmThroughputMiBps)
	if err = s.validateWarmThroughput(tx, stream.Key.Scope, streamMode(stream), throughput); err != nil {
		return nil, err
	}
	if err = requireActive(stream); err != nil {
		return nil, err
	}
	if s.runtime == nil {
		return nil, failure("InternalFailureException", "Kinesis log runtime is not configured", 500)
	}
	// A native partition provides one MiB/s of write capacity. Warm throughput
	// changes use the same pending topology path as explicit shard operations.
	if err = s.scheduleReshard(tx, stream, max(4, throughput), StreamUpdate{AcceptedAt: s.clock.Now(), WarmMiBps: &throughput}); err != nil {
		return nil, err
	}
	current := api.NaturalIntegerObject(0)
	if stream.Data.WarmThroughput != nil && stream.Data.WarmThroughput.CurrentMiBps != nil {
		current = *stream.Data.WarmThroughput.CurrentMiBps
	} else if stream.Data.OpenShardCount != nil {
		current = api.NaturalIntegerObject(*stream.Data.OpenShardCount)
	}
	return &api.UpdateStreamWarmThroughputOutput{StreamName: stream.Data.StreamName, StreamARN: stream.Data.StreamARN, WarmThroughput: &api.WarmThroughputObject{CurrentMiBps: &current, TargetMiBps: new(api.NaturalIntegerObject(throughput))}}, nil
}
