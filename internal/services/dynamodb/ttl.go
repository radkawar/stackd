package dynamodb

import (
	"context"
	"time"

	api "stackd/internal/awsapi/dynamodb"
)

func (s *Service) describeTimeToLive(ctx context.Context, tx Transaction, in *api.DescribeTimeToLiveInput) (*api.DescribeTimeToLiveOutput, error) {
	table, err := s.controlTable(ctx, tx, value(in.TableName), "DescribeTimeToLive", nil)
	if err != nil {
		return nil, err
	}
	return &api.DescribeTimeToLiveOutput{TimeToLiveDescription: new(api.CloneTimeToLiveDescription(table.TTL))}, nil
}

func (s *Service) updateTimeToLive(ctx context.Context, tx Transaction, in *api.UpdateTimeToLiveInput) (*api.UpdateTimeToLiveOutput, error) {
	table, err := s.controlTable(ctx, tx, value(in.TableName), "UpdateTimeToLive", nil)
	if err != nil {
		return nil, err
	}
	if err = transitionAvailable(table); err != nil {
		return nil, err
	}
	spec := in.TimeToLiveSpecification
	if spec == nil || spec.Enabled == nil || spec.AttributeName == nil || len(value(spec.AttributeName)) < 1 || len(value(spec.AttributeName)) > 255 {
		return nil, failure("ValidationException", "TimeToLiveSpecification requires Enabled and an AttributeName of 1 to 255 bytes")
	}
	enabled := bool(*spec.Enabled)
	status := value(table.TTL.TimeToLiveStatus)
	active := status == "ENABLED" || status == "ENABLING" || status == "DISABLING"
	if active && value(table.TTL.AttributeName) != value(spec.AttributeName) {
		return nil, failure("ValidationException", "TimeToLive is active on a different AttributeName: current AttributeName is "+value(table.TTL.AttributeName))
	}
	if active && enabled {
		return nil, failure("ValidationException", "TimeToLive is already enabled")
	}
	if !active && !enabled {
		return nil, failure("ValidationException", "TimeToLive is already disabled")
	}
	// Expiry is performed by the native TTL scanner; disabling needs no engine.
	if enabled {
		if err = s.requireEngine(); err != nil {
			return nil, err
		}
	}
	now := s.clock.Now()
	if !table.TTLChangedAt.IsZero() && now.Before(table.TTLChangedAt.Add(time.Hour)) {
		return nil, failure("ValidationException", "Time to live has been modified multiple times within a fixed interval")
	}
	var members []TableRecord
	if table.Replica.GroupID != "" {
		members, err = tx.ReplicaTables(table.Replica.GroupID)
		if err != nil {
			return nil, err
		}
		for _, peer := range members {
			if peer.Key == table.Key {
				continue
			}
			if err = s.authorizeTable(regionalContext(ctx, peer.Key.Region), tx, peer.Key, "UpdateTimeToLive", "", nil); err != nil {
				return nil, err
			}
		}
	}
	table.TTLChangedAt = now
	table.TTL = api.TimeToLiveDescription{TimeToLiveStatus: new(api.TimeToLiveStatusDISABLED)}
	table.TTLNextScan = time.Time{}
	if enabled {
		table.TTL.TimeToLiveStatus = new(api.TimeToLiveStatusENABLED)
		table.TTL.AttributeName = new(*spec.AttributeName)
		table.TTLNextScan = now
	}
	if err = tx.PutTable(table); err != nil {
		return nil, err
	}
	// Validate the requested transition once against the calling replica, then
	// synchronize its state and scanner deadlines in this same transaction.
	for _, peer := range members {
		if peer.Key == table.Key {
			continue
		}
		peer.TTL = api.CloneTimeToLiveDescription(table.TTL)
		peer.TTLChangedAt, peer.TTLNextScan = table.TTLChangedAt, table.TTLNextScan
		if err = tx.PutTable(peer); err != nil {
			return nil, err
		}
	}
	return &api.UpdateTimeToLiveOutput{TimeToLiveSpecification: &api.TimeToLiveSpecification{AttributeName: new(*spec.AttributeName), Enabled: new(*spec.Enabled)}}, nil
}
