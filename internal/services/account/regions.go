package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	api "stackd/internal/awsapi/account"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type RegionStatus string

const (
	EnabledByDefault RegionStatus = "ENABLED_BY_DEFAULT"
	Enabled          RegionStatus = "ENABLED"
	Enabling         RegionStatus = "ENABLING"
	Disabled         RegionStatus = "DISABLED"
	Disabling        RegionStatus = "DISABLING"
)

// These service-time delays model the captured asynchronous phases, not an AWS
// completion-time SLA. See docs/account-regions.md for the sampled observations.
const enableDelay = 2 * time.Minute
const disableDelay = time.Minute

func regionStatus(reader Reader, key RegionKey, instant time.Time) (RegionStatus, error) {
	if key.Partition != "aws" {
		// TODO: Comeback capture Account regional availability and opt-in rules for China, GovCloud and isolated partitions.
		return "", validation("RegionName", key.Region+" is not a valid region for opt-in or opt-out.", "fieldValidationFailed")
	}
	for _, region := range awscatalog.CommercialRegions() {
		if region.Name != key.Region {
			continue
		}
		if !region.OptInRequired {
			return EnabledByDefault, nil
		}
		record, found, err := reader.Region(key)
		if err != nil {
			return "", err
		}
		if !found {
			return Disabled, nil
		}
		if !instant.Before(record.Due) {
			switch record.Status {
			case Enabling:
				return Enabled, nil
			case Disabling:
				return Disabled, nil
			}
		}
		return record.Status, nil
	}
	return "", validation("RegionName", key.Region+" is not a valid region for opt-in or opt-out.", "fieldValidationFailed")
}

func (s *Service) getRegionOptStatus(ctx context.Context, in api.GetRegionOptStatusInput) (any, error) {
	var output *api.GetRegionOptStatusOutput
	err := s.repository.View(ctx, func(reader Reader) error {
		ctx, instant := reader.Context(), s.clock.Now().UTC()
		region := value(in.RegionName)
		target, err := s.authorize(ctx, "GetRegionOptStatus", value(in.AccountId), map[string][]string{"account:TargetRegion": {region}}, instant)
		if err != nil {
			return err
		}
		status, err := regionStatus(reader, RegionKey{awsctx.FromContext(ctx).Partition, target, region}, instant)
		if err != nil {
			return err
		}
		output = &api.GetRegionOptStatusOutput{RegionName: in.RegionName, RegionOptStatus: ptr(api.RegionOptStatus(status))}
		return nil
	})
	return output, err
}

func (s *Service) enableRegion(ctx context.Context, in api.EnableRegionInput) (any, error) {
	return s.changeRegion(ctx, "EnableRegion", value(in.AccountId), value(in.RegionName), Enabling, &in)
}
func (s *Service) disableRegion(ctx context.Context, in api.DisableRegionInput) (any, error) {
	return s.changeRegion(ctx, "DisableRegion", value(in.AccountId), value(in.RegionName), Disabling, &in)
}

func (s *Service) changeRegion(ctx context.Context, action, target, region string, next RegionStatus, input any) (any, error) {
	// TODO: Comeback capture and enforce concurrent region-transition limits, request throttling and account-dependent enable/disable timing before Account completion.
	err := s.repository.Update(ctx, func(writer Writer) error {
		ctx, instant := writer.Context(), s.clock.Now().UTC()
		target, err := s.authorize(ctx, action, target, map[string][]string{"account:TargetRegion": {region}}, instant)
		if err != nil {
			return err
		}
		key := RegionKey{awsctx.FromContext(ctx).Partition, target, region}
		current, err := regionStatus(writer, key, instant)
		if err != nil {
			return err
		}
		if current == Enabling || current == Disabling {
			return failure("ConflictException", fmt.Sprintf("Account %s and region %s is currently being enabled or disabled. Please wait until it finishes and then try again.", target, region), 409)
		}
		if next == Enabling && current != Disabled || next == Disabling && current != Enabled {
			return validation("RegionName", "Unable to switch region status because of its current opt-in status.", "invalidRegionOptTarget")
		}
		delay := enableDelay
		if next == Disabling {
			delay = disableDelay
		}
		if err := writer.PutRegion(key, RegionRecord{Status: next, Due: instant.Add(delay)}); err != nil {
			return err
		}
		return s.recordAPICall(ctx, action, input, &api.Unit{}, nil)
	})
	return &api.Unit{}, err
}

// RegionEnabled checks the destination account for regional credential issuance
// using the caller's captured authority time and borrowed transaction context.
func (s *Service) RegionEnabled(ctx context.Context, accountID, region string, instant time.Time) (bool, error) {
	// China and GovCloud accounts have access to their partition's regions;
	// commercial opt-in is separate from credential partition validation.
	// https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html
	if awsctx.FromContext(ctx).Partition != "aws" {
		return true, nil
	}
	var enabled bool
	err := s.repository.View(ctx, func(reader Reader) error {
		status, err := regionStatus(reader, RegionKey{awsctx.FromContext(ctx).Partition, accountID, region}, instant)
		enabled = status == EnabledByDefault || status == Enabled || status == Disabling
		return err
	})
	var apiErr *awswire.Error
	if errors.As(err, &apiErr) && (apiErr.Code == "ValidationException" || apiErr.Code == "AccessDeniedException") {
		return false, nil
	}
	return enabled, err
}
