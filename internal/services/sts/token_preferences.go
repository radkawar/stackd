package sts

import (
	"context"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// TokenPreferences supplies the issuing account's current IAM preference from
// the authority transaction. Regional endpoints always issue all-region tokens.
type TokenPreferences interface {
	GlobalEndpointAllRegions(context.Context, string) (bool, error)
}

// RegionAccess supplies current destination-account opt-in state from the
// shared credential authority transaction at its captured decision time.
type RegionAccess interface {
	RegionEnabled(context.Context, string, string, time.Time) (bool, error)
}

type globalEndpointKey struct{}

func (s *Service) defaultRegionsOnly(ctx context.Context, accountID string, instant time.Time) (bool, *awswire.Error) {
	if err := s.checkRegion(ctx, accountID, instant); err != nil {
		return false, err
	}
	global, _ := ctx.Value(globalEndpointKey{}).(bool)
	if !global && awsctx.FromContext(ctx).Region != "aws-global" {
		return false, nil
	}
	if s.tokenPreferences == nil {
		// The isolated credential-only STS provider has no IAM settings.
		return true, nil
	}
	allRegions, err := s.tokenPreferences.GlobalEndpointAllRegions(ctx, accountID)
	if err != nil {
		return false, stsCredentialError(err)
	}
	return !allRegions, nil
}

func (s *Service) checkRegion(ctx context.Context, accountID string, instant time.Time) *awswire.Error {
	// TODO: Comeback implement console-managed regional STS activation and capture variable credential-recognition propagation after Account region disablement.
	global, _ := ctx.Value(globalEndpointKey{}).(bool)
	m := awsctx.FromContext(ctx)
	if s.regions == nil || global || m.Region == "aws-global" {
		return nil
	}
	enabled, err := s.regions.RegionEnabled(ctx, accountID, m.Region, instant)
	if err != nil {
		return stsCredentialError(err)
	}
	if !enabled {
		return stsDenied("The destination account has not enabled the requested region.")
	}
	return nil
}
