package cloudtrail

import (
	"context"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Organization is a current view from Organizations, never a second membership store.
// Administrator includes the management account and active CloudTrail delegates.
type Organization struct {
	ID, ManagementAccountID                   string
	AllFeatures, TrustedAccess, Administrator bool
}

// OrganizationView joins the caller's transaction for current membership, trust,
// delegation and Account-owned regional availability. No external effects run here.
type OrganizationView interface {
	Organization(context.Context, string, string) (Organization, error)
	RegionEnabled(context.Context, string, string, string) (bool, error)
	DigestScopes(context.Context, TrailRecord) ([]Scope, error)
}

func organizationFor(ctx context.Context, view OrganizationView, partition, account string) (Organization, error) {
	if view == nil {
		return Organization{}, nil
	}
	return view.Organization(ctx, partition, account)
}

func (s *Service) organizationAdmission(ctx context.Context, conversion bool) (Organization, *awswire.Error) {
	m := awsctx.FromContext(ctx)
	org, err := organizationFor(ctx, s.organizations, m.Partition, m.AccountID)
	if err != nil {
		return org, wireError(err)
	}
	if org.ID == "" {
		return org, failure("OrganizationsNotInUseException", "The account is not a member of an organization.")
	}
	if !org.Administrator || conversion && m.AccountID != org.ManagementAccountID {
		return org, failure("NotOrganizationMasterAccountException", "Only the management account can convert trails; creation requires the management account or a CloudTrail delegated administrator.")
	}
	if !org.AllFeatures {
		return org, failure("OrganizationNotInAllFeaturesModeException", "The organization must have all features enabled.")
	}
	if !org.TrustedAccess {
		return org, failure("CloudTrailAccessNotEnabledException", "Trusted access for CloudTrail is not enabled in AWS Organizations.")
	}
	return org, nil
}

// visibleTrails projects member shadows from the management-owned trail. Joins,
// leaves and delegation changes therefore take effect without copied trail rows.
func visibleTrails(r Reader, view OrganizationView, partition, account string) ([]TrailRecord, error) {
	trails, err := r.Trails(partition, account)
	if err != nil {
		return nil, err
	}
	// Ordinary trails must not make permission-free authentication depend on
	// Organizations storage when no organization trail is configured.
	hasOrganizationTrails, err := r.HasOrganizationTrails(partition)
	if err != nil || !hasOrganizationTrails {
		return trails, err
	}
	org, err := organizationFor(r.Context(), view, partition, account)
	if err != nil {
		return nil, err
	}
	if org.ID == "" || !org.AllFeatures || !org.TrustedAccess || org.ManagementAccountID == account {
		return trails, nil
	}
	owned, err := r.Trails(partition, org.ManagementAccountID)
	if err != nil {
		return nil, err
	}
	for _, trail := range owned {
		if trail.OrganizationID == org.ID {
			trails = append(trails, trail)
		}
	}
	return trails, nil
}

func organizationRegion(ctx context.Context, view OrganizationView, trail TrailRecord, account, region string) (bool, error) {
	if trail.OrganizationID == "" {
		return true, nil
	}
	if view == nil {
		return false, unsupported("No organization view is configured.")
	}
	enabled, err := view.RegionEnabled(ctx, trail.Key.Partition, account, trail.Key.Region)
	if err != nil || !enabled || region == trail.Key.Region {
		return enabled, err
	}
	return view.RegionEnabled(ctx, trail.Key.Partition, account, region)
}

func (s *Service) resolveTrail(r Reader, reference string) (TrailRecord, error) {
	key, wire := keyFor(r.Context(), reference)
	if wire != nil {
		return TrailRecord{}, wire
	}
	m := awsctx.FromContext(r.Context())
	trails, err := visibleTrails(r, s.organizations, m.Partition, m.AccountID)
	if err != nil {
		return TrailRecord{}, err
	}
	arn := strings.HasPrefix(reference, "arn:")
	for _, trail := range trails {
		if arn && trail.Key != key || !arn && (trail.Key.Name != key.Name || trail.Key.Region != m.Region && !trail.MultiRegion) {
			continue
		}
		// Member shadows of a single-region trail exist only in its home region.
		if trail.Key.AccountID != m.AccountID && !trail.MultiRegion && trail.Key.Region != m.Region {
			continue
		}
		ok, err := organizationRegion(r.Context(), s.organizations, trail, m.AccountID, m.Region)
		if err != nil {
			return TrailRecord{}, err
		}
		if ok {
			return trail, nil
		}
	}
	return TrailRecord{}, ErrNotFound
}

// ReconcileOrganization removes organization scope permanently when trusted
// access or the owning organization disappears. Source Organizations outcomes
// invoke this in their shared journal transaction, including disable/re-enable.
func reconcileOrganization(tx Transaction, view OrganizationView, partition, account string) error {
	if view == nil {
		return nil
	}
	trails, err := tx.Trails(partition, account)
	if err != nil {
		return err
	}
	org, err := organizationFor(tx.Context(), view, partition, account)
	if err != nil {
		return err
	}
	for _, trail := range trails {
		if trail.OrganizationID != "" && (org.ID != trail.OrganizationID || org.ManagementAccountID != account || !org.TrustedAccess || !org.AllFeatures) {
			trail.OrganizationID = ""
			if err := tx.PutTrail(trail); err != nil {
				return err
			}
		}
	}
	return nil
}
