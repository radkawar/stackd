package integrations

import (
	"context"
	"time"

	"stackd/clock"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudtrail"
	"stackd/storage/organizations"
)

// CloudTrailOrganizations reads the existing authoritative Organizations storage
// with the borrowed transaction. CloudTrail retains only the organization ID.
type CloudTrailOrganizations struct {
	Storage organizations.Storage
	Regions interface {
		RegionEnabled(context.Context, string, string, time.Time) (bool, error)
	}
	Clock clock.Clock
}

func (a CloudTrailOrganizations) Organization(ctx context.Context, partition, account string) (cloudtrail.Organization, error) {
	state, _, err := a.Storage.Load(ctx, partition)
	if err != nil {
		return cloudtrail.Organization{}, err
	}
	for _, org := range state.Organizations {
		member, active := false, false
		for _, candidate := range org.Accounts {
			if candidate.ID == account {
				member, active = true, candidate.State == "ACTIVE"
				break
			}
		}
		if !member {
			continue
		}
		out := cloudtrail.Organization{ID: org.Organization.ID, ManagementAccountID: org.Organization.MasterAccountID, AllFeatures: org.Organization.FeatureSet == "ALL"}
		for _, service := range org.Services {
			if service.Principal == "cloudtrail.amazonaws.com" {
				out.TrustedAccess = true
				break
			}
		}
		out.Administrator = active && account == out.ManagementAccountID
		for _, delegate := range org.Delegations {
			if active && delegate.AccountID == account && delegate.Principal == "cloudtrail.amazonaws.com" {
				out.Administrator = true
				break
			}
		}
		return out, nil
	}
	return cloudtrail.Organization{}, nil
}

func (a CloudTrailOrganizations) RegionEnabled(ctx context.Context, partition, account, region string) (bool, error) {
	metadata := awsctx.FromContext(ctx)
	metadata.Partition = partition
	return a.Regions.RegionEnabled(awsctx.WithMetadata(ctx, metadata), account, region, a.Clock.Now())
}

// DigestScopes resolves empty-hour chains too, without waiting for a member API
// event. Membership and regional opt-in remain owned by their existing services.
func (a CloudTrailOrganizations) DigestScopes(ctx context.Context, trail cloudtrail.TrailRecord) ([]cloudtrail.Scope, error) {
	accounts := []string{trail.Key.AccountID}
	if trail.OrganizationID != "" {
		state, _, err := a.Storage.Load(ctx, trail.Key.Partition)
		if err != nil {
			return nil, err
		}
		accounts = nil
		for _, org := range state.Organizations {
			if org.Organization.ID != trail.OrganizationID {
				continue
			}
			for _, member := range org.Accounts {
				if member.State == "ACTIVE" {
					accounts = append(accounts, member.ID)
				}
			}
		}
	}
	regions := []string{trail.Key.Region}
	if trail.MultiRegion {
		regions = nil
		switch trail.Key.Partition {
		case "aws":
			for _, region := range awscatalog.CommercialRegions() {
				regions = append(regions, region.Name)
			}
		case "aws-cn":
			regions = []string{"cn-north-1", "cn-northwest-1"}
		case "aws-us-gov":
			regions = []string{"us-gov-east-1", "us-gov-west-1"}
		default:
			regions = []string{trail.Key.Region}
		}
	}
	out := []cloudtrail.Scope{}
	for _, account := range accounts {
		home, err := a.RegionEnabled(ctx, trail.Key.Partition, account, trail.Key.Region)
		if err != nil {
			return nil, err
		}
		if !home {
			continue
		}
		for _, region := range regions {
			enabled, err := a.RegionEnabled(ctx, trail.Key.Partition, account, region)
			if err != nil {
				return nil, err
			}
			if enabled {
				out = append(out, cloudtrail.Scope{Partition: trail.Key.Partition, AccountID: account, Region: region})
			}
		}
	}
	return out, nil
}
