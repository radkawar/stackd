package organizations

import (
	"fmt"
	"regexp"
	"strings"
)

const defaultAccountQuota = 10

// AccountQuota configures the maximum organization size for one management
// account. The management account and closed members count toward Maximum.
// Scope is global across regions and isolated by partition.
type AccountQuota struct {
	Partition           string
	ManagementAccountID string
	Maximum             int
}

type accountQuotaScope struct{ partition, management string }

// AccountQuotas is immutable validated configuration. Nil uses the published
// default. Configuration changes take effect when a service is reconstructed;
// they do not erase accounts or accepted creation jobs.
type AccountQuotas struct{ overrides map[accountQuotaScope]int }

var quotaPartitionPattern = regexp.MustCompile(`^aws(?:-[a-z]+)*$`)

// NewAccountQuotas validates explicit overrides and detaches the caller's input.
// AWS publishes an adjustable account quota with a maximum of 50,000. New
// organizations can have an applied quota below the default of ten.
// Source: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html
func NewAccountQuotas(overrides []AccountQuota) (*AccountQuotas, error) {
	quotas := &AccountQuotas{overrides: make(map[accountQuotaScope]int, len(overrides))}
	for _, override := range overrides {
		if !quotaPartitionPattern.MatchString(override.Partition) {
			return nil, fmt.Errorf("organization account quota requires a valid AWS partition")
		}
		if len(override.ManagementAccountID) != 12 || strings.Trim(override.ManagementAccountID, "0123456789") != "" {
			return nil, fmt.Errorf("organization account quota requires a 12-digit management account ID")
		}
		if override.Maximum < 1 || override.Maximum > 50000 {
			return nil, fmt.Errorf("organization account quota must be between 1 and 50000")
		}
		key := accountQuotaScope{override.Partition, override.ManagementAccountID}
		if _, exists := quotas.overrides[key]; exists {
			return nil, fmt.Errorf("duplicate organization account quota for %s/%s", override.Partition, override.ManagementAccountID)
		}
		quotas.overrides[key] = override.Maximum
	}
	return quotas, nil
}

func (q *AccountQuotas) maximum(partition, management string) int {
	if q != nil {
		if maximum, ok := q.overrides[accountQuotaScope{partition, management}]; ok {
			return maximum
		}
	}
	return defaultAccountQuota
}

// accountQuotaReached includes open invitation reservations. A pending create
// can fail at completion if another operation has consumed the remaining space.
func (s *operationState) accountQuotaReached(o *orgState, maximum int, accepting string) bool {
	count := len(o.accounts)
	for _, stored := range s.handshakes {
		invitation, visible := s.observeHandshake(stored)
		if visible && invitation.Action == "INVITE" && invitation.OrganizationID == o.organization.ID && invitation.State == "OPEN" && invitation.ID != accepting {
			count++
		}
	}
	return count >= maximum
}
