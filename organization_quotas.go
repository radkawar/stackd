package stackd

import "stackd/internal/services/organizations"

// OrganizationAccountQuota overrides the published organization-size default
// for one management account and partition. See Config.OrganizationAccountQuotas.
type OrganizationAccountQuota = organizations.AccountQuota
