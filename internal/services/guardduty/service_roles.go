package guardduty

import "context"

const ServicePrincipal = "guardduty.amazonaws.com"
const ServiceRoleName = "AWSServiceRoleForAmazonGuardDuty"

// WithRoleUsage joins the IAM deletion decision to a writable detector snapshot.
// Suspending a detector does not disable/delete the regional service resource.
func (s *Service) WithRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []string) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		detectors, err := tx.AllDetectors()
		if err != nil {
			return err
		}
		var resources []string
		for _, d := range detectors {
			if d.Partition == partition && d.AccountID == account {
				resources = append(resources, d.ARN)
			}
		}
		return fn(tx.Context(), resources)
	})
}
