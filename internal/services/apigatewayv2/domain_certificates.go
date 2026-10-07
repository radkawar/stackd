package apigatewayv2

import "context"

// CertificateUsers implements ACM's live consumer boundary, including the
// ownership-verification certificate. Matching both ARN and immutable identity
// prevents a deleted certificate incarnation from acquiring old associations.
func (s *Service) CertificateUsers(ctx context.Context, partition, account, region, arn, id string) ([]string, error) {
	users := []string{}
	e := s.repository.View(ctx, func(r Reader) error {
		rows, e := r.Domains(Scope{Partition: partition, AccountID: account, Region: region})
		if e != nil {
			return e
		}
		for _, domain := range rows {
			if domain.CertificateARN == arn && domain.CertificateID == id || domain.OwnershipCertificateARN == arn && domain.OwnershipCertificateID == id {
				users = append(users, controlARN(domain.Key.Scope, "/domainnames/"+domain.Key.Name))
			}
		}
		return nil
	})
	return users, e
}
