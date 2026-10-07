package integrations

import (
	"context"

	"stackd/internal/services/apigatewayv2"
	"stackd/internal/services/elbv2"
)

// ACMCertificateUsage checks live load-balancer and API Gateway domain bindings
// in the caller's shared transaction domain.
type ACMCertificateUsage struct {
	ELBV2      *elbv2.Service
	APIGateway *apigatewayv2.Service
}

func (a ACMCertificateUsage) CertificateUsers(ctx context.Context, partition, account, region, arn, id string) ([]string, error) {
	users, err := (ELBV2CertificateUsage{ELBV2: a.ELBV2}).CertificateUsers(ctx, partition, account, region, arn, id)
	if err != nil {
		return nil, err
	}
	domains, err := a.APIGateway.CertificateUsers(ctx, partition, account, region, arn, id)
	if err != nil {
		return nil, err
	}
	return append(users, domains...), nil
}
