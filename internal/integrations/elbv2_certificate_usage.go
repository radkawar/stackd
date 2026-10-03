package integrations

import (
	"context"
	"errors"

	"stackd/internal/services/acm"
	"stackd/internal/services/elbv2"
	"stackd/internal/services/iam"
)

// ELBV2CertificateUsage protects IAM certificate deletion using ELB-owned
// listener dependencies. Both repositories must share the instance transaction
// domain; the IAM write context is borrowed without opening an independent view.
type ELBV2CertificateUsage struct{ ELBV2 *elbv2.Service }

var _ iam.ServerCertificateUsage = ELBV2CertificateUsage{}
var _ acm.CertificateUsage = ELBV2CertificateUsage{}

func (a ELBV2CertificateUsage) CertificateUsers(ctx context.Context, partition, accountID, region, arn, id string) ([]string, error) {
	if a.ELBV2 == nil {
		return nil, errors.New("elbv2: certificate dependency authority is not configured")
	}
	return a.ELBV2.ServerCertificateLoadBalancers(ctx, elbv2.Scope{Partition: partition, AccountID: accountID, Region: region}, elbv2.ServerCertificateReference{ARN: arn, ID: id})
}

func (a ELBV2CertificateUsage) ServerCertificateLoadBalancers(ctx context.Context, scope iam.Scope, certificate iam.ServerCertificateReference) ([]string, error) {
	if a.ELBV2 == nil {
		return nil, errors.New("elbv2: certificate dependency authority is not configured")
	}
	return a.ELBV2.ServerCertificateLoadBalancers(ctx, elbv2.Scope{Partition: scope.Partition, AccountID: scope.AccountID}, elbv2.ServerCertificateReference{ARN: certificate.ARN, ID: certificate.ID})
}
