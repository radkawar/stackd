package integrations

import (
	"context"
	"crypto/tls"
	"errors"

	"stackd/internal/services/acm"
	"stackd/internal/services/elbv2"
	"stackd/internal/services/iam"
	"strings"
)

// ELBV2Certificates resolves live IAM- or ACM-owned TLS material. ELB admission
// owns caller permission; private keys never enter ALB resource state.
type ELBV2Certificates struct {
	IAM *iam.Service
	ACM *acm.Service
}

var _ elbv2.CertificateSource = ELBV2Certificates{}

func (a ELBV2Certificates) Certificate(ctx context.Context, scope elbv2.Scope, arn, id string) (tls.Certificate, error) {
	if strings.HasPrefix(arn, "arn:"+scope.Partition+":acm:") {
		if a.ACM == nil {
			return tls.Certificate{}, errors.New("elbv2: ACM certificate authority is not configured")
		}
		if err := elbv2ScopeContext(ctx, scope); err != nil {
			return tls.Certificate{}, err
		}
		return a.ACM.Certificate(ctx, acm.Scope{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, arn, id)
	}
	if a.IAM == nil {
		return tls.Certificate{}, errors.New("elbv2: IAM certificate authority is not configured")
	}
	if err := elbv2ScopeContext(ctx, scope); err != nil {
		return tls.Certificate{}, err
	}
	return a.IAM.ServerCertificateForTLSByID(ctx, iam.Scope{Partition: scope.Partition, AccountID: scope.AccountID}, id)
}

func (a ELBV2Certificates) CertificateID(ctx context.Context, scope elbv2.Scope, arn string) (string, error) {
	if strings.HasPrefix(arn, "arn:"+scope.Partition+":acm:") {
		if a.ACM == nil {
			return "", errors.New("elbv2: ACM certificate authority is not configured")
		}
		if err := elbv2ScopeContext(ctx, scope); err != nil {
			return "", err
		}
		return a.ACM.CertificateID(ctx, acm.Scope{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, arn)
	}
	if a.IAM == nil {
		return "", errors.New("elbv2: IAM certificate authority is not configured")
	}
	if err := elbv2ScopeContext(ctx, scope); err != nil {
		return "", err
	}
	return a.IAM.CertificateID(ctx, iam.Scope{Partition: scope.Partition, AccountID: scope.AccountID}, arn)
}
