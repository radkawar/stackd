package elbv2

import (
	"context"
	"errors"
	"slices"
	"strings"
)

// ServerCertificateReference names IAM- or ACM-owned material; no private
// deployment material is copied into ELB control state.
type ServerCertificateReference struct {
	ARN string
	ID  string
}

// ServerCertificateLoadBalancers observes this account's listeners, restricted to
// the certificate's region for ACM. The owner calls it inside its authorized
// deletion transaction; View joins it so admission cannot race the snapshot.
func (s *Service) ServerCertificateLoadBalancers(ctx context.Context, scope Scope, certificate ServerCertificateReference) ([]string, error) {
	isIAM := strings.HasPrefix(certificate.ARN, "arn:"+scope.Partition+":iam::"+scope.AccountID+":server-certificate/")
	isACM := scope.Region != "" && strings.HasPrefix(certificate.ARN, "arn:"+scope.Partition+":acm:"+scope.Region+":"+scope.AccountID+":certificate/")
	if scope.Partition == "" || scope.AccountID == "" || certificate.ID == "" || (!isIAM && !isACM) {
		return nil, errors.New("elbv2: invalid server certificate dependency scope")
	}
	var loadBalancers []string
	err := s.repository.View(ctx, func(tx Reader) error {
		listeners, err := tx.Listeners(Scope{})
		if err != nil {
			return err
		}
		for _, listener := range listeners {
			if listener.Partition != scope.Partition || listener.AccountID != scope.AccountID || isACM && listener.Region != scope.Region {
				continue
			}
			if listener.CertificateID == certificate.ID && (isIAM || len(listener.Data.Certificates) == 1 && value(listener.Data.Certificates[0].CertificateArn) == certificate.ARN) {
				loadBalancers = append(loadBalancers, value(listener.Data.LoadBalancerArn))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(loadBalancers)
	return slices.Compact(loadBalancers), nil
}
