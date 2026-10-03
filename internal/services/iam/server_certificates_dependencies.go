package iam

import (
	"context"
	"strings"

	"stackd/internal/awswire"
)

// ServerCertificateReference identifies IAM-owned deployment material without
// disclosing its body or private key. ID remains stable across name/path changes.
type ServerCertificateReference struct {
	ARN string
	ID  string
}

// ServerCertificateUsage supplies load balancer dependencies across every region
// of this IAM account. The implementation must join the transaction carried by
// ctx, retaining its dependency snapshot until IAM's authorized delete commits.
type ServerCertificateUsage interface {
	ServerCertificateLoadBalancers(context.Context, Scope, ServerCertificateReference) ([]string, error)
}

// SetServerCertificateUsage connects the load balancer dependency authority.
// Configure this during instance assembly, before serving requests. A nil source
// is appropriate only for standalone instances without load balancer consumers.
func (s *Service) SetServerCertificateUsage(source ServerCertificateUsage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serverCertificateUsage = source
}

func (s *Service) checkServerCertificateUnused(ctx context.Context, scope Scope, certificate *ServerCertificateRecord) *awswire.Error {
	s.mu.Lock()
	usage := s.serverCertificateUsage
	s.mu.Unlock()
	if usage == nil {
		return nil
	}
	loadBalancers, err := usage.ServerCertificateLoadBalancers(ctx, scope, ServerCertificateReference{ARN: certificate.ARN, ID: certificate.ID})
	if err != nil {
		return &awswire.Error{Code: "ServiceFailure", Message: "Unable to determine server certificate dependencies.", StatusCode: 500}
	}
	if len(loadBalancers) != 0 {
		return conflict("Certificate: " + certificate.ID + " is currently in use by " + strings.Join(loadBalancers, ", ") + ". Please remove it first before deleting it from IAM.")
	}
	return nil
}
