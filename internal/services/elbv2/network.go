package elbv2

import (
	"context"
	"crypto/tls"
	"errors"
	"net/netip"
	"strings"

	native "stackd/compute/elbv2"
	"stackd/compute/network"
	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/awswire"
)

// NetworkAuthority keeps ENI identity, address allocation and current packet
// policy in EC2. Runtime code never persists or invents a second policy graph.
type NetworkAuthority interface {
	Validate(context.Context, Scope, []string, []string) (string, api.AvailabilityZones, error)
	DefaultSecurityGroups(context.Context, Scope, string) ([]string, error)
	SetSecurityGroups(context.Context, Scope, string, string, []string) (NetworkAttachment, error)
	ValidateVPC(context.Context, Scope, string) error
	Allocate(context.Context, Scope, string, string, uint64, bool, []string) (NetworkAttachment, error)
	Observe(context.Context, Scope, string, string) (NetworkAttachment, error)
	Release(context.Context, Scope, string, string) error
	ResolveTarget(context.Context, Scope, string, string, string) (TargetEndpoint, error)
}
type NetworkAttachment struct {
	ID, SubnetID  string
	PublicAddress string
	Network       network.Specification
}
type TargetEndpoint struct {
	Address, AvailabilityZone, InterfaceID, OwnerARN, Incarnation string
}

func loadBalancerAddress(internetFacing bool, attachment NetworkAttachment) string {
	if internetFacing {
		return attachment.PublicAddress
	}
	return attachment.Network.Address.String()
}

// CertificateSource supplies detached TLS material from its actual owner. Private
// keys are never copied into load-balancer resource state or API responses.
type CertificateSource interface {
	Certificate(context.Context, Scope, string, string) (tls.Certificate, error)
	CertificateID(context.Context, Scope, string) (string, error)
}
type NativeRuntime = native.Runtime

func (s *Service) validateLoadBalancerNetwork(ctx context.Context, subnets, groups []string) (string, api.AvailabilityZones, error) {
	if s.networks == nil || s.runtime == nil || s.runtime.native == nil {
		return "", nil, failure("UnsupportedOperation", "Application Load Balancers require a configured native network runtime.")
	}
	if !s.dnsAttached {
		return "", nil, failure("UnsupportedOperation", "Application Load Balancers require a configured DNS endpoint.")
	}
	vpc, zones, err := s.networks.Validate(ctx, scopeFor(ctx), subnets, groups)
	return vpc, zones, networkAdmissionError(err)
}
func (s *Service) validateTargetGroupNetwork(ctx context.Context, vpcID string) error {
	if s.networks == nil {
		return failure("UnsupportedOperation", "Target groups require the EC2 network authority.")
	}
	return networkAdmissionError(s.networks.ValidateVPC(ctx, scopeFor(ctx), vpcID))
}
func networkAdmissionError(err error) error {
	var apiErr *awswire.Error
	if !errors.As(err, &apiErr) {
		return err
	}
	switch apiErr.Code {
	case "InvalidSubnetID.NotFound":
		return failure("SubnetNotFound", apiErr.Message)
	case "InvalidGroup.NotFound":
		return failure("InvalidSecurityGroup", apiErr.Message)
	case "InvalidParameterValue", "InvalidParameter", "InvalidVpcID.NotFound":
		return failure("ValidationError", apiErr.Message)
	case "UnauthorizedOperation":
		return failure("AccessDenied", apiErr.Message)
	}
	return err
}
func (s *Service) validateListenerCertificate(ctx context.Context, arn, id string) (string, error) {
	if s.runtime == nil || s.runtime.certificates == nil {
		return "", failure("UnsupportedOperation", "HTTPS requires a configured certificate owner.")
	}
	scope := scopeFor(ctx)
	if !strings.HasPrefix(arn, "arn:"+scope.Partition+":iam::"+scope.AccountID+":server-certificate/") &&
		!strings.HasPrefix(arn, "arn:"+scope.Partition+":acm:"+scope.Region+":"+scope.AccountID+":certificate/") {
		return "", failure("CertificateNotFound", "Certificate is not available in this account and region.")
	}
	if id == "" {
		var err error
		id, err = s.runtime.certificates.CertificateID(ctx, scope, arn)
		if err != nil || id == "" {
			return "", failure("CertificateNotFound", "Certificate is not available from its owner.")
		}
	}
	if _, err := s.runtime.certificates.Certificate(ctx, scope, arn, id); err != nil {
		return "", failure("CertificateNotFound", "Certificate is not available from its owner.")
	}
	return id, nil
}
func targetAddress(endpoint TargetEndpoint) (netip.Addr, error) {
	addr, err := netip.ParseAddr(endpoint.Address)
	if err != nil || !addr.Is4() || !addr.IsGlobalUnicast() {
		return netip.Addr{}, errors.New("target has no usable IPv4 endpoint")
	}
	return addr, nil
}
