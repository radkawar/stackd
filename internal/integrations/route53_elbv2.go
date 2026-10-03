package integrations

import (
	"context"
	"errors"

	"golang.org/x/net/dns/dnsmessage"

	"stackd/internal/services/elbv2"
	"stackd/internal/services/route53"
)

// Route53Aliases delegates ALB alias records to the same owner used by the
// shared DNS endpoint. No address, health, or load-balancer state is copied.
type Route53Aliases struct{ ELBV2 *elbv2.Service }

func (a Route53Aliases) ValidateAlias(ctx context.Context, target route53.AliasTarget, typ dnsmessage.Type) error {
	if a.ELBV2 == nil {
		return errors.New("route53: ALB DNS authority is not configured")
	}
	return a.ELBV2.ValidateDNSAlias(ctx, target.DNSName, target.HostedZoneID, typ)
}

func (a Route53Aliases) ResolveAlias(ctx context.Context, target route53.AliasTarget, typ dnsmessage.Type) ([]dnsmessage.Resource, error) {
	if a.ELBV2 == nil {
		return nil, errors.New("route53: ALB DNS authority is not configured")
	}
	return a.ELBV2.LookupDNSAlias(ctx, target.DNSName, target.HostedZoneID, typ)
}
