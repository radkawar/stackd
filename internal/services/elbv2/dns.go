package elbv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"stackd/compute/dns"
)

// DNSAuthority attaches this service's read-only DNS owner to an already bound
// endpoint. The release function removes only this service's registration.
type DNSAuthority interface {
	Register(dns.Resolver) (func(), error)
}

// RegisterDNS migrates retained projections and attaches the managed DNS owner.
// Assembly calls it before customer hosted zones, then Start reuses the binding.
// Configure it before workers or API admission; registration is idempotent.
func (s *Service) RegisterDNS(ctx context.Context) error {
	authority := s.dns
	if authority == nil {
		return errors.New("load-balancer DNS authority is absent")
	}
	if s.dnsAttached {
		return nil
	}
	if err := s.migrateDNSNames(ctx); err != nil {
		return err
	}
	release, err := authority.Register(s)
	if err != nil {
		return err
	}
	s.dnsRelease = release
	s.dnsAttached = true
	return nil
}

func loadBalancerDNSName(lb LoadBalancerRecord) string {
	// VPC and scoped ARN are immutable. The VPC identity also separates stores
	// whose sequential ALB IDs and account/region happen to be identical.
	digest := sha256.Sum256([]byte(value(lb.Data.LoadBalancerArn) + "\x00" + value(lb.Data.VpcId)))
	name := strings.ToLower(value(lb.Data.LoadBalancerName)) + "-" + hex.EncodeToString(digest[:10])
	if value(lb.Data.Scheme) == "internal" {
		name = "internal-" + name
	}
	suffix := "amazonaws.com"
	if lb.Partition == "aws-cn" {
		suffix += ".cn"
	}
	return name + "." + lb.Region + ".elb." + suffix
}

// ensureDNSName cuts retained literal-IP projections over to the single naming
// authority. Already-issued names never change with ENI/address replacement.
func ensureDNSName(lb *LoadBalancerRecord) bool {
	changed := false
	if zoneID := applicationHostedZones[lb.Region]; value(lb.Data.CanonicalHostedZoneId) == "" && zoneID != "" {
		text(&lb.Data.CanonicalHostedZoneId, zoneID)
		changed = true
	}
	name := value(lb.Data.DNSName)
	if _, err := netip.ParseAddr(name); name != "" && err != nil {
		return changed
	}
	text(&lb.Data.DNSName, loadBalancerDNSName(*lb))
	return true
}

func (s *Service) migrateDNSNames(ctx context.Context) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.LoadBalancers(Scope{})
		if err != nil {
			return err
		}
		for _, lb := range rows {
			if ensureDNSName(&lb) {
				if err := tx.PutLoadBalancer(lb); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// LookupDNS resolves only this owner's persisted ALB names. Current addresses
// come from EC2, not cached runtime nodes or a copied network policy. Observe
// runs outside the ALB read transaction because IAM may renew the service session.
func (s *Service) LookupDNS(ctx context.Context, question dnsmessage.Question) (dns.Result, error) {
	return s.lookupDNS(ctx, question, "")
}

// LookupDNSAlias verifies the regional alias zone against the actual ALB owner.
// Route 53 passes public DNS names, not resource credentials or copied addresses.
func (s *Service) LookupDNSAlias(ctx context.Context, name, zoneID string, typ dnsmessage.Type) ([]dnsmessage.Resource, error) {
	if zoneID == "" {
		return nil, ErrNotFound
	}
	name = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(name, ".")), "dualstack.")
	qname, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, err
	}
	result, err := s.lookupDNS(ctx, dnsmessage.Question{Name: qname, Class: dnsmessage.ClassINET, Type: typ}, zoneID)
	if err != nil {
		return nil, err
	}
	if !result.Exists {
		return nil, ErrNotFound
	}
	return result.Answers, nil
}

// ValidateDNSAlias reads only retained ALB ownership and joins a caller's shared
// transaction. It never probes networks or renews runtime service credentials.
func (s *Service) ValidateDNSAlias(ctx context.Context, name, zoneID string, typ dnsmessage.Type) error {
	if zoneID == "" || typ != dnsmessage.TypeA {
		return errors.New("ALB aliases require an A record and the regional hosted zone ID")
	}
	name = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(name, ".")), "dualstack.") + "."
	_, err := s.dnsLoadBalancer(ctx, name, zoneID)
	return err
}

func (s *Service) dnsLoadBalancer(ctx context.Context, name, zoneID string) (LoadBalancerRecord, error) {
	var selected LoadBalancerRecord
	err := s.repository.View(ctx, func(tx Reader) error {
		rows, err := tx.LoadBalancers(Scope{})
		if err != nil {
			return err
		}
		for _, lb := range rows {
			if !lb.Deleting && strings.EqualFold(value(lb.Data.DNSName)+".", name) &&
				(zoneID == "" || zoneID == value(lb.Data.CanonicalHostedZoneId)) {
				selected = lb
				return nil
			}
		}
		return ErrNotFound
	})
	return selected, err
}

func (s *Service) lookupDNS(ctx context.Context, question dnsmessage.Question, aliasZoneID string) (dns.Result, error) {
	name := strings.ToLower(question.Name.String())
	result := dns.Result{}
	if !strings.HasSuffix(name, ".elb.amazonaws.com.") && !strings.HasSuffix(name, ".elb.amazonaws.com.cn.") {
		return result, nil
	}
	result.Authoritative = true
	if s.networks == nil {
		return result, errors.New("load-balancer DNS requires the EC2 network authority")
	}
	selected, err := s.dnsLoadBalancer(ctx, name, aliasZoneID)
	if errors.Is(err, ErrNotFound) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.Exists = true
	if question.Type != dnsmessage.TypeA {
		return result, nil
	}
	ctx = runtimeContext(ctx, selected.Scope)
	for _, zone := range selected.Data.AvailabilityZones {
		id := selected.AttachmentIDs[value(zone.SubnetId)]
		if id == "" {
			continue
		}
		attachment, err := s.networks.Observe(ctx, selected.Scope, value(selected.Data.LoadBalancerArn), id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return result, err
		}
		address, err := netip.ParseAddr(loadBalancerAddress(value(selected.Data.Scheme) == "internet-facing", attachment))
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() {
			continue
		}
		result.Answers = append(result.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: address.As4()}})
	}
	return result, nil
}
