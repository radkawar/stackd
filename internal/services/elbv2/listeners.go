package elbv2

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	api "stackd/internal/awsapi/elbv2"
	"strings"
)

func registerListeners(s *Service) {
	register(s, "CreateListener", s.createListener)
	register(s, "DeleteListener", s.deleteListener)
	register(s, "DescribeListeners", s.describeListeners)
	register(s, "ModifyListener", s.modifyListener)
	register(s, "DescribeListenerCertificates", s.describeListenerCertificates)
}
func (s *Service) validateListener(ctx context.Context, tx Reader, lb LoadBalancerRecord, d *api.Listener, certificateID *string) error {
	if intValue(d.Port) < 1 || intValue(d.Port) > 65535 {
		return invalid("Listener port must be between 1 and 65535")
	}
	p := value(d.Protocol)
	if p != "HTTP" && p != "HTTPS" {
		return unsupported("Only HTTP and HTTPS application listeners are supported")
	}
	if len(d.AlpnPolicy) > 0 || d.MutualAuthentication != nil {
		return unsupported("ALPN and mutual TLS authentication are not supported")
	}
	if p == "HTTP" {
		if len(d.Certificates) > 0 || d.SslPolicy != nil {
			return invalid("HTTP listeners cannot have certificates or SSL policies")
		}
		*certificateID = ""
	} else {
		if len(d.Certificates) != 1 {
			return invalid("Exactly one default certificate is required for HTTPS")
		}
		if d.Certificates[0].IsDefault != nil {
			return invalid("IsDefault cannot be specified on listener creation or modification")
		}
		id, e := s.validateListenerCertificate(ctx, value(d.Certificates[0].CertificateArn), *certificateID)
		if e != nil {
			return e
		}
		*certificateID = id
		if d.SslPolicy == nil {
			text(&d.SslPolicy, "ELBSecurityPolicy-2016-08")
		}
		if value(d.SslPolicy) != "ELBSecurityPolicy-TLS13-1-2-Res-2021-06" {
			return unsupported("Only explicitly selected ELBSecurityPolicy-TLS13-1-2-Res-2021-06 is supported")
		}
	}
	if e := validateRedirectProtocol(value(d.Protocol), d.DefaultActions); e != nil {
		return e
	}
	if e := s.validateActions(tx, d.DefaultActions, true); e != nil {
		return e
	}
	return validateActionNetwork(tx, lb, d.DefaultActions)
}
func (s *Service) createListener(ctx context.Context, tx Transaction, in *api.CreateListenerInput) (*api.CreateListenerOutput, error) {
	sc := scopeFor(ctx)
	lb, e := loadBalancer(tx, sc, value(in.LoadBalancerArn))
	if e != nil {
		return nil, e
	}
	d := api.Listener{LoadBalancerArn: in.LoadBalancerArn, Port: in.Port, Protocol: in.Protocol, DefaultActions: in.DefaultActions, Certificates: in.Certificates, SslPolicy: in.SslPolicy, AlpnPolicy: in.AlpnPolicy, MutualAuthentication: in.MutualAuthentication}
	resource := strings.Replace(value(lb.Data.LoadBalancerArn), ":loadbalancer/", ":listener/", 1) + "/*"
	conditions := map[string][]string{"elasticloadbalancing:ListenerProtocol": {value(d.Protocol)}}
	if d.SslPolicy != nil {
		conditions["elasticloadbalancing:SecurityPolicy"] = []string{value(d.SslPolicy)}
	}
	if e = s.authorizeChildCreate(ctx, "CreateListener", value(lb.Data.LoadBalancerArn), lb.Tags, resource, in.Tags, conditions); e != nil {
		return nil, e
	}
	certificateID := ""
	if e = s.validateListener(ctx, tx, lb, &d, &certificateID); e != nil {
		return nil, e
	}
	ls, e := tx.Listeners(sc)
	if e != nil {
		return nil, e
	}
	for _, l := range ls {
		if value(l.Data.LoadBalancerArn) == value(in.LoadBalancerArn) && intValue(l.Data.Port) == intValue(in.Port) {
			prior := l.Data
			prior.ListenerArn = nil
			if reflect.DeepEqual(prior, d) && l.CertificateID == certificateID {
				return &api.CreateListenerOutput{Listeners: api.Listeners{l.Data}}, nil
			}
			return nil, failure("DuplicateListener", "A listener already exists on this port")
		}
	}
	id, e := tx.NextID()
	if e != nil {
		return nil, e
	}
	text(&d.ListenerArn, strings.TrimSuffix(resource, "*")+fmt.Sprintf("%016x", id))
	l := ListenerRecord{Scope: sc, Data: d, Tags: in.Tags, CertificateID: certificateID}
	if e = tx.PutListener(l); e != nil {
		return nil, e
	}
	r := RuleRecord{Scope: sc, ListenerARN: value(d.ListenerArn), Data: api.Rule{Actions: d.DefaultActions}}
	text(&r.Data.RuleArn, strings.Replace(value(d.ListenerArn), ":listener/", ":listener-rule/", 1)+"/"+fmt.Sprintf("%016x", id))
	text(&r.Data.Priority, "default")
	boolean(&r.Data.IsDefault, true)
	if e = tx.PutRule(r); e != nil {
		return nil, e
	}
	if e = refreshAssociations(tx, sc); e != nil {
		return nil, e
	}
	if e = s.touchLoadBalancer(tx, sc, value(lb.Data.LoadBalancerArn)); e != nil {
		return nil, e
	}
	return &api.CreateListenerOutput{Listeners: api.Listeners{d}}, nil
}
func deleteListenerRows(tx Transaction, l ListenerRecord) error {
	rs, e := tx.Rules(l.Scope)
	if e != nil {
		return e
	}
	for _, r := range rs {
		if r.ListenerARN == value(l.Data.ListenerArn) {
			if e = tx.DeleteRule(r.Scope, value(r.Data.RuleArn)); e != nil {
				return e
			}
		}
	}
	return tx.DeleteListener(l.Scope, value(l.Data.ListenerArn))
}
func (s *Service) deleteListener(ctx context.Context, tx Transaction, in *api.DeleteListenerInput) (*api.DeleteListenerOutput, error) {
	l, e := listener(tx, scopeFor(ctx), value(in.ListenerArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "DeleteListener", value(in.ListenerArn), l.Tags, nil); e != nil {
		return nil, e
	}
	if e = deleteListenerRows(tx, l); e != nil {
		return nil, e
	}
	if e = refreshAssociations(tx, l.Scope); e != nil {
		return nil, e
	}
	if e = s.touchLoadBalancer(tx, l.Scope, value(l.Data.LoadBalancerArn)); e != nil {
		return nil, e
	}
	return &api.DeleteListenerOutput{}, nil
}
func (s *Service) describeListeners(ctx context.Context, tx Transaction, in *api.DescribeListenersInput) (*api.DescribeListenersOutput, error) {
	sc := scopeFor(ctx)
	if e := s.authorize(ctx, "DescribeListeners", "*", nil, nil); e != nil {
		return nil, e
	}
	if in.LoadBalancerArn != nil && len(in.ListenerArns) > 0 {
		return nil, invalid("Specify a load balancer or listener ARNs")
	}
	if in.LoadBalancerArn != nil {
		if _, e := loadBalancer(tx, sc, value(in.LoadBalancerArn)); e != nil {
			return nil, e
		}
	}
	ls, e := tx.Listeners(sc)
	if e != nil {
		return nil, e
	}
	out := api.Listeners{}
	found := map[string]bool{}
	for _, l := range ls {
		if in.LoadBalancerArn != nil && value(l.Data.LoadBalancerArn) != value(in.LoadBalancerArn) {
			continue
		}
		if len(in.ListenerArns) > 0 && !slices.Contains(in.ListenerArns, *l.Data.ListenerArn) {
			continue
		}
		out = append(out, l.Data)
		found[value(l.Data.ListenerArn)] = true
	}
	for _, a := range in.ListenerArns {
		if !found[string(a)] {
			return nil, failure("ListenerNotFound", "Listener does not exist")
		}
	}
	out, next, e := page(out, in.Marker, in.PageSize, fmt.Sprint("DescribeListeners:", sc, value(in.LoadBalancerArn), in.ListenerArns), func(v api.Listener) string { return value(v.ListenerArn) })
	return &api.DescribeListenersOutput{Listeners: out, NextMarker: next}, e
}
func (s *Service) modifyListener(ctx context.Context, tx Transaction, in *api.ModifyListenerInput) (*api.ModifyListenerOutput, error) {
	sc := scopeFor(ctx)
	l, e := listener(tx, sc, value(in.ListenerArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "ModifyListener", value(in.ListenerArn), l.Tags, map[string][]string{"elasticloadbalancing:ListenerProtocol": {value(in.Protocol)}, "elasticloadbalancing:SecurityPolicy": {value(in.SslPolicy)}}); e != nil {
		return nil, e
	}
	lb, e := loadBalancer(tx, sc, value(l.Data.LoadBalancerArn))
	if e != nil {
		return nil, e
	}
	d := &l.Data
	if in.Port != nil {
		d.Port = in.Port
	}
	if in.Protocol != nil {
		d.Protocol = in.Protocol
		if value(in.Protocol) == "HTTP" {
			d.Certificates = nil
			d.SslPolicy = nil
		}
	}
	if in.Certificates != nil {
		d.Certificates = in.Certificates
		l.CertificateID = ""
	}
	if in.SslPolicy != nil {
		d.SslPolicy = in.SslPolicy
	}
	if in.DefaultActions != nil {
		d.DefaultActions = in.DefaultActions
	}
	if in.AlpnPolicy != nil {
		d.AlpnPolicy = in.AlpnPolicy
	}
	if in.MutualAuthentication != nil {
		d.MutualAuthentication = in.MutualAuthentication
	}
	if e = s.validateListener(ctx, tx, lb, d, &l.CertificateID); e != nil {
		return nil, e
	}
	ls, e := tx.Listeners(sc)
	if e != nil {
		return nil, e
	}
	for _, other := range ls {
		if value(other.Data.ListenerArn) != value(in.ListenerArn) && value(other.Data.LoadBalancerArn) == value(d.LoadBalancerArn) && intValue(other.Data.Port) == intValue(d.Port) {
			return nil, failure("DuplicateListener", "A listener already exists on this port")
		}
	}
	if e = tx.PutListener(l); e != nil {
		return nil, e
	}
	rs, e := tx.Rules(sc)
	if e != nil {
		return nil, e
	}
	for _, r := range rs {
		if r.ListenerARN == value(d.ListenerArn) && r.Data.IsDefault != nil && *r.Data.IsDefault {
			r.Data.Actions = d.DefaultActions
			if e = tx.PutRule(r); e != nil {
				return nil, e
			}
		}
	}
	if e = refreshAssociations(tx, sc); e != nil {
		return nil, e
	}
	if e = s.touchLoadBalancer(tx, sc, value(d.LoadBalancerArn)); e != nil {
		return nil, e
	}
	return &api.ModifyListenerOutput{Listeners: api.Listeners{*d}}, nil
}
func (s *Service) describeListenerCertificates(ctx context.Context, tx Transaction, in *api.DescribeListenerCertificatesInput) (*api.DescribeListenerCertificatesOutput, error) {
	if e := s.authorize(ctx, "DescribeListenerCertificates", "*", nil, nil); e != nil {
		return nil, e
	}
	l, e := listener(tx, scopeFor(ctx), value(in.ListenerArn))
	if e != nil {
		return nil, e
	}
	out := api.CloneCertificateList(l.Data.Certificates)
	for i := range out {
		boolean(&out[i].IsDefault, true)
	}
	out, next, e := page(out, in.Marker, in.PageSize, fmt.Sprint("DescribeListenerCertificates:", scopeFor(ctx), value(in.ListenerArn)), func(v api.Certificate) string { return value(v.CertificateArn) })
	return &api.DescribeListenerCertificatesOutput{Certificates: out, NextMarker: next}, e
}
