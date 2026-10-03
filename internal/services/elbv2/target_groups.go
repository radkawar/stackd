package elbv2

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	api "stackd/internal/awsapi/elbv2"
	"strconv"
	"strings"
	"time"
)

func registerTargetGroups(s *Service) {
	register(s, "CreateTargetGroup", s.createTargetGroup)
	register(s, "DeleteTargetGroup", s.deleteTargetGroup)
	register(s, "DescribeTargetGroups", s.describeTargetGroups)
	register(s, "ModifyTargetGroup", s.modifyTargetGroup)
	register(s, "DescribeTargetGroupAttributes", s.describeTargetGroupAttributes)
	register(s, "ModifyTargetGroupAttributes", s.modifyTargetGroupAttributes)
}
func (s *Service) createTargetGroup(ctx context.Context, tx Transaction, in *api.CreateTargetGroupInput) (*api.CreateTargetGroupOutput, error) {
	sc := scopeFor(ctx)
	name := value(in.Name)
	if e := validateName(name, false); e != nil {
		return nil, e
	}
	d := api.TargetGroup{TargetGroupName: in.Name, Port: in.Port, Protocol: in.Protocol, ProtocolVersion: in.ProtocolVersion, VpcId: in.VpcId, TargetType: in.TargetType, IpAddressType: in.IpAddressType, HealthCheckEnabled: in.HealthCheckEnabled, HealthCheckIntervalSeconds: in.HealthCheckIntervalSeconds, HealthCheckPath: in.HealthCheckPath, HealthCheckPort: in.HealthCheckPort, HealthCheckProtocol: in.HealthCheckProtocol, HealthCheckTimeoutSeconds: in.HealthCheckTimeoutSeconds, HealthyThresholdCount: in.HealthyThresholdCount, UnhealthyThresholdCount: in.UnhealthyThresholdCount, Matcher: in.Matcher}
	if d.TargetType == nil {
		text(&d.TargetType, "instance")
	}
	if value(d.TargetType) != "ip" && value(d.TargetType) != "instance" {
		return nil, unsupported("Only instance and IP Application Load Balancer targets are supported")
	}
	if value(d.Protocol) != "HTTP" && value(d.Protocol) != "HTTPS" {
		return nil, unsupported("Only HTTP and HTTPS target group protocols are supported")
	}
	if intValue(d.Port) < 1 || intValue(d.Port) > 65535 {
		return nil, invalid("Port must be between 1 and 65535")
	}
	if d.ProtocolVersion == nil {
		text(&d.ProtocolVersion, "HTTP1")
	}
	if value(d.ProtocolVersion) != "HTTP1" {
		return nil, unsupported("HTTP2 and gRPC target protocols are not supported")
	}
	if in.TargetControlPort != nil {
		return nil, unsupported("Target optimizer is not supported")
	}
	if d.IpAddressType == nil {
		text(&d.IpAddressType, "ipv4")
	}
	if value(d.IpAddressType) != "ipv4" {
		return nil, unsupported("IPv6 target groups are not supported")
	}
	defaultHealth(&d)
	if e := validateHealth(d); e != nil {
		return nil, e
	}
	if value(d.VpcId) == "" {
		return nil, invalid("VpcId is required")
	}
	if e := s.authorizeCreate(ctx, "CreateTargetGroup", arn(sc, "targetgroup/"+name+"/*"), in.Tags, nil); e != nil {
		return nil, e
	}
	if e := s.validateTargetGroupNetwork(ctx, value(d.VpcId)); e != nil {
		return nil, e
	}
	groups, e := tx.TargetGroups(sc)
	if e != nil {
		return nil, e
	}
	for _, g := range groups {
		if value(g.Data.TargetGroupName) != name {
			continue
		}
		a, b := g.Data, d
		a.TargetGroupArn = nil
		a.LoadBalancerArns = nil
		b.LoadBalancerArns = nil
		if !reflect.DeepEqual(a, b) {
			return nil, failure("DuplicateTargetGroupName", "A target group with the same name has different settings")
		}
		g.Data.LoadBalancerArns = nil
		return &api.CreateTargetGroupOutput{TargetGroups: api.TargetGroups{g.Data}}, nil
	}
	id, e := tx.NextID()
	if e != nil {
		return nil, e
	}
	text(&d.TargetGroupArn, arn(sc, fmt.Sprintf("targetgroup/%s/%016x", name, id)))
	d.LoadBalancerArns = api.LoadBalancerArns{}
	g := TargetGroupRecord{Scope: sc, Data: d, Tags: in.Tags, DeregistrationDelay: 300 * time.Second}
	if e = tx.PutTargetGroup(g); e != nil {
		return nil, e
	}
	// Creation omits associations; subsequent descriptions retain the list.
	d.LoadBalancerArns = nil
	return &api.CreateTargetGroupOutput{TargetGroups: api.TargetGroups{d}}, nil
}
func defaultHealth(d *api.TargetGroup) {
	if d.HealthCheckEnabled == nil {
		boolean(&d.HealthCheckEnabled, true)
	}
	if d.HealthCheckProtocol == nil {
		text(&d.HealthCheckProtocol, "HTTP")
	}
	if d.HealthCheckPort == nil {
		text(&d.HealthCheckPort, "traffic-port")
	}
	if d.HealthCheckPath == nil {
		text(&d.HealthCheckPath, "/")
	}
	if d.HealthCheckIntervalSeconds == nil {
		number(&d.HealthCheckIntervalSeconds, 30)
	}
	if d.HealthCheckTimeoutSeconds == nil {
		number(&d.HealthCheckTimeoutSeconds, 5)
	}
	if d.HealthyThresholdCount == nil {
		number(&d.HealthyThresholdCount, 5)
	}
	if d.UnhealthyThresholdCount == nil {
		number(&d.UnhealthyThresholdCount, 2)
	}
	if d.Matcher == nil {
		d.Matcher = &api.Matcher{}
		text(&d.Matcher.HttpCode, "200")
	}
}
func validateHealth(d api.TargetGroup) error {
	if d.HealthCheckEnabled == nil || !*d.HealthCheckEnabled {
		return invalid("Health checks cannot be disabled for instance or IP targets")
	}
	if value(d.HealthCheckProtocol) != "HTTP" && value(d.HealthCheckProtocol) != "HTTPS" {
		return invalid("HealthCheckProtocol must be HTTP or HTTPS")
	}
	p := value(d.HealthCheckPort)
	if p != "traffic-port" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return invalid("HealthCheckPort must be traffic-port or a valid port")
		}
	}
	if p := value(d.HealthCheckPath); len(p) < 1 || len(p) > 1024 || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\r\n") {
		return invalid("HealthCheckPath must begin with / and contain at most 1024 characters")
	}
	if n := intValue(d.HealthCheckIntervalSeconds); n < 5 || n > 300 {
		return invalid("HealthCheckIntervalSeconds must be between 5 and 300")
	}
	if n := intValue(d.HealthCheckTimeoutSeconds); n < 2 || n > 120 || n >= intValue(d.HealthCheckIntervalSeconds) {
		return invalid("HealthCheckTimeoutSeconds must be between 2 and 120 and less than the interval")
	}
	if n := intValue(d.HealthyThresholdCount); n < 2 || n > 10 {
		return invalid("HealthyThresholdCount must be between 2 and 10")
	}
	if n := intValue(d.UnhealthyThresholdCount); n < 2 || n > 10 {
		return invalid("UnhealthyThresholdCount must be between 2 and 10")
	}
	if d.Matcher == nil || d.Matcher.GrpcCode != nil {
		return invalid("HTTP matcher is required")
	}
	for _, part := range strings.Split(value(d.Matcher.HttpCode), ",") {
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return invalid("Invalid HTTP matcher")
		}
		lo, e := strconv.Atoi(bounds[0])
		if e != nil || lo < 200 || lo > 499 {
			return invalid("HTTP matcher codes must be between 200 and 499")
		}
		if len(bounds) == 2 {
			hi, e := strconv.Atoi(bounds[1])
			if e != nil || hi < lo || hi > 499 {
				return invalid("Invalid HTTP matcher range")
			}
		}
	}
	return nil
}
func (s *Service) deleteTargetGroup(ctx context.Context, tx Transaction, in *api.DeleteTargetGroupInput) (*api.DeleteTargetGroupOutput, error) {
	sc := scopeFor(ctx)
	a := value(in.TargetGroupArn)
	if e := scopedARN(sc, a, "targetgroup"); e != nil {
		return nil, e
	}
	g, e := tx.TargetGroup(sc, a)
	if e != nil && e != ErrNotFound {
		return nil, e
	}
	if e = s.authorize(ctx, "DeleteTargetGroup", a, g.Tags, nil); e != nil {
		return nil, e
	}
	if g.Data.TargetGroupArn == nil {
		return &api.DeleteTargetGroupOutput{}, nil
	}
	if len(g.Data.LoadBalancerArns) > 0 {
		return nil, failure("ResourceInUse", "Target group is referenced by a listener or rule")
	}
	targets, e := tx.Targets(sc, a)
	if e != nil {
		return nil, e
	}
	for _, t := range targets {
		if e = tx.DeleteTarget(sc, a, value(t.Data.Id), int32(intValue(t.Data.Port))); e != nil {
			return nil, e
		}
	}
	if e = tx.DeleteTargetGroup(sc, a); e != nil {
		return nil, e
	}
	return &api.DeleteTargetGroupOutput{}, nil
}
func (s *Service) describeTargetGroups(ctx context.Context, tx Transaction, in *api.DescribeTargetGroupsInput) (*api.DescribeTargetGroupsOutput, error) {
	sc := scopeFor(ctx)
	if e := s.authorize(ctx, "DescribeTargetGroups", "*", nil, nil); e != nil {
		return nil, e
	}
	if len(in.TargetGroupArns) > 0 && len(in.Names) > 0 {
		return nil, invalid("Specify either names or ARNs")
	}
	if in.LoadBalancerArn != nil {
		if _, e := loadBalancer(tx, sc, value(in.LoadBalancerArn)); e != nil {
			return nil, e
		}
	}
	rows, e := tx.TargetGroups(sc)
	if e != nil {
		return nil, e
	}
	out := api.TargetGroups{}
	found := map[string]bool{}
	for _, g := range rows {
		a, n := value(g.Data.TargetGroupArn), value(g.Data.TargetGroupName)
		if len(in.TargetGroupArns) > 0 && !slices.Contains(in.TargetGroupArns, api.TargetGroupArn(a)) {
			continue
		}
		if len(in.Names) > 0 && !slices.Contains(in.Names, api.TargetGroupName(n)) {
			continue
		}
		if in.LoadBalancerArn != nil && !slices.Contains(g.Data.LoadBalancerArns, *in.LoadBalancerArn) {
			continue
		}
		out = append(out, g.Data)
		found[a] = true
		found[n] = true
	}
	for _, a := range in.TargetGroupArns {
		if !found[string(a)] {
			return nil, failure("TargetGroupNotFound", "Target group does not exist")
		}
	}
	for _, n := range in.Names {
		if !found[string(n)] {
			return nil, failure("TargetGroupNotFound", "Target group does not exist")
		}
	}
	out, next, e := page(out, in.Marker, in.PageSize, fmt.Sprint("DescribeTargetGroups:", sc, in.TargetGroupArns, in.Names, value(in.LoadBalancerArn)), func(v api.TargetGroup) string { return value(v.TargetGroupArn) })
	return &api.DescribeTargetGroupsOutput{TargetGroups: out, NextMarker: next}, e
}
func (s *Service) modifyTargetGroup(ctx context.Context, tx Transaction, in *api.ModifyTargetGroupInput) (*api.ModifyTargetGroupOutput, error) {
	g, e := targetGroup(tx, scopeFor(ctx), value(in.TargetGroupArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "ModifyTargetGroup", value(in.TargetGroupArn), g.Tags, nil); e != nil {
		return nil, e
	}
	d := &g.Data
	if in.HealthCheckEnabled != nil {
		d.HealthCheckEnabled = in.HealthCheckEnabled
	}
	if in.HealthCheckIntervalSeconds != nil {
		d.HealthCheckIntervalSeconds = in.HealthCheckIntervalSeconds
	}
	if in.HealthCheckPath != nil {
		d.HealthCheckPath = in.HealthCheckPath
	}
	if in.HealthCheckPort != nil {
		d.HealthCheckPort = in.HealthCheckPort
	}
	if in.HealthCheckProtocol != nil {
		d.HealthCheckProtocol = in.HealthCheckProtocol
	}
	if in.HealthCheckTimeoutSeconds != nil {
		d.HealthCheckTimeoutSeconds = in.HealthCheckTimeoutSeconds
	}
	if in.HealthyThresholdCount != nil {
		d.HealthyThresholdCount = in.HealthyThresholdCount
	}
	if in.UnhealthyThresholdCount != nil {
		d.UnhealthyThresholdCount = in.UnhealthyThresholdCount
	}
	if in.Matcher != nil {
		d.Matcher = in.Matcher
	}
	if e = validateHealth(*d); e != nil {
		return nil, e
	}
	if e = tx.PutTargetGroup(g); e != nil {
		return nil, e
	}
	ts, e := tx.Targets(g.Scope, value(g.Data.TargetGroupArn))
	if e != nil {
		return nil, e
	}
	for _, t := range ts {
		if t.State == "draining" {
			continue
		}
		t.Version, e = tx.NextID()
		if e != nil {
			return nil, e
		}
		t.NextCheck = s.clock.Now()
		t.Successes = 0
		t.Failures = 0
		if e = tx.PutTarget(t); e != nil {
			return nil, e
		}
	}
	return &api.ModifyTargetGroupOutput{TargetGroups: api.TargetGroups{g.Data}}, nil
}
func targetGroupAttributes(g TargetGroupRecord) api.TargetGroupAttributes {
	// Readback includes fixed defaults. Non-default settings remain rejected
	// until their respective routing and health owners implement them.
	return api.TargetGroupAttributes{
		{Key: new(api.TargetGroupAttributeKey("deregistration_delay.timeout_seconds")), Value: new(api.TargetGroupAttributeValue(strconv.FormatInt(int64(g.DeregistrationDelay/time.Second), 10)))},
		{Key: new(api.TargetGroupAttributeKey("stickiness.enabled")), Value: new(api.TargetGroupAttributeValue("false"))},
		{Key: new(api.TargetGroupAttributeKey("stickiness.type")), Value: new(api.TargetGroupAttributeValue("lb_cookie"))},
		{Key: new(api.TargetGroupAttributeKey("stickiness.lb_cookie.duration_seconds")), Value: new(api.TargetGroupAttributeValue("86400"))},
		{Key: new(api.TargetGroupAttributeKey("stickiness.app_cookie.duration_seconds")), Value: new(api.TargetGroupAttributeValue("86400"))},
		{Key: new(api.TargetGroupAttributeKey("stickiness.app_cookie.cookie_name")), Value: new(api.TargetGroupAttributeValue(""))},
		{Key: new(api.TargetGroupAttributeKey("slow_start.duration_seconds")), Value: new(api.TargetGroupAttributeValue("0"))},
		{Key: new(api.TargetGroupAttributeKey("load_balancing.algorithm.type")), Value: new(api.TargetGroupAttributeValue("round_robin"))},
		{Key: new(api.TargetGroupAttributeKey("load_balancing.algorithm.anomaly_mitigation")), Value: new(api.TargetGroupAttributeValue("off"))},
		{Key: new(api.TargetGroupAttributeKey("load_balancing.cross_zone.enabled")), Value: new(api.TargetGroupAttributeValue("use_load_balancer_configuration"))},
		{Key: new(api.TargetGroupAttributeKey("target_group_health.dns_failover.minimum_healthy_targets.count")), Value: new(api.TargetGroupAttributeValue("1"))},
		{Key: new(api.TargetGroupAttributeKey("target_group_health.dns_failover.minimum_healthy_targets.percentage")), Value: new(api.TargetGroupAttributeValue("off"))},
		{Key: new(api.TargetGroupAttributeKey("target_group_health.unhealthy_state_routing.minimum_healthy_targets.count")), Value: new(api.TargetGroupAttributeValue("1"))},
		{Key: new(api.TargetGroupAttributeKey("target_group_health.unhealthy_state_routing.minimum_healthy_targets.percentage")), Value: new(api.TargetGroupAttributeValue("off"))},
	}
}
func (s *Service) describeTargetGroupAttributes(ctx context.Context, tx Transaction, in *api.DescribeTargetGroupAttributesInput) (*api.DescribeTargetGroupAttributesOutput, error) {
	g, e := targetGroup(tx, scopeFor(ctx), value(in.TargetGroupArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "DescribeTargetGroupAttributes", "*", nil, nil); e != nil {
		return nil, e
	}
	return &api.DescribeTargetGroupAttributesOutput{Attributes: targetGroupAttributes(g)}, nil
}
func (s *Service) modifyTargetGroupAttributes(ctx context.Context, tx Transaction, in *api.ModifyTargetGroupAttributesInput) (*api.ModifyTargetGroupAttributesOutput, error) {
	g, e := targetGroup(tx, scopeFor(ctx), value(in.TargetGroupArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "ModifyTargetGroupAttributes", value(in.TargetGroupArn), g.Tags, nil); e != nil {
		return nil, e
	}
	seen := map[string]bool{}
	for _, a := range in.Attributes {
		k := value(a.Key)
		if seen[k] {
			return nil, invalid("Duplicate attribute")
		}
		seen[k] = true
		if k != "deregistration_delay.timeout_seconds" {
			return nil, unsupported("Unsupported target group attribute: " + k)
		}
		n, e := strconv.Atoi(value(a.Value))
		if e != nil || n < 0 || n > 3600 {
			return nil, invalid("Deregistration delay must be between 0 and 3600 seconds")
		}
		g.DeregistrationDelay = time.Duration(n) * time.Second
	}
	if e = tx.PutTargetGroup(g); e != nil {
		return nil, e
	}
	return &api.ModifyTargetGroupAttributesOutput{Attributes: targetGroupAttributes(g)}, nil
}
