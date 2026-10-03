package elbv2

import (
	"context"
	"errors"
	"net/netip"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/elbv2"
	"strconv"
	"strings"
	"time"
)

func registerTargets(s *Service) {
	register(s, "RegisterTargets", s.registerTargets)
	register(s, "DeregisterTargets", s.deregisterTargets)
	register(s, "DescribeTargetHealth", s.describeTargetHealth)
}
func normalizeTarget(g TargetGroupRecord, t api.TargetDescription) (api.TargetDescription, error) {
	if value(t.Id) == "" {
		return t, invalid("Target ID is required")
	}
	if t.QuicServerId != nil {
		return t, unsupported("QUIC targets are not supported")
	}
	if t.Port == nil {
		t.Port = g.Data.Port
	}
	if intValue(t.Port) < 1 || intValue(t.Port) > 65535 {
		return t, invalid("Target port must be between 1 and 65535")
	}
	if value(g.Data.TargetType) == "ip" {
		a, e := netip.ParseAddr(value(t.Id))
		if e != nil || !a.Is4() || !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
			return t, invalid("IP targets must be IPv4 addresses from a VPC subnet, RFC1918, or RFC6598")
		}
	}
	if value(g.Data.TargetType) == "instance" && t.AvailabilityZone != nil {
		return t, invalid("AvailabilityZone cannot be specified for instance targets")
	}
	return t, nil
}
func (s *Service) registerTarget(ctx context.Context, tx Transaction, g TargetGroupRecord, t api.TargetDescription, owner, incarnation string) error {
	t, e := normalizeTarget(g, t)
	if e != nil {
		return e
	}
	if s.networks == nil {
		return unsupported("Target registration requires the EC2 network authority")
	}
	endpoint, e := s.networks.ResolveTarget(ctx, g.Scope, value(g.Data.VpcId), value(g.Data.TargetType), value(t.Id))
	if e != nil {
		return targetNetworkError(e)
	}
	if owner != "" && !targetEndpointMatches(g.Scope, value(g.Data.TargetType), value(t.Id), owner, incarnation, endpoint) {
		return failure("InvalidTarget", "Target no longer belongs to the expected resource incarnation")
	}
	if value(g.Data.TargetType) == "ip" {
		if (endpoint.AvailabilityZone == "" || endpoint.AvailabilityZone == "all") && value(t.AvailabilityZone) == "" {
			return invalid("AvailabilityZone is required for targets outside the VPC")
		}
		if endpoint.AvailabilityZone != "" && endpoint.AvailabilityZone != "all" {
			if value(t.AvailabilityZone) != "" && value(t.AvailabilityZone) != "all" && value(t.AvailabilityZone) != endpoint.AvailabilityZone {
				return invalid("Target AvailabilityZone does not match its subnet")
			}
			if t.AvailabilityZone == nil {
				text(&t.AvailabilityZone, endpoint.AvailabilityZone)
			}
		}
		if (endpoint.AvailabilityZone == "" || endpoint.AvailabilityZone == "all") && value(t.AvailabilityZone) != "all" {
			return invalid("AvailabilityZone must be all for a target outside the VPC")
		}
	}
	if owner == "" {
		incarnation = endpoint.Incarnation
	}
	old, e := tx.Target(g.Scope, value(g.Data.TargetGroupArn), value(t.Id), int32(intValue(t.Port)))
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	if e == nil {
		if old.OwnerARN != owner || old.Incarnation != incarnation {
			return failure("ResourceInUse", "Target is registered to a different owner or incarnation")
		}
		if owner != "" || old.State != "draining" {
			return nil
		}
		old.State = "initial"
		old.Reason = "Elb.RegistrationInProgress"
		old.Description = "Target registration is in progress"
		old.DrainUntil = time.Time{}
		old.NextCheck = s.clock.Now()
		old.Version, e = tx.NextID()
		if e != nil {
			return e
		}
		old.Successes = 0
		old.Failures = 0
		return tx.PutTarget(old)
	}
	version, e := tx.NextID()
	if e != nil {
		return e
	}
	r := TargetRecord{Scope: g.Scope, TargetGroupARN: value(g.Data.TargetGroupArn), Data: t, OwnerARN: owner, Incarnation: incarnation, State: "initial", Reason: "Elb.RegistrationInProgress", Description: "Target registration is in progress", NextCheck: s.clock.Now(), Version: version}
	if len(g.Data.LoadBalancerArns) == 0 {
		r.State = "unused"
		r.Reason = "Target.NotInUse"
		r.Description = "Target group is not configured to receive traffic from the load balancer"
	}
	return tx.PutTarget(r)
}
func (s *Service) registerTargets(ctx context.Context, tx Transaction, in *api.RegisterTargetsInput) (*api.RegisterTargetsOutput, error) {
	g, e := targetGroup(tx, scopeFor(ctx), value(in.TargetGroupArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "RegisterTargets", value(in.TargetGroupArn), g.Tags, nil); e != nil {
		return nil, e
	}
	if len(in.Targets) == 0 {
		return nil, invalid("Targets is required")
	}
	for _, t := range in.Targets {
		if e = s.registerTarget(ctx, tx, g, t, "", ""); e != nil {
			return nil, e
		}
	}
	return &api.RegisterTargetsOutput{}, nil
}
func (s *Service) deregisterTarget(tx Transaction, g TargetGroupRecord, t api.TargetDescription, owner, incarnation string, owned bool) error {
	t, e := normalizeTarget(g, t)
	if e != nil {
		return e
	}
	old, e := tx.Target(g.Scope, value(g.Data.TargetGroupArn), value(t.Id), int32(intValue(t.Port)))
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if owned && (old.OwnerARN != owner || old.Incarnation != incarnation) {
		return nil
	}
	if !owned && old.OwnerARN != "" {
		return failure("ResourceInUse", "Target is managed by another service")
	}
	if old.State == "draining" {
		return nil
	}
	if len(g.Data.LoadBalancerArns) == 0 {
		return tx.DeleteTarget(g.Scope, old.TargetGroupARN, value(t.Id), int32(intValue(t.Port)))
	}
	old.State = "draining"
	old.Reason = "Target.DeregistrationInProgress"
	old.Description = "Target deregistration is in progress"
	old.DrainUntil = s.clock.Now().Add(g.DeregistrationDelay)
	old.NextCheck = old.DrainUntil
	old.Version, e = tx.NextID()
	if e != nil {
		return e
	}
	return tx.PutTarget(old)
}
func (s *Service) deregisterTargets(ctx context.Context, tx Transaction, in *api.DeregisterTargetsInput) (*api.DeregisterTargetsOutput, error) {
	g, e := targetGroup(tx, scopeFor(ctx), value(in.TargetGroupArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "DeregisterTargets", value(in.TargetGroupArn), g.Tags, nil); e != nil {
		return nil, e
	}
	if len(in.Targets) == 0 {
		return nil, invalid("Targets is required")
	}
	for _, t := range in.Targets {
		if e = s.deregisterTarget(tx, g, t, "", "", false); e != nil {
			return nil, e
		}
	}
	return &api.DeregisterTargetsOutput{}, nil
}
func healthDescription(g TargetGroupRecord, t TargetRecord) api.TargetHealthDescription {
	h := &api.TargetHealth{}
	text(&h.State, t.State)
	if t.Reason != "" {
		text(&h.Reason, t.Reason)
	}
	if t.Description != "" {
		text(&h.Description, t.Description)
	}
	d := api.TargetHealthDescription{Target: &t.Data, TargetHealth: h}
	port := value(g.Data.HealthCheckPort)
	if port == "traffic-port" {
		port = strconv.FormatInt(intValue(t.Data.Port), 10)
	}
	text(&d.HealthCheckPort, port)
	return d
}
func (s *Service) describeTargetHealth(ctx context.Context, tx Transaction, in *api.DescribeTargetHealthInput) (*api.DescribeTargetHealthOutput, error) {
	g, e := targetGroup(tx, scopeFor(ctx), value(in.TargetGroupArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "DescribeTargetHealth", value(in.TargetGroupArn), g.Tags, nil); e != nil {
		return nil, e
	}
	if len(in.Include) > 0 {
		return nil, unsupported("Target anomaly detection is not supported")
	}
	out := &api.DescribeTargetHealthOutput{TargetHealthDescriptions: api.TargetHealthDescriptions{}}
	if len(in.Targets) > 0 {
		for _, t := range in.Targets {
			t, e = normalizeTarget(g, t)
			if e != nil {
				return nil, e
			}
			r, e := tx.Target(g.Scope, value(g.Data.TargetGroupArn), value(t.Id), int32(intValue(t.Port)))
			if errors.Is(e, ErrNotFound) {
				r = TargetRecord{Data: t, State: "unused", Reason: "Target.NotRegistered", Description: "Target is not registered to the target group"}
			} else if e != nil {
				return nil, e
			}
			out.TargetHealthDescriptions = append(out.TargetHealthDescriptions, healthDescription(g, r))
		}
		return out, nil
	}
	rows, e := tx.Targets(g.Scope, value(g.Data.TargetGroupArn))
	if e != nil {
		return nil, e
	}
	for _, t := range rows {
		out.TargetHealthDescriptions = append(out.TargetHealthDescriptions, healthDescription(g, t))
	}
	return out, nil
}
func ownedScope(ctx context.Context, sc Scope, owner, incarnation string) error {
	if sc != scopeFor(ctx) || sc == (Scope{}) {
		return failure("AccessDenied", "Target consumer scope does not match the caller")
	}
	if owner == "" {
		return nil
	}
	prefix := "arn:" + sc.Partition + ":ecs:" + sc.Region + ":" + sc.AccountID + ":task/"
	if strings.HasPrefix(owner, prefix) && incarnation != "" {
		return nil
	}
	if autoScalingTargetOwner(sc, owner) && strings.HasPrefix(incarnation, "i-") && !strings.ContainsAny(incarnation, "/:") {
		return nil
	}
	return invalid("A scoped ECS task or Auto Scaling group owner and resource incarnation are required")
}

func autoScalingTargetOwner(sc Scope, owner string) bool {
	prefix := "arn:" + sc.Partition + ":autoscaling:" + sc.Region + ":" + sc.AccountID + ":autoScalingGroup:"
	resource, ok := strings.CutPrefix(owner, prefix)
	if !ok {
		return false
	}
	id, name, ok := strings.Cut(resource, ":autoScalingGroupName/")
	return ok && id != "" && name != "" && !strings.Contains(id, ":")
}

// ECS/public registrations retain their ENI fence. Auto Scaling registers an
// immutable EC2 instance ID, whose current primary ENI remains EC2's authority.
// Never compare the ASG consumer ARN with the EC2 network endpoint owner ARN.
func targetEndpointMatches(sc Scope, kind, id, owner, incarnation string, endpoint TargetEndpoint) bool {
	if autoScalingTargetOwner(sc, owner) {
		return kind == "instance" && incarnation == id && endpoint.InterfaceID != "" &&
			endpoint.OwnerARN == "arn:"+sc.Partition+":ec2:"+sc.Region+":"+sc.AccountID+":instance/"+id
	}
	return (incarnation == "" || endpoint.Incarnation == incarnation) && (owner == "" || endpoint.OwnerARN == owner)
}

// ValidateTargetGroup admits an ECS awsvpc binding under the supplied linked-role caller.
func (s *Service) ValidateTargetGroup(ctx context.Context, sc Scope, a, vpcID string) error {
	if e := ownedScope(ctx, sc, "", ""); e != nil {
		return e
	}
	return s.repository.View(ctx, func(tx Reader) error {
		g, e := targetGroup(tx, sc, a)
		if e != nil {
			return e
		}
		if e = s.authorize(tx.Context(), "DescribeTargetGroups", "*", nil, nil); e != nil {
			return e
		}
		if value(g.Data.TargetType) != "ip" || value(g.Data.VpcId) != vpcID {
			return invalid("ECS awsvpc requires an IP target group in the same VPC")
		}
		if len(g.Data.LoadBalancerArns) == 0 {
			return invalid("ECS target group must be associated with a load balancer")
		}
		return nil
	})
}

// ValidateInstanceTargetGroup admits an ASG binding through current linked-role
// authority and the same scoped target-group owner used by public ELB commands.
func (s *Service) ValidateInstanceTargetGroup(ctx context.Context, sc Scope, a, vpcID string) error {
	if e := ownedScope(ctx, sc, "", ""); e != nil {
		return e
	}
	return s.repository.View(ctx, func(tx Reader) error {
		g, e := targetGroup(tx, sc, a)
		if e != nil {
			return e
		}
		if e = s.authorize(tx.Context(), "DescribeTargetGroups", "*", nil, nil); e != nil {
			return e
		}
		if value(g.Data.TargetType) != "instance" || value(g.Data.VpcId) != vpcID {
			return invalid("Auto Scaling requires an instance target group in the same VPC")
		}
		if len(g.Data.LoadBalancerArns) == 0 {
			return invalid("Auto Scaling target group must be associated with a load balancer")
		}
		return nil
	})
}

// RegisterOwnedTarget fences the consumer/resource incarnation; a repeat preserves health and drain state.
func (s *Service) RegisterOwnedTarget(ctx context.Context, sc Scope, a string, t api.TargetDescription, owner, incarnation string) error {
	if owner == "" {
		return invalid("Target owner is required")
	}
	if e := ownedScope(ctx, sc, owner, incarnation); e != nil {
		return e
	}
	ctx, reserveErr := apievents.Reserve(ctx)
	if reserveErr != nil {
		return reserveErr
	}
	e := s.repository.Attempt(ctx, func(tx Transaction) error {
		g, e := targetGroup(tx, sc, a)
		if e != nil {
			return e
		}
		if e = s.authorize(tx.Context(), "RegisterTargets", a, g.Tags, nil); e != nil {
			return e
		}
		if e = s.registerTarget(tx.Context(), tx, g, t, owner, incarnation); e != nil {
			return e
		}
		in := &api.RegisterTargetsInput{TargetGroupArn: g.Data.TargetGroupArn, Targets: api.TargetDescriptions{t}}
		return s.recordCall(tx.Context(), "RegisterTargets", in, &api.RegisterTargetsOutput{}, nil)
	})
	if e == nil {
		s.wakeRuntime()
	}
	return e
}

// DeregisterOwnedTarget is cleanup-safe after target-group deletion and cannot retire a replacement owner.
func (s *Service) DeregisterOwnedTarget(ctx context.Context, sc Scope, a string, t api.TargetDescription, owner, incarnation string) error {
	if owner == "" {
		return invalid("Target owner is required")
	}
	if e := ownedScope(ctx, sc, owner, incarnation); e != nil {
		return e
	}
	ctx, reserveErr := apievents.Reserve(ctx)
	if reserveErr != nil {
		return reserveErr
	}
	e := s.repository.Attempt(ctx, func(tx Transaction) error {
		g, e := tx.TargetGroup(sc, a)
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		if e = s.authorize(tx.Context(), "DeregisterTargets", a, g.Tags, nil); e != nil {
			return e
		}
		if g.Data.TargetGroupArn == nil {
			return nil
		}
		if e = s.deregisterTarget(tx, g, t, owner, incarnation, true); e != nil {
			return e
		}
		in := &api.DeregisterTargetsInput{TargetGroupArn: g.Data.TargetGroupArn, Targets: api.TargetDescriptions{t}}
		return s.recordCall(tx.Context(), "DeregisterTargets", in, &api.DeregisterTargetsOutput{}, nil)
	})
	if e == nil {
		s.wakeRuntime()
	}
	return e
}

// OwnedTargetHealth reports absent for an old identity, never the replacement's health.
func (s *Service) OwnedTargetHealth(ctx context.Context, sc Scope, a string, t api.TargetDescription, owner, incarnation string) (TargetRecord, bool, error) {
	if owner == "" {
		return TargetRecord{}, false, invalid("Target owner is required")
	}
	if e := ownedScope(ctx, sc, owner, incarnation); e != nil {
		return TargetRecord{}, false, e
	}
	var out TargetRecord
	found := false
	e := s.repository.View(ctx, func(tx Reader) error {
		g, e := tx.TargetGroup(sc, a)
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		if e = s.authorize(tx.Context(), "DescribeTargetHealth", a, g.Tags, nil); e != nil {
			return e
		}
		if g.Data.TargetGroupArn == nil {
			return nil
		}
		t, e = normalizeTarget(g, t)
		if e != nil {
			return e
		}
		r, e := tx.Target(sc, a, value(t.Id), int32(intValue(t.Port)))
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if r.OwnerARN == owner && r.Incarnation == incarnation {
			out = r
			found = true
		}
		return nil
	})
	return out, found, e
}
func targetNetworkError(e error) error {
	w := wireError(e)
	switch w.Code {
	case "InvalidParameterValue", "InvalidParameter", "InvalidIPAddress.InUse":
		return invalid(w.Message)
	case "InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed", "IncorrectInstanceState":
		return failure("InvalidTarget", w.Message)
	default:
		return e
	}
}
