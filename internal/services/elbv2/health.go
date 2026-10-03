package elbv2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (r *runtimeController) reconcileTarget(ctx context.Context, key string, due time.Time, version uint64) error {
	var target TargetRecord
	var group TargetGroupRecord
	found := false
	err := r.service.repository.View(ctx, func(tx Reader) error {
		all, e := tx.Targets(Scope{}, "")
		if e != nil {
			return e
		}
		for _, t := range all {
			if runtimeTargetKey(t) == key {
				target = t
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		group, e = tx.TargetGroup(target.Scope, target.TargetGroupARN)
		return e
	})
	if err != nil || !found || target.Version != version {
		return err
	}
	if target.State == "draining" {
		if !target.DrainUntil.Equal(due) {
			return nil
		}
		r.mu.Lock()
		for _, flight := range r.inflight[key] {
			if flight.version <= target.Version && flight.incarnation == target.Incarnation && flight.owner == target.OwnerARN {
				flight.cancel()
			}
		}
		r.mu.Unlock()
		return r.service.repository.Update(ctx, func(tx Transaction) error {
			current, e := tx.Target(target.Scope, target.TargetGroupARN, value(target.Data.Id), targetPort(target.Data))
			if errors.Is(e, ErrNotFound) {
				return nil
			}
			if e != nil {
				return e
			}
			if current.State != "draining" || current.Version != target.Version || !current.DrainUntil.Equal(due) || current.Incarnation != target.Incarnation || current.OwnerARN != target.OwnerARN {
				return nil
			}
			return tx.DeleteTarget(target.Scope, target.TargetGroupARN, value(target.Data.Id), targetPort(target.Data))
		})
	}
	if !target.NextCheck.Equal(due) {
		return nil
	}
	ctx = runtimeContext(ctx, target.Scope)
	node := r.groupNode(group)
	if node == nil {
		return r.commitHealth(ctx, target, "unused", "Target.NotInUse", "Target group is not configured to receive traffic from the load balancer", false, false)
	}
	endpoint, err := r.service.networks.ResolveTarget(ctx, target.Scope, value(group.Data.VpcId), value(group.Data.TargetType), value(target.Data.Id))
	if err != nil || !targetEndpointMatches(target.Scope, value(group.Data.TargetType), value(target.Data.Id), target.OwnerARN, target.Incarnation, endpoint) {
		return r.commitHealth(ctx, target, "unused", "Target.InvalidState", "Target is not in its registered network incarnation", false, false)
	}
	enabled, err := r.targetEnabled(ctx, group, target, endpoint)
	if err != nil {
		return err
	}
	if !enabled {
		return r.commitHealth(ctx, target, "unused", "Target.NotInUse", "Target is in an Availability Zone that is not enabled", false, false)
	}
	address, err := targetAddress(endpoint)
	if err != nil {
		return r.commitHealth(ctx, target, "unused", "Target.IpUnusable", err.Error(), false, false)
	}
	timeout := time.Duration(defaultInt(group.Data.HealthCheckTimeoutSeconds, 5)) * time.Second
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	port := int(targetPort(target.Data))
	if p := value(group.Data.HealthCheckPort); p != "" && p != "traffic-port" {
		port, _ = strconv.Atoi(p)
	}
	path := value(group.Data.HealthCheckPath)
	if path == "" {
		path = "/"
	}
	scheme := strings.ToLower(value(group.Data.HealthCheckProtocol))
	if scheme == "" {
		scheme = "http"
	}
	endpointURL := scheme + "://" + net.JoinHostPort(address.String(), strconv.Itoa(port)) + path
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, endpointURL, nil)
	if err != nil {
		return r.commitHealth(ctx, target, "unhealthy", "Target.FailedHealthChecks", "Health check path is invalid", false, true)
	}
	if scheme == "http" && port == 80 || scheme == "https" && port == 443 {
		request.Host = address.String()
	}
	request.Header.Set("User-Agent", "ELB-HealthChecker/2.0")
	response, err := node.health.RoundTrip(request)
	if err != nil {
		reason, description := "Target.FailedHealthChecks", "Health checks failed"
		var netErr net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
			reason, description = "Target.Timeout", "Request timed out"
		}
		return r.commitHealth(ctx, target, "unhealthy", reason, description, false, true)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
	matcher := "200"
	if group.Data.Matcher != nil && group.Data.Matcher.HttpCode != nil {
		matcher = value(group.Data.Matcher.HttpCode)
	}
	if matchesStatus(matcher, response.StatusCode) {
		return r.commitHealth(ctx, target, "healthy", "", "", true, true)
	}
	return r.commitHealth(ctx, target, "unhealthy", "Target.ResponseCodeMismatch", fmt.Sprintf("Health checks failed with these codes: [%d]", response.StatusCode), false, true)
}
func defaultInt[T ~int32](v *T, fallback int) int {
	if v == nil {
		return fallback
	}
	return int(*v)
}
func matchesStatus(matcher string, status int) bool {
	for _, part := range strings.Split(matcher, ",") {
		start, end, rangeFound := strings.Cut(part, "-")
		a, err := strconv.Atoi(start)
		if err != nil {
			continue
		}
		if !rangeFound && a == status {
			return true
		}
		if rangeFound {
			b, e := strconv.Atoi(end)
			if e == nil && a <= status && status <= b {
				return true
			}
		}
	}
	return false
}

// TODO: Comeback model native distributed per-zone health consensus and routing;
// this kernel probes through one actual enabled node of an associated balancer.
func (r *runtimeController) groupNode(group TargetGroupRecord) *runtimeNode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, arn := range group.Data.LoadBalancerArns {
		nodes := r.nodes[string(arn)]
		var selected string
		for subnet := range nodes {
			if selected == "" || subnet < selected {
				selected = subnet
			}
		}
		if selected != "" {
			return nodes[selected]
		}
	}
	return nil
}
func (r *runtimeController) targetEnabled(ctx context.Context, group TargetGroupRecord, target TargetRecord, endpoint TargetEndpoint) (bool, error) {
	zone := value(target.Data.AvailabilityZone)
	if zone == "" {
		zone = endpoint.AvailabilityZone
	}
	enabled := false
	err := r.service.repository.View(ctx, func(tx Reader) error {
		for _, arn := range group.Data.LoadBalancerArns {
			lb, e := tx.LoadBalancer(group.Scope, string(arn))
			if errors.Is(e, ErrNotFound) {
				continue
			}
			if e != nil {
				return e
			}
			if lb.Deleting {
				continue
			}
			for _, availability := range lb.Data.AvailabilityZones {
				if zone == "all" || zone == value(availability.ZoneName) {
					enabled = true
					return nil
				}
			}
		}
		return nil
	})
	return enabled, err
}
func (r *runtimeController) commitHealth(ctx context.Context, observed TargetRecord, state, reason, description string, success, probed bool) error {
	return r.service.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Target(observed.Scope, observed.TargetGroupARN, value(observed.Data.Id), targetPort(observed.Data))
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if current.State == "draining" || current.Version != observed.Version || current.Incarnation != observed.Incarnation || current.OwnerARN != observed.OwnerARN || !current.NextCheck.Equal(observed.NextCheck) {
			return nil
		}
		group, e := tx.TargetGroup(current.Scope, current.TargetGroupARN)
		if e != nil {
			return e
		}
		interval := time.Duration(defaultInt(group.Data.HealthCheckIntervalSeconds, 30)) * time.Second
		current.NextCheck = r.service.clock.Now().Add(interval)
		if !probed {
			current.State, current.Reason, current.Description = state, reason, description
			current.Successes, current.Failures = 0, 0
			return tx.PutTarget(current)
		}
		if success {
			current.Successes++
			current.Failures = 0
			threshold := defaultInt(group.Data.HealthyThresholdCount, 5)
			// Native initial registration needs one success, not the recovery threshold.
			if current.State == "initial" || current.State == "unused" || current.State == "healthy" || current.Successes >= threshold {
				current.State, current.Reason, current.Description = "healthy", "", ""
			}
		} else {
			current.Failures++
			current.Successes = 0
			if current.Failures >= defaultInt(group.Data.UnhealthyThresholdCount, 2) {
				current.State, current.Reason, current.Description = "unhealthy", reason, description
			}
			if current.State == "unused" {
				current.State, current.Reason, current.Description = "initial", "Elb.InitialHealthChecking", "Initial health checks in progress"
			}
		}
		return tx.PutTarget(current)
	})
}
func targetURL(group TargetGroupRecord, target TargetRecord, endpoint TargetEndpoint) (*url.URL, error) {
	address, err := targetAddress(endpoint)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(value(group.Data.Protocol))
	if scheme != "http" && scheme != "https" {
		return nil, errors.New("unsupported target protocol")
	}
	return &url.URL{Scheme: scheme, Host: net.JoinHostPort(address.String(), strconv.Itoa(int(targetPort(target.Data))))}, nil
}
