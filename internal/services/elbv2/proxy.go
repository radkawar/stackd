package elbv2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"slices"
	"sort"
	"strconv"
	"time"

	api "stackd/internal/awsapi/elbv2"
)

func (r *runtimeController) serve(w http.ResponseWriter, request *http.Request, scope Scope, listenerARN string, node *runtimeNode) {
	ctx := runtimeContext(request.Context(), scope)
	client := idleRequestConnection(ctx)
	if client != nil {
		request.TLS = client.requestTLS()
	}
	if client != nil && request.Body != nil && request.Body != http.NoBody {
		client.policy.mu.Lock()
		client.reading, client.readAt = true, time.Now()
		_ = client.Conn.SetReadDeadline(client.readAt.Add(client.policy.timeout))
		client.policy.mu.Unlock()
		request.Body = &idleRequestBody{ReadCloser: request.Body, connection: client}
	}
	var listener ListenerRecord
	var lb LoadBalancerRecord
	var rules api.Rules
	err := r.service.repository.View(ctx, func(tx Reader) error {
		var e error
		listener, e = tx.Listener(scope, listenerARN)
		if e != nil {
			return e
		}
		lb, e = tx.LoadBalancer(scope, value(listener.Data.LoadBalancerArn))
		if e != nil {
			return e
		}
		if lb.Deleting {
			return ErrNotFound
		}
		records, e := tx.Rules(scope)
		if e != nil {
			return e
		}
		for _, record := range records {
			if record.ListenerARN == listenerARN {
				rules = append(rules, record.Data)
			}
		}
		return nil
	})
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	var started time.Time
	status := http.StatusOK
	targetStatus := false
	connectionError := false
	groupARN, actionType, zone, targetZone := "", "", "", ""
	for _, availability := range lb.Data.AvailabilityZones {
		if value(availability.SubnetId) == node.attachment.SubnetID {
			zone = value(availability.ZoneName)
			break
		}
	}
	var responseTime time.Duration
	defer func() {
		r.observeResponse(ctx, lb, groupARN, zone, targetZone, actionType, status, targetStatus, connectionError, responseTime)
	}()
	actions := listener.Data.DefaultActions
	if rule, ok := MatchRule(rules, request); ok {
		actions = rule.Actions
	}
	action, err := SelectAction(actions, r.actionSequence.Add(1))
	if err != nil {
		status = 503
		http.Error(w, "Service Unavailable", status)
		return
	}
	switch value(action.Type) {
	case "fixed-response":
		var contentType, body string
		status, contentType, body, err = FixedResponse(action)
		if err != nil {
			status = 500
			http.Error(w, "Internal Server Error", status)
			return
		}
		w.Header().Set("Content-Type", contentType)
		actionType = "fixed-response"
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	case "redirect":
		var location string
		location, status, err = RedirectURL(action, request)
		if err != nil {
			status = 500
			http.Error(w, "Internal Server Error", status)
			return
		}
		actionType = "redirect"
		http.Redirect(w, request, location, status)
	case "forward":
		target, group, endpoint, err := r.selectTarget(ctx, scope, value(action.TargetGroupArn))
		if err != nil {
			status = 503
			http.Error(w, "Service Unavailable", status)
			return
		}
		destination, err := targetURL(group, target, endpoint)
		if err != nil {
			status = 503
			http.Error(w, "Service Unavailable", status)
			return
		}
		inflightCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		targetZone = value(target.Data.AvailabilityZone)
		if targetZone == "" || targetZone == "all" {
			targetZone = endpoint.AvailabilityZone
		}
		if targetZone == "" || targetZone == "all" {
			targetZone = zone
		}
		release, err := r.admitForward(inflightCtx, lb, target, targetZone, cancel)
		if err != nil {
			status = 503
			http.Error(w, "Service Unavailable", status)
			return
		}
		defer release()
		groupARN = value(group.Data.TargetGroupArn)
		started = time.Now()
		connected, negotiatingTLS := false, false
		inflightCtx = httptrace.WithClientTrace(inflightCtx, &httptrace.ClientTrace{
			GotConn:           func(httptrace.GotConnInfo) { connected = true },
			TLSHandshakeStart: func() { negotiatingTLS = true },
		})
		proxy := &httputil.ReverseProxy{Transport: node.transport, FlushInterval: -1,
			Rewrite: func(p *httputil.ProxyRequest) {
				originalHost := p.In.Host
				p.SetURL(destination)
				p.Out.Host = originalHost
				p.Out.Header["X-Forwarded-For"] = slices.Clone(p.In.Header["X-Forwarded-For"])
				p.SetXForwarded()
				if port := listener.Data.Port; port != nil {
					p.Out.Header.Set("X-Forwarded-Port", strconv.Itoa(int(*port)))
				}
			},
			ModifyResponse: func(response *http.Response) error {
				status, targetStatus, responseTime = response.StatusCode, true, time.Since(started)
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, req *http.Request, e error) {
				status = 502
				connectionError = !connected && !negotiatingTLS
				var timeout interface{ Timeout() bool }
				if errors.As(e, &timeout) && timeout.Timeout() {
					status = 504
				}
				if client := idleRequestConnection(req.Context()); client != nil && client.clientBodyTimeout() {
					status = 408
					w.Header().Set("Connection", "close")
				}
				http.Error(w, http.StatusText(status), status)
			},
		}
		proxy.ServeHTTP(w, request.WithContext(inflightCtx))
	default:
		status = 500
		http.Error(w, "Internal Server Error", status)
	}
}
func (r *runtimeController) selectTarget(ctx context.Context, scope Scope, groupARN string) (TargetRecord, TargetGroupRecord, TargetEndpoint, error) {
	var group TargetGroupRecord
	var candidates []TargetRecord
	err := r.service.repository.View(ctx, func(tx Reader) error {
		var e error
		group, e = tx.TargetGroup(scope, groupARN)
		if e != nil {
			return e
		}
		candidates, e = tx.Targets(scope, groupARN)
		return e
	})
	if err != nil {
		return TargetRecord{}, group, TargetEndpoint{}, err
	}
	healthy := make([]TargetRecord, 0, len(candidates))
	unhealthy := make([]TargetRecord, 0, len(candidates))
	for _, target := range candidates {
		switch target.State {
		case "healthy":
			healthy = append(healthy, target)
		case "unhealthy":
			unhealthy = append(unhealthy, target)
		}
	}
	eligible := healthy
	if len(eligible) == 0 {
		eligible = unhealthy
	} // ALB fails open only for registered unhealthy targets, never draining/initial.
	sort.Slice(eligible, func(i, j int) bool { return runtimeTargetKey(eligible[i]) < runtimeTargetKey(eligible[j]) })
	if len(eligible) == 0 {
		return TargetRecord{}, group, TargetEndpoint{}, ErrNotFound
	}
	start := int(r.targetSequence.Add(1) % uint64(len(eligible)))
	for i := range eligible {
		target := eligible[(start+i)%len(eligible)]
		endpoint, e := r.service.networks.ResolveTarget(ctx, scope, value(group.Data.VpcId), value(group.Data.TargetType), value(target.Data.Id))
		if e != nil || !targetEndpointMatches(target.Scope, value(group.Data.TargetType), value(target.Data.Id), target.OwnerARN, target.Incarnation, endpoint) {
			continue
		}
		enabled, e := r.targetEnabled(ctx, group, target, endpoint)
		if e != nil || !enabled {
			continue
		}
		return target, group, endpoint, nil
	}
	return TargetRecord{}, group, TargetEndpoint{}, ErrNotFound
}
func (r *runtimeController) admitForward(ctx context.Context, lb LoadBalancerRecord, observed TargetRecord, zone string, cancel context.CancelFunc) (func(), error) {
	key := runtimeTargetKey(observed)
	id := r.sequence.Add(1)
	// Register before the final retained check: a concurrent due drain can cancel
	// this request but cannot miss it between a state read and the first socket.
	r.mu.Lock()
	if r.inflight[key] == nil {
		r.inflight[key] = map[uint64]forwardFlight{}
	}
	r.inflight[key][id] = forwardFlight{cancel: cancel, version: observed.Version, incarnation: observed.Incarnation, owner: observed.OwnerARN}
	r.mu.Unlock()
	release := func() {
		r.mu.Lock()
		delete(r.inflight[key], id)
		if len(r.inflight[key]) == 0 {
			delete(r.inflight, key)
		}
		r.mu.Unlock()
	}
	err := r.service.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Target(observed.Scope, observed.TargetGroupARN, value(observed.Data.Id), targetPort(observed.Data))
		if e != nil {
			return e
		}
		if current.State != "healthy" && current.State != "unhealthy" || current.Version != observed.Version || current.Incarnation != observed.Incarnation || current.OwnerARN != observed.OwnerARN {
			return ErrNotFound
		}
		return r.observeForward(tx, lb, current, zone)
	})
	if err != nil {
		release()
		return nil, err
	}
	if r.metrics != nil {
		r.jobs.Wake()
	}
	return release, nil
}
