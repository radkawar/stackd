package elbv2

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"slices"
	"strconv"
	"time"

	api "stackd/internal/awsapi/elbv2"
)

func (r *runtimeController) serve(w http.ResponseWriter, request *http.Request, scope Scope, listenerARN string, node *runtimeNode) {
	ctx := runtimeContext(request.Context(), scope)
	client := idleRequestConnection(ctx)
	ambiguous := client != nil && client.ambiguousDesync()
	if ambiguous {
		request.Close = true
		w.Header().Set("Connection", "close")
	}
	if client != nil {
		request.TLS = client.requestTLS()
		// ALB accepts one final request after the client keepalive duration
		// elapses, then gracefully closes HTTP/1 after this response. This is
		// connection age, not idle time, and does not cut off a streaming body.
		if !client.accepted.IsZero() && time.Since(client.accepted) >= defaultClientKeepAlive {
			w.Header().Set("Connection", "close")
			request.Close = true
		}
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
	// This identifies ALB-generated responses only. Successful forwarding
	// removes it before the target's original response headers are copied.
	w.Header().Set("Server", "awselb/2.0")
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
		var targetConnection net.Conn
		defer func() {
			if targetConnection != nil {
				_ = targetConnection.Close()
			}
		}()
		inflightCtx = httptrace.WithClientTrace(inflightCtx, &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				connected = true
				if ambiguous {
					targetConnection = info.Conn
				}
			},
			TLSHandshakeStart: func() { negotiatingTLS = true },
		})
		proxy := &httputil.ReverseProxy{Transport: node.transport, FlushInterval: -1,
			Rewrite: func(p *httputil.ProxyRequest) {
				originalHost := p.In.Host
				p.SetURL(destination)
				p.Out.Host = originalHost
				// ReverseProxy clears incoming Close. Restore the actual
				// defensive both-leg closure after its request rewriting.
				p.Out.Close = ambiguous
				// Transport reads the request body before it writes trailers.
				// Keep the map populated by net/http at EOF, not Clone's
				// pre-body copy of nil trailer values.
				p.Out.Trailer = p.In.Trailer
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
				w.Header().Set("Server", "awselb/2.0")
				status = 502
				connectionError = !connected && !negotiatingTLS
				var timeout interface{ Timeout() bool }
				if errors.As(e, &timeout) && timeout.Timeout() {
					status = 504
				}
				if client := idleRequestConnection(req.Context()); client != nil && client.clientBodyTimeout() {
					status = 408
					w.Header().Set("Connection", "close")
				} else if client != nil && client.clientProtocolFailure() {
					status = 400
					w.Header().Set("Connection", "close")
				}
				http.Error(w, http.StatusText(status), status)
			},
		}
		w.Header().Del("Server")
		proxy.ServeHTTP(w, request.WithContext(inflightCtx))
	default:
		status = 500
		http.Error(w, "Internal Server Error", status)
	}
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
