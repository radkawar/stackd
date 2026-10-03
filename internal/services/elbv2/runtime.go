package elbv2

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	native "stackd/compute/elbv2"
	metricsapi "stackd/internal/awsapi/cloudwatch"
	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// MetricPublisher delegates observations to the CloudWatch source publication
// boundary. ELB owns no competing metric store or customer PutMetricData identity.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}
type runtimeController struct {
	service        *Service
	native         NativeRuntime
	certificates   CertificateSource
	metrics        MetricPublisher
	jobs           *scheduler.Driver
	mu             sync.RWMutex
	nodes          map[string]map[string]*runtimeNode
	sequence       atomic.Uint64
	actionSequence atomic.Uint64
	targetSequence atomic.Uint64
	inflight       map[string]map[uint64]forwardFlight
	work           map[string]runtimeWork
	workers        sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	closed         bool
}
type runtimeWork struct {
	version uint64
	cancel  context.CancelFunc
}
type forwardFlight struct {
	cancel             context.CancelFunc
	version            uint64
	incarnation, owner string
}
type runtimeNode struct {
	attachment NetworkAttachment
	groups     []string
	node       native.Node
	listeners  map[string]*runtimeListener
	transport  *http.Transport
	health     *http.Transport
	idle       *connectionIdlePolicy
}
type runtimeListener struct {
	data          api.Listener
	certificateID string
	server        *http.Server
}

func newRuntimeController(s *Service, c Config) *runtimeController {
	ctx, cancel := context.WithCancel(context.Background())
	r := &runtimeController{service: s, native: c.Runtime, certificates: c.Certificates, metrics: c.Metrics, nodes: map[string]map[string]*runtimeNode{}, inflight: map[string]map[uint64]forwardFlight{}, work: map[string]runtimeWork{}, ctx: ctx, cancel: cancel}
	r.jobs = scheduler.New(s.clock, r, metricJobs{s})
	return r
}
func (s *Service) wakeRuntime()                 { s.runtime.jobs.Wake() }
func (s *Service) JobDriver() *scheduler.Driver { return s.runtime.jobs }

// Close detaches controllers and listeners without removing durable native nodes.
// Explicit DeleteLoadBalancer owns external teardown and releases its ENIs.
func (s *Service) Close() error {
	if s.dnsRelease != nil {
		s.dnsRelease()
	}
	s.runtime.jobs.Close()
	s.runtime.mu.Lock()
	s.runtime.closed = true
	s.runtime.cancel()
	s.runtime.mu.Unlock()
	s.runtime.workers.Wait()
	s.runtime.mu.Lock()
	nodesByBalancer := s.runtime.nodes
	s.runtime.nodes = map[string]map[string]*runtimeNode{}
	s.runtime.mu.Unlock()
	var result error
	for _, nodes := range nodesByBalancer {
		for _, n := range nodes {
			result = errors.Join(result, n.close())
		}
	}
	return result
}
func (n *runtimeNode) close() error {
	for _, l := range n.listeners {
		_ = l.server.Close()
	}
	n.transport.CloseIdleConnections()
	n.health.CloseIdleConnections()
	n.idle.close()
	return n.node.Close()
}
func runtimeContext(ctx context.Context, scope Scope) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
}
func runtimeTargetKey(t TargetRecord) string {
	return t.TargetGroupARN + "\x00" + value(t.Data.Id) + "\x00" + strconv.Itoa(int(targetPort(t.Data)))
}
func targetPort(t api.TargetDescription) int32 {
	if t.Port == nil {
		return 0
	}
	return int32(*t.Port)
}
func (r *runtimeController) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var selected scheduler.Job
	found := false
	choose := func(key string, due time.Time, version uint64) {
		r.mu.RLock()
		work, busy := r.work[key]
		r.mu.RUnlock()
		if busy {
			// Cancel obsolete probes promptly, but let native LB reconciliation
			// reach its fence. Cancelling a policy install would tear down live
			// connections for an otherwise non-disruptive attribute update.
			if work.version != version && strings.HasPrefix(key, "target:") {
				work.cancel()
			}
			return
		}
		if !found || due.Before(selected.Due) || due.Equal(selected.Due) && key < selected.Key {
			selected = scheduler.Job{Key: key, Due: due, Version: version}
			found = true
		}
	}
	err := r.service.repository.View(ctx, func(tx Reader) error {
		lbs, err := tx.LoadBalancers(Scope{})
		if err != nil {
			return err
		}
		for _, lb := range lbs {
			choose("lb:"+value(lb.Data.LoadBalancerArn), lb.NextReconcile, lb.Version)
		}
		targets, err := tx.Targets(Scope{}, "")
		if err != nil {
			return err
		}
		for _, t := range targets {
			due := t.NextCheck
			if t.State == "draining" {
				due = t.DrainUntil
			}
			choose("target:"+runtimeTargetKey(t), due, t.Version)
		}
		return nil
	})
	return selected, found, err
}
func (r *runtimeController) Run(_ context.Context, job scheduler.Job) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	if _, busy := r.work[job.Key]; busy {
		r.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(r.ctx)
	r.work[job.Key] = runtimeWork{version: job.Version, cancel: cancel}
	r.workers.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.workers.Done()
		defer func() {
			cancel()
			r.mu.Lock()
			delete(r.work, job.Key)
			r.mu.Unlock()
			r.jobs.Wake()
		}()
		var err error
		if strings.HasPrefix(job.Key, "lb:") {
			err = r.reconcileLoadBalancer(ctx, strings.TrimPrefix(job.Key, "lb:"), job.Due, job.Version)
		} else {
			err = r.reconcileTarget(ctx, strings.TrimPrefix(job.Key, "target:"), job.Due, job.Version)
		}
		if err != nil {
			// The retained due intent remains retryable. Keep this resource out of
			// the shared scheduler briefly without holding its serial job gate.
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
			case <-timer.C:
			}
		}
	}()
	return nil
}
func (r *runtimeController) reconcileLoadBalancer(ctx context.Context, arn string, due time.Time, version uint64) error {
	var lb LoadBalancerRecord
	found := false
	err := r.service.repository.View(ctx, func(tx Reader) error {
		all, e := tx.LoadBalancers(Scope{})
		if e != nil {
			return e
		}
		for _, v := range all {
			if value(v.Data.LoadBalancerArn) == arn {
				lb = v
				found = true
				break
			}
		}
		return nil
	})
	if err != nil || !found || lb.Version != version || !lb.NextReconcile.Equal(due) {
		return err
	}
	ctx = runtimeContext(ctx, lb.Scope)
	if lb.Deleting {
		return r.removeLoadBalancer(ctx, lb)
	}
	if r.native == nil || r.service.networks == nil || !r.service.dnsAttached {
		return r.finishReconcile(ctx, lb, errors.New("native load-balancer network runtime or DNS endpoint is unavailable"))
	}
	groups := make([]string, len(lb.Data.SecurityGroups))
	for i, g := range lb.Data.SecurityGroups {
		groups[i] = string(g)
	}
	wanted := map[string]bool{}
	for _, zone := range lb.Data.AvailabilityZones {
		subnet := value(zone.SubnetId)
		wanted[subnet] = true
		var attachment NetworkAttachment
		id := lb.AttachmentIDs[subnet]
		r.mu.RLock()
		current := r.nodes[arn][subnet]
		r.mu.RUnlock()
		if id == "" {
			accepted := false
			err = r.service.repository.Update(ctx, func(tx Transaction) error {
				current, e := tx.LoadBalancer(lb.Scope, arn)
				if errors.Is(e, ErrNotFound) {
					return nil
				}
				if e != nil {
					return e
				}
				if current.Deleting || current.Version != lb.Version {
					return nil
				}
				present := false
				for _, z := range current.Data.AvailabilityZones {
					if value(z.SubnetId) == subnet {
						present = true
					}
				}
				if !present {
					return nil
				}
				// ENI allocation is EC2-owned transactional intent, not a native
				// effect. Join its record, idempotency token and events to this
				// exact ALB attachment so neither can commit without the other.
				attachment, e = r.service.networks.Allocate(tx.Context(), lb.Scope, arn, subnet, current.AttachmentGenerations[subnet], value(current.Data.Scheme) == "internet-facing", groups)
				if e != nil {
					return e
				}
				if current.AttachmentIDs == nil {
					current.AttachmentIDs = map[string]string{}
				}
				if old := current.AttachmentIDs[subnet]; old != "" && old != attachment.ID {
					return errors.New("load-balancer attachment changed concurrently")
				}
				current.AttachmentIDs[subnet] = attachment.ID
				accepted = true
				return tx.PutLoadBalancer(current)
			})
			if err != nil {
				return r.finishReconcile(ctx, lb, err)
			}
			if !accepted {
				return nil
			}
			if lb.AttachmentIDs == nil {
				lb.AttachmentIDs = map[string]string{}
			}
			lb.AttachmentIDs[subnet] = attachment.ID
		} else {
			if current == nil || !slices.Equal(current.groups, groups) {
				attachment, err = r.service.networks.SetSecurityGroups(ctx, lb.Scope, arn, id, groups)
			} else {
				attachment, err = r.service.networks.Observe(ctx, lb.Scope, arn, id)
			}
			if err != nil {
				return r.finishReconcile(ctx, lb, err)
			}
		}
		if value(lb.Data.Scheme) == "internet-facing" && attachment.PublicAddress == "" {
			return r.finishReconcile(ctx, lb, errors.New("internet-facing node has no current EC2 public IPv4 binding"))
		}
		if current == nil {
			node, e := r.native.Prepare(ctx, native.Specification{LoadBalancerARN: arn, AttachmentID: attachment.ID, Network: attachment.Network})
			if e != nil {
				return r.finishReconcile(ctx, lb, e)
			}
			current = &runtimeNode{attachment: attachment, groups: slices.Clone(groups), node: node, listeners: map[string]*runtimeListener{}, idle: newConnectionIdlePolicy(lb.IdleTimeout)}
			// No pooled backend connection can outlive an EC2 target incarnation check.
			idle := current.idle
			current.transport = &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := node.DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return idle.wrap(conn), nil
			}, DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			// HealthCheckTimeoutSeconds, not the client idle attribute, owns
			// probe lifetime. Keep probes off the forwarding inactivity policy.
			current.health = &http.Transport{DialContext: node.DialContext, DisableKeepAlives: true, TLSClientConfig: current.transport.TLSClientConfig}
			r.mu.Lock()
			if r.nodes[arn] == nil {
				r.nodes[arn] = map[string]*runtimeNode{}
			}
			r.nodes[arn][subnet] = current
			r.mu.Unlock()
		}
		current.idle.setTimeout(lb.IdleTimeout)
		if current.attachment.ID != attachment.ID {
			return r.finishReconcile(ctx, lb, errors.New("native node attachment identity changed"))
		}
		if err = current.node.SetNetworkPolicy(ctx, attachment.Network.Policy); err != nil {
			// Unenforceable current policy must not leave an unfiltered serving node.
			_ = current.close()
			r.mu.Lock()
			delete(r.nodes[arn], subnet)
			r.mu.Unlock()
			return r.finishReconcile(ctx, lb, err)
		}
		r.mu.Lock()
		current.attachment = attachment
		if !slices.Equal(current.groups, groups) {
			current.groups = slices.Clone(groups)
		}
		r.mu.Unlock()
		if err = r.reconcileListeners(ctx, lb, current); err != nil {
			return r.finishReconcile(ctx, lb, err)
		}
	}
	for subnet, id := range lb.AttachmentIDs {
		if !wanted[subnet] {
			if err = r.removeNode(ctx, lb, subnet, id); err != nil {
				return r.finishReconcile(ctx, lb, err)
			}
			delete(lb.AttachmentIDs, subnet)
			delete(lb.AttachmentGenerations, subnet)
		}
	}
	return r.finishReconcile(ctx, lb, nil)
}
func (r *runtimeController) finishReconcile(ctx context.Context, observed LoadBalancerRecord, effectErr error) error {
	if effectErr != nil {
		arn := value(observed.Data.LoadBalancerArn)
		r.mu.Lock()
		nodes := r.nodes[arn]
		delete(r.nodes, arn)
		r.mu.Unlock()
		for _, node := range nodes {
			_ = node.close()
		}
	}
	return r.service.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.LoadBalancer(observed.Scope, value(observed.Data.LoadBalancerArn))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		// A concurrent command owns its due hint and new configuration.
		if current.Deleting || current.Version != observed.Version || !current.NextReconcile.Equal(observed.NextReconcile) {
			return nil
		}
		current.NextReconcile = r.service.clock.Now().Add(time.Second)
		state, reason := "active", ""
		if effectErr != nil {
			state = "active_impaired"
			reason = effectErr.Error()
		}
		current.Data.State = &api.LoadBalancerState{Code: new(api.LoadBalancerStateEnum(state))}
		if reason != "" {
			current.Data.State.Reason = new(api.StateReason(reason))
		}
		if effectErr == nil {
			current.AttachmentIDs = observed.AttachmentIDs
			current.AttachmentGenerations = observed.AttachmentGenerations
		}
		return tx.PutLoadBalancer(current)
	})
}
func (r *runtimeController) removeNode(ctx context.Context, lb LoadBalancerRecord, subnet, id string) error {
	arn := value(lb.Data.LoadBalancerArn)
	r.mu.Lock()
	node := r.nodes[arn][subnet]
	if node != nil {
		delete(r.nodes[arn], subnet)
	}
	r.mu.Unlock()
	if node != nil {
		_ = node.close()
	}
	attachment, err := r.service.networks.Observe(ctx, lb.Scope, arn, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = r.native.Remove(ctx, native.Specification{LoadBalancerARN: arn, AttachmentID: id, Network: attachment.Network}); err != nil {
		return err
	}
	return r.service.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.LoadBalancer(lb.Scope, arn)
		if err != nil {
			return err
		}
		if current.AttachmentIDs[subnet] != id {
			return nil
		}
		if !current.Deleting {
			for _, zone := range current.Data.AvailabilityZones {
				if value(zone.SubnetId) == subnet {
					// SetSubnets re-added this subnet while native teardown was
					// in flight. Keep its EC2 identity for the next Prepare.
					return nil
				}
			}
		}
		if err := r.service.networks.Release(tx.Context(), lb.Scope, arn, id); err != nil {
			return err
		}
		delete(current.AttachmentIDs, subnet)
		delete(current.AttachmentGenerations, subnet)
		return tx.PutLoadBalancer(current)
	})
}
func (r *runtimeController) removeLoadBalancer(ctx context.Context, lb LoadBalancerRecord) error {
	if r.native == nil || r.service.networks == nil {
		return errors.New("load-balancer cleanup requires its configured native owners")
	}
	for subnet, id := range lb.AttachmentIDs {
		if err := r.removeNode(ctx, lb, subnet, id); err != nil {
			return err
		}
	}
	r.mu.Lock()
	delete(r.nodes, value(lb.Data.LoadBalancerArn))
	r.mu.Unlock()
	return r.service.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteLoadBalancer(lb.Scope, value(lb.Data.LoadBalancerArn)) })
}
func (r *runtimeController) reconcileListeners(ctx context.Context, lb LoadBalancerRecord, node *runtimeNode) error {
	var listeners []ListenerRecord
	err := r.service.repository.View(ctx, func(tx Reader) error { var e error; listeners, e = tx.Listeners(lb.Scope); return e })
	if err != nil {
		return err
	}
	desired := map[string]bool{}
	for _, record := range listeners {
		data := record.Data
		if value(data.LoadBalancerArn) != value(lb.Data.LoadBalancerArn) {
			continue
		}
		arn := value(data.ListenerArn)
		desired[arn] = true
		previous := node.listeners[arn]
		if previous != nil && previous.certificateID == record.CertificateID && value(previous.data.Protocol) == value(data.Protocol) && reflect.DeepEqual(previous.data.Port, data.Port) && reflect.DeepEqual(previous.data.Certificates, data.Certificates) && value(previous.data.SslPolicy) == value(data.SslPolicy) {
			continue
		}
		if previous != nil {
			_ = previous.server.Close()
			delete(node.listeners, arn)
		}
		if data.Port == nil {
			return errors.New("retained listener has no port")
		}
		listener, err := node.node.Listen(ctx, int(*data.Port))
		if err != nil {
			return err
		}
		var tlsConfig *tls.Config
		if value(data.Protocol) == "HTTPS" {
			if r.certificates == nil || len(data.Certificates) != 1 {
				_ = listener.Close()
				return errors.New("HTTPS requires one owned default certificate")
			}
			cert, err := r.certificates.Certificate(ctx, lb.Scope, value(data.Certificates[0].CertificateArn), record.CertificateID)
			if err != nil {
				_ = listener.Close()
				return err
			}
			tlsConfig = listenerTLSConfig(cert)
			certificateARN := value(data.Certificates[0].CertificateArn)
			if strings.HasPrefix(certificateARN, "arn:"+lb.Partition+":acm:") {
				// An ACM identity survives renewal. Resolve its current material for
				// each handshake instead of pinning the listener to the first leaf.
				tlsConfig.Certificates = nil
				tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					current, err := r.certificates.Certificate(runtimeContext(hello.Context(), lb.Scope), lb.Scope, certificateARN, record.CertificateID)
					if err != nil {
						return nil, err
					}
					return &current, nil
				}
			}
		}
		listener = idleListener{Listener: listener, policy: node.idle, tlsConfig: tlsConfig}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) { r.serve(w, request, lb.Scope, arn, node) }), ConnContext: idleHTTPContext, ConnState: idleHTTPState}
		node.listeners[arn] = &runtimeListener{data: api.CloneListener(data), certificateID: record.CertificateID, server: server}
		go func() { _ = server.Serve(listener) }()
	}
	for arn, l := range node.listeners {
		if !desired[arn] {
			_ = l.server.Close()
			delete(node.listeners, arn)
		}
	}
	return nil
}
