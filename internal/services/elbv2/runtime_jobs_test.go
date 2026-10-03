package elbv2

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/scheduler"
	"sync"
	"testing"
	"time"
)

func TestBlockedHealthProbeDoesNotDelayOtherTargetDrain(t *testing.T) {
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	var once sync.Once
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "10.0.0.8" || r.UserAgent() != "ELB-HealthChecker/2.0" {
			http.NotFound(w, r)
			return
		}
		once.Do(func() { close(entered) })
		<-r.Context().Done()
		close(cancelled)
	}))
	defer backend.Close()
	ctx := context.Background()
	now := time.Now()
	scope := Scope{"aws", "000000000000", "us-east-1"}
	lbARN := "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/jobs/1"
	groupARN := "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/jobs/2"
	service := New(Config{Networks: controlNetwork{}})
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
	}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	// The fixture supplies EC2 identity; the probe itself blocks on a real HTTP
	// socket. Only the runtime scheduler and persistent health/drain transitions
	// are under test, rather than a stubbed response or forwarding count.
	service.runtime.nodes[lbARN] = map[string]*runtimeNode{"subnet-a": {health: transport}}
	defer func() {
		service.runtime.mu.Lock()
		service.runtime.nodes = map[string]map[string]*runtimeNode{}
		service.runtime.mu.Unlock()
		_ = service.Close()
	}()
	group := TargetGroupRecord{Scope: scope, Data: api.TargetGroup{TargetGroupArn: new(api.TargetGroupArn(groupARN)), VpcId: new(api.VpcId("vpc-0aeae393af73839cf")), TargetType: new(api.TargetTypeEnum("ip")), LoadBalancerArns: api.LoadBalancerArns{api.LoadBalancerArn(lbARN)}, HealthCheckTimeoutSeconds: new(api.HealthCheckTimeoutSeconds(120)), HealthCheckIntervalSeconds: new(api.HealthCheckIntervalSeconds(5))}}
	blocked := TargetRecord{Scope: scope, TargetGroupARN: groupARN, Data: api.TargetDescription{Id: new(api.TargetId("10.0.0.8")), Port: new(api.Port(80))}, State: "initial", Version: 1, NextCheck: now}
	draining := blocked
	draining.Data = api.CloneTargetDescription(blocked.Data)
	draining.Data.Id = new(api.TargetId("10.0.0.9"))
	draining.Data.Port = new(api.Port(8080))
	draining.State = "draining"
	draining.DrainUntil = now
	if err := service.repository.Update(ctx, func(tx Transaction) error {
		if e := tx.PutLoadBalancer(LoadBalancerRecord{Scope: scope, Data: api.LoadBalancer{LoadBalancerArn: new(api.LoadBalancerArn(lbARN)), AvailabilityZones: api.AvailabilityZones{{SubnetId: new(api.SubnetId("subnet-a")), ZoneName: new(api.ZoneName("us-east-1a"))}}}, NextReconcile: now.Add(time.Hour), Version: 1}); e != nil {
			return e
		}
		if e := tx.PutTargetGroup(group); e != nil {
			return e
		}
		if e := tx.PutTarget(blocked); e != nil {
			return e
		}
		return tx.PutTarget(draining)
	}); err != nil {
		t.Fatal(err)
	}
	returned := make(chan struct{})
	go func() {
		_ = service.runtime.Run(ctx, scheduler.Job{Key: "target:" + runtimeTargetKey(blocked), Due: now, Version: 1})
		close(returned)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("real health socket never opened")
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("health socket held shared scheduler gate")
	}
	job, ok, err := service.runtime.Next(ctx)
	if err != nil || !ok || job.Key != "target:"+runtimeTargetKey(draining) {
		t.Fatalf("blocked probe obscured due drain: %+v %t %v", job, ok, err)
	}
	if err = service.runtime.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		var exists bool
		_ = service.repository.View(ctx, func(tx Reader) error {
			_, e := tx.Target(scope, groupARN, "10.0.0.9", 8080)
			exists = e == nil
			return nil
		})
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("due drain waited for unrelated 120-second probe")
		}
		time.Sleep(time.Millisecond)
	}
	service.runtime.mu.Lock()
	service.runtime.nodes = map[string]map[string]*runtimeNode{}
	service.runtime.mu.Unlock()
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("shutdown left native health request running")
	}
}
