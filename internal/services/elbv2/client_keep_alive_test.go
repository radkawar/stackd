package elbv2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	api "stackd/internal/awsapi/elbv2"
)

func TestNativeClientKeepAliveFinalRequest(t *testing.T) {
	ctx := controlContext(t)
	s := New(Config{})
	defer s.Close()
	sc := scopeFor(ctx)
	lbARN := arn(sc, "loadbalancer/app/keepalive/0000000000000001")
	listenerARN := arn(sc, "listener/app/keepalive/0000000000000001/0000000000000002")
	lb := LoadBalancerRecord{Scope: sc, IdleTimeout: time.Minute}
	text(&lb.Data.LoadBalancerArn, lbARN)
	listener := ListenerRecord{Scope: sc}
	text(&listener.Data.ListenerArn, listenerARN)
	text(&listener.Data.LoadBalancerArn, lbARN)
	listener.Data.DefaultActions = api.Actions{{Type: new(api.ActionTypeEnum("fixed-response")), FixedResponseConfig: &api.FixedResponseActionConfig{StatusCode: new(api.FixedResponseActionStatusCode("200")), ContentType: new(api.FixedResponseActionContentType("text/plain")), MessageBody: new(api.FixedResponseActionMessage("real handler response"))}}}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutLoadBalancer(lb); err != nil {
			return err
		}
		return tx.PutListener(listener)
	}); err != nil {
		t.Fatal(err)
	}
	for _, expired := range []bool{false, true} {
		accepted := time.Now()
		if expired {
			accepted = accepted.Add(-defaultClientKeepAlive - time.Second)
		}
		connection := &idleConnection{accepted: accepted}
		request := httptest.NewRequest(http.MethodGet, "http://native/", nil)
		request = request.WithContext(context.WithValue(ctx, idleHTTPContextKey{}, connection))
		response := httptest.NewRecorder()
		s.runtime.serve(response, request, sc, listenerARN, &runtimeNode{})
		if response.Code != 200 || response.Body.String() != "real handler response" {
			t.Fatalf("final request truncated: %#v", response)
		}
		if (response.Header().Get("Connection") == "close") != expired || request.Close != expired {
			t.Fatalf("connection age closure: expired=%v headers=%v close=%v", expired, response.Header(), request.Close)
		}
	}
}
