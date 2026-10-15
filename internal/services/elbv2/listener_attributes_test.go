package elbv2

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	api "stackd/internal/awsapi/elbv2"
)

func TestTerraformListenerNativeAttributeBaseline(t *testing.T) {
	ctx := controlContext(t)
	scope := scopeFor(ctx)
	balancerARN := "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/native/0000000000000001"
	listenerARN := "arn:aws:elasticloadbalancing:us-east-1:000000000000:listener/app/native/0000000000000001/0000000000000002"
	repository := NewMemoryRepository(nil)
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutLoadBalancer(LoadBalancerRecord{Scope: scope, Data: api.LoadBalancer{LoadBalancerArn: new(api.LoadBalancerArn(balancerARN))}}); err != nil {
			return err
		}
		return tx.PutListener(ListenerRecord{Scope: scope, Data: api.Listener{
			ListenerArn: new(api.ListenerArn(listenerARN)), LoadBalancerArn: new(api.LoadBalancerArn(balancerARN)),
			Protocol: new(api.ProtocolEnum("HTTP")), Port: new(api.Port(8080)),
			DefaultActions: api.Actions{{Type: new(api.ActionTypeEnum("fixed-response")), FixedResponseConfig: &api.FixedResponseActionConfig{
				StatusCode: new(api.FixedResponseActionStatusCode("200")), ContentType: new(api.FixedResponseActionContentType("text/plain")),
				MessageBody: new(api.FixedResponseActionMessage("native baseline")),
			}}},
		}})
	}); err != nil {
		t.Fatal(err)
	}
	s := New(Config{Repository: repository})
	defer s.Close()
	out, err := controlCall(t, s, ctx, "DescribeListenerAttributes", url.Values{"ListenerArn": {listenerARN}})
	if err != nil {
		t.Fatal(err)
	}
	attributes := out.(*api.DescribeListenerAttributesOutput).Attributes
	if len(attributes) != 11 {
		t.Fatalf("baseline attribute count = %d", len(attributes))
	}
	for _, attribute := range attributes {
		want := ""
		if value(attribute.Key) == "routing.http.response.server.enabled" {
			want = "true"
		}
		if value(attribute.Value) != want {
			t.Fatalf("attribute %s = %q, want %q", value(attribute.Key), value(attribute.Value), want)
		}
	}
	for _, enabled := range []string{"true", "false"} {
		_, err := controlCall(t, s, ctx, "ModifyListenerAttributes", url.Values{
			"ListenerArn": {listenerARN}, "Attributes.member.1.Key": {"routing.http.response.server.enabled"},
			"Attributes.member.1.Value": {enabled},
		})
		if (err != nil) != (enabled == "false") {
			t.Fatalf("server-enabled %s: %v", enabled, err)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "http://native/", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	s.runtime.serve(response, request, scope, listenerARN, &runtimeNode{})
	if response.Code != http.StatusOK || response.Body.String() != "native baseline" || response.Header().Get("Server") != "awselb/2.0" {
		t.Fatalf("actual native baseline response = %d %q %v", response.Code, response.Body.String(), response.Header())
	}
}
