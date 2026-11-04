package elbv2

import (
	"net/url"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/elbv2"
)

// Request shapes follow AWS Load Balancer Controller v2.14.1:
// pkg/ingress/model_build_listener.go, pkg/deploy/elbv2/listener_utils.go,
// pkg/targetgroupbinding/resource_manager.go. This is a generated-Query/control
// regression, not evidence of a routable k3d overlay or a running controller.
func TestLoadBalancerControllerIPTargetReconciliation(t *testing.T) {
	ctx := controlContext(t)
	s := New(Config{Networks: controlNetwork{}, Clock: clock.NewManual(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))})
	defer s.Close()
	lb := dnsRecord(scopeFor(ctx), "controller", "internal")
	text(&lb.Data.VpcId, "vpc-0aeae393af73839cf")
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutLoadBalancer(lb) }); err != nil {
		t.Fatal(err)
	}
	call := func(action string, input url.Values) any {
		t.Helper()
		out, err := controlCall(t, s, ctx, action, input)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return out
	}
	group := controlGroup(t, s, ctx, "k8s-controller-echo")
	call("DescribeLoadBalancerAttributes", url.Values{"LoadBalancerArn": {value(lb.Data.LoadBalancerArn)}})
	call("DescribeTargetGroupAttributes", url.Values{"TargetGroupArn": {value(group.TargetGroupArn)}})
	listener := call("CreateListener", url.Values{
		"LoadBalancerArn": {value(lb.Data.LoadBalancerArn)}, "Protocol": {"HTTP"}, "Port": {"80"},
		"DefaultActions.member.1.Type": {"fixed-response"}, "DefaultActions.member.1.Order": {"1"},
		"DefaultActions.member.1.FixedResponseConfig.ContentType": {"text/plain"},
		"DefaultActions.member.1.FixedResponseConfig.StatusCode":  {"404"},
		"Tags.member.1.Key": {"elbv2.k8s.aws/cluster"}, "Tags.member.1.Value": {"controller"},
	}).(*api.CreateListenerOutput).Listeners[0]
	call("DescribeListenerAttributes", url.Values{"ListenerArn": {value(listener.ListenerArn)}})
	rule := call("CreateRule", url.Values{
		"ListenerArn": {value(listener.ListenerArn)}, "Priority": {"1"},
		"Conditions.member.1.Field": {"path-pattern"}, "Conditions.member.1.PathPatternConfig.Values.member.1": {"/*"},
		"Actions.member.1.Type": {"forward"}, "Actions.member.1.Order": {"1"},
		"Actions.member.1.ForwardConfig.TargetGroups.member.1.TargetGroupArn": {value(group.TargetGroupArn)},
		"Actions.member.1.ForwardConfig.TargetGroups.member.1.Weight":         {"1"},
		"Tags.member.1.Key": {"ingress.k8s.aws/stack"}, "Tags.member.1.Value": {"controller/echo"},
	}).(*api.CreateRuleOutput).Rules[0]
	call("DescribeTags", url.Values{
		"ResourceArns.member.1": {value(lb.Data.LoadBalancerArn)},
		"ResourceArns.member.2": {value(listener.ListenerArn)},
		"ResourceArns.member.3": {value(rule.RuleArn)},
		"ResourceArns.member.4": {value(group.TargetGroupArn)},
	})

	registration := url.Values{
		"TargetGroupArn": {value(group.TargetGroupArn)}, "Targets.member.1.Id": {"192.168.72.3"},
		"Targets.member.1.Port": {"8080"}, "Targets.member.1.AvailabilityZone": {"all"},
	}
	call("RegisterTargets", registration)
	call("RegisterTargets", registration)
	health := call("DescribeTargetHealth", url.Values{"TargetGroupArn": {value(group.TargetGroupArn)}}).(*api.DescribeTargetHealthOutput)
	if len(health.TargetHealthDescriptions) != 1 {
		t.Fatalf("idempotent controller registration returned %d targets", len(health.TargetHealthDescriptions))
	}
	target := health.TargetHealthDescriptions[0]
	if value(target.Target.AvailabilityZone) != "all" || value(target.TargetHealth.State) == "healthy" {
		t.Fatalf("outside-VPC target zone=%q health=%q without a native node", value(target.Target.AvailabilityZone), value(target.TargetHealth.State))
	}

	call("ModifyTargetGroupAttributes", url.Values{
		"TargetGroupArn":          {value(group.TargetGroupArn)},
		"Attributes.member.1.Key": {"deregistration_delay.timeout_seconds"}, "Attributes.member.1.Value": {"0"},
	})
	call("DeregisterTargets", registration)
	call("RegisterTargets", registration)
	health = call("DescribeTargetHealth", url.Values{"TargetGroupArn": {value(group.TargetGroupArn)}}).(*api.DescribeTargetHealthOutput)
	if len(health.TargetHealthDescriptions) != 1 || value(health.TargetHealthDescriptions[0].TargetHealth.State) == "draining" || value(health.TargetHealthDescriptions[0].TargetHealth.State) == "healthy" {
		t.Fatalf("controller re-registration did not cancel draining without inventing health: %+v", health)
	}
	call("DeleteRule", url.Values{"RuleArn": {value(rule.RuleArn)}})
	call("DeregisterTargets", registration)
	call("DeleteTargetGroup", url.Values{"TargetGroupArn": {value(group.TargetGroupArn)}})
	call("DeleteListener", url.Values{"ListenerArn": {value(listener.ListenerArn)}})
}
