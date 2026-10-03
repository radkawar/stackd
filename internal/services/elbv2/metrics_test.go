package elbv2

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	cw "stackd/internal/awsapi/cloudwatch"
	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/scheduler"
	"stackd/internal/services/cloudwatch"
	"stackd/storage/memory"
)

func TestRequestMetricsFollowNativeTargetSelection(t *testing.T) {
	ctx := controlContext(t)
	scope := scopeFor(ctx)
	start := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	source := clock.NewManual(start)
	domain := memory.NewDomain()
	metrics := cloudwatch.New(cloudwatch.Config{Clock: source, Repository: cloudwatch.NewMemoryRepository(domain)})
	defer metrics.Close()
	service := New(Config{Clock: source, Repository: NewMemoryRepository(domain), Networks: controlNetwork{}, Metrics: metrics})
	defer service.Close()
	// This fixture explicitly drains metric windows; it does not create native
	// ALB nodes or start the independent load-balancer reconciliation source.
	service.runtime.jobs.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			w.WriteHeader(500)
		}
		_, _ = io.WriteString(w, "actual target")
	}))
	defer backend.Close()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	lbARN := "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/metrics/1"
	groupARN := "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/metrics/2"
	listenerARN := "arn:aws:elasticloadbalancing:us-east-1:000000000000:listener/app/metrics/1/3"
	lb := LoadBalancerRecord{Scope: scope, Data: api.LoadBalancer{LoadBalancerArn: new(api.LoadBalancerArn(lbARN)), AvailabilityZones: api.AvailabilityZones{{SubnetId: new(api.SubnetId("subnet-a")), ZoneName: new(api.ZoneName("us-east-1a"))}, {SubnetId: new(api.SubnetId("subnet-b")), ZoneName: new(api.ZoneName("us-east-1b"))}}}}
	group := TargetGroupRecord{Scope: scope, Data: api.TargetGroup{TargetGroupArn: new(api.TargetGroupArn(groupARN)), VpcId: new(api.VpcId("vpc-0aeae393af73839cf")), Protocol: new(api.ProtocolEnum("HTTP")), TargetType: new(api.TargetTypeEnum("ip")), LoadBalancerArns: api.LoadBalancerArns{api.LoadBalancerArn(lbARN)}}}
	listener := ListenerRecord{Scope: scope, Data: api.Listener{ListenerArn: new(api.ListenerArn(listenerARN)), LoadBalancerArn: lb.Data.LoadBalancerArn, Port: new(api.Port(80)), DefaultActions: api.Actions{{Type: new(api.ActionTypeEnum("forward")), TargetGroupArn: group.Data.TargetGroupArn}}}}
	node := &runtimeNode{transport: transport, health: transport, attachment: NetworkAttachment{SubnetID: "subnet-b"}}
	service.runtime.nodes[lbARN] = map[string]*runtimeNode{"subnet-b": node}
	defer func() { service.runtime.nodes = map[string]map[string]*runtimeNode{} }()
	update := func(f func(Transaction) error) {
		t.Helper()
		if err := service.repository.Update(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	update(func(tx Transaction) error {
		if err := tx.PutLoadBalancer(lb); err != nil {
			return err
		}
		if err := tx.PutTargetGroup(group); err != nil {
			return err
		}
		if err := tx.PutListener(listener); err != nil {
			return err
		}
		for i := 8; i < 10; i++ {
			if err := tx.PutTarget(TargetRecord{Scope: scope, TargetGroupARN: groupARN, Data: api.TargetDescription{Id: new(api.TargetId("10.0.0." + strconv.Itoa(i))), Port: new(api.Port(80))}, State: "initial", NextCheck: start, Version: 1}); err != nil {
				return err
			}
		}
		return nil
	})
	// These real probes establish the denominator, but are not customer requests.
	for i := 8; i < 10; i++ {
		if err := service.runtime.reconcileTarget(ctx, groupARN+"\x00"+"10.0.0."+strconv.Itoa(i)+"\x0080", start, 1); err != nil {
			t.Fatal(err)
		}
	}
	jobs := metricJobs{service}
	if err := jobs.Run(ctx, scheduler.Job{Key: "sample:" + lbARN, Due: start}); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { service.runtime.serve(w, r, scope, listenerARN, node) }))
	defer front.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(path string, status int) {
		t.Helper()
		response, err := client.Get(front.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != status {
			t.Fatalf("HTTP %s: status=%d error=%v", path, response.StatusCode, err)
		}
	}
	for range 4 {
		request("/", 200)
		request("/error", 500)
	}
	setAction := func(action api.Action) {
		listener.Data.DefaultActions = api.Actions{action}
		update(func(tx Transaction) error { return tx.PutListener(listener) })
	}
	setAction(api.Action{Type: new(api.ActionTypeEnum("fixed-response")), FixedResponseConfig: &api.FixedResponseActionConfig{StatusCode: new(api.FixedResponseActionStatusCode("201")), MessageBody: new(api.FixedResponseActionMessage("fixed"))}})
	request("/fixed", 201)
	setAction(api.Action{Type: new(api.ActionTypeEnum("redirect")), RedirectConfig: &api.RedirectActionConfig{Protocol: new(api.RedirectActionProtocol("HTTP")), Port: new(api.RedirectActionPort("80")), Host: new(api.RedirectActionHost("example.test")), Path: new(api.RedirectActionPath("/")), StatusCode: new(api.RedirectActionStatusCodeEnum("HTTP_302"))}})
	request("/redirect", 302)
	setAction(api.Action{Type: new(api.ActionTypeEnum("forward")), TargetGroupArn: new(api.TargetGroupArn(groupARN + "-missing"))})
	request("/empty", 503)
	if err := source.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Run(ctx, scheduler.Job{Key: "publish:" + lbARN, Due: start.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	dimensions := cw.Dimensions{{Name: new(cw.DimensionName("LoadBalancer")), Value: new(cw.DimensionValue("app/metrics/1"))}, {Name: new(cw.DimensionName("TargetGroup")), Value: new(cw.DimensionValue("targetgroup/metrics/2"))}}
	query := func(name string, dims cw.Dimensions, unit cw.StandardUnit) []cw.DatapointValue {
		t.Helper()
		out, err := metrics.GetMetricData(ctx, &cw.GetMetricDataInput{StartTime: new(cw.Timestamp(start)), EndTime: new(cw.Timestamp(source.Now())), ScanBy: new(cw.ScanBy("TimestampDescending")), MetricDataQueries: cw.MetricDataQueries{{Id: new(cw.MetricId("m")), MetricStat: &cw.MetricStat{Metric: &cw.Metric{Namespace: new(cw.Namespace("AWS/ApplicationELB")), MetricName: new(cw.MetricName(name)), Dimensions: dims}, Period: new(cw.Period(60)), Stat: new(cw.Stat("Sum")), Unit: &unit}}}})
		if err != nil {
			t.Fatal(err)
		}
		return out.MetricDataResults[0].Values
	}
	zonal := append(cw.Dimensions(nil), dimensions...)
	zonal = append(zonal, cw.Dimension{Name: new(cw.DimensionName("AvailabilityZone")), Value: new(cw.DimensionValue("us-east-1a"))})
	if values := query("RequestCountPerTarget", zonal, cw.StandardUnitNone); len(values) != 1 || values[0] != 4 {
		t.Fatalf("target-zone request count: %v", values)
	}
	zonal[2].Value = new(cw.DimensionValue("us-east-1b"))
	if values := query("RequestCountPerTarget", zonal, cw.StandardUnitNone); len(values) != 0 {
		t.Fatalf("target metric attributed to ingress node zone: %v", values)
	}
	for _, test := range []struct {
		name       string
		dimensions cw.Dimensions
		unit       cw.StandardUnit
		want       float64
	}{
		{"RequestCount", dimensions, cw.StandardUnitCount, 8}, {"RequestCountPerTarget", dimensions, cw.StandardUnitNone, 4}, {"RequestCountPerTarget", dimensions[1:], cw.StandardUnitNone, 4}, {"HTTPCode_Target_5XX_Count", dimensions, cw.StandardUnitCount, 4}, {"HealthyHostCount", dimensions, cw.StandardUnitCount, 2}, {"HTTP_Fixed_Response_Count", dimensions[:1], cw.StandardUnitCount, 1}, {"HTTP_Redirect_Count", dimensions[:1], cw.StandardUnitCount, 1}, {"HTTPCode_ELB_503_Count", dimensions[:1], cw.StandardUnitCount, 1},
	} {
		t.Run(test.name+strings.Join([]string{string(*test.dimensions[0].Name)}, ""), func(t *testing.T) {
			values := query(test.name, test.dimensions, test.unit)
			if len(values) != 1 || float64(values[0]) != test.want {
				t.Fatalf("got %v want %v", values, test.want)
			}
		})
	}
	// A deregistered target can still own its drain, but is no longer part of
	// the registered fallback denominator. Real connection failures still count.
	backend.Close()
	update(func(tx Transaction) error {
		for i := 8; i < 10; i++ {
			target, err := tx.Target(scope, groupARN, "10.0.0."+strconv.Itoa(i), 80)
			if err != nil {
				return err
			}
			target.State = "unhealthy"
			if i == 8 {
				target.State = "draining"
			}
			if err := tx.PutTarget(target); err != nil {
				return err
			}
		}
		return nil
	})
	setAction(api.Action{Type: new(api.ActionTypeEnum("forward")), TargetGroupArn: group.Data.TargetGroupArn})
	if err := jobs.Run(ctx, scheduler.Job{Key: "sample:" + lbARN, Due: source.Now()}); err != nil {
		t.Fatal(err)
	}
	for range 8 {
		request("/", 502)
	}
	if err := source.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Run(ctx, scheduler.Job{Key: "publish:" + lbARN, Due: source.Now()}); err != nil {
		t.Fatal(err)
	}
	if values := query("RequestCountPerTarget", dimensions, cw.StandardUnitNone); len(values) != 2 || values[0] != 8 {
		t.Fatalf("draining target diluted failed requests: %v", values)
	}
	if values := query("TargetConnectionErrorCount", dimensions, cw.StandardUnitCount); len(values) != 1 || values[0] != 8 {
		t.Fatalf("actual failed connects: %v", values)
	}
	if err := jobs.Run(ctx, scheduler.Job{Key: "sample:" + lbARN, Due: source.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Run(ctx, scheduler.Job{Key: "publish:" + lbARN, Due: source.Now()}); err != nil {
		t.Fatal(err)
	}
	if values := query("RequestCountPerTarget", dimensions, cw.StandardUnitNone); len(values) != 3 || values[0] != 0 {
		t.Fatalf("idle registered target did not report observed zero: %v", values)
	}
}
