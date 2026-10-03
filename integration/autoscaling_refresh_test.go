package stackd_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	asgtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

// Native admission/history is replayed through signed SDK requests. The empty
// AMI is only a dry-run prerequisite; the executable refresh smoke proves guest
// replacement, changed application bytes, ALB traffic and physical retirement.
func TestAutoScalingRefreshNativeHistoryAndBakeRecovery(t *testing.T) {
	fixture := asgFixture(t, "refresh_native")
	audit := warmPoolNativeAudit(t, "refresh_native")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.row(t, "refresh-group-zero").StartedAt)
			bindings := map[string]string{}
			var cloud *stackd.Stack
			clients, reopen := asgRetainedCloud(t, backend, fixture, source, bindings, func(s *stackd.Stack) { cloud = s })
			for _, label := range []string{"owned-vpc", "owned-subnet", "owned-group", "refresh-template-one", "refresh-template-two"} {
				asgPrerequisite(t, clients, fixture.Region, fixture.row(t, label), bindings, nil)
			}
			asgReplay(t, clients, fixture.Region, fixture.row(t, "refresh-group-zero"), bindings, asgRoot())
			replay := func(label string) {
				t.Helper()
				row := fixture.row(t, label)
				actual, callErr := awstest.CallSDK(t.Context(), asgClient(clients, fixture.Region, asgRoot(), clients.server.Client()), row.Operation, json.RawMessage(asgReplace(string(row.Input), bindings)))
				if row.Code != "Success" {
					assertAPIError(t, callErr, row.Code)
				} else {
					if callErr != nil {
						t.Fatal(callErr)
					}
					expected := reflect.New(reflect.TypeOf(actual).Elem()).Interface()
					if err := awstest.DecodeSDK(row.Output, expected); err != nil {
						t.Fatal(err)
					}
					if want, ok := expected.(*autoscaling.DescribeInstanceRefreshesOutput); ok {
						normalizeRefreshHistoryTimes(t, label, want, actual.(*autoscaling.DescribeInstanceRefreshesOutput))
					}
					asgCompare(t, label, ec2NetworkDocument(t, expected), ec2NetworkDocument(t, actual), bindings)
				}
				got := auditLookupRecord(t, organizationTrailClient(clients, fixture.Account, fixture.Region), nativeAuditRequestID(t, actual, callErr), row.Operation)
				native, ok := audit[label]
				if !ok {
					t.Fatalf("missing native audit %s", label)
				}
				for _, field := range []string{"eventSource", "eventName", "readOnly", "eventCategory", "managementEvent", "requestParameters", "responseElements", "errorCode"} {
					want, wp := native[field]
					observed, op := got[field]
					if wp != op {
						t.Fatalf("%s audit %s presence changed", label, field)
					}
					asgCompare(t, label+".audit."+field, want, observed, bindings)
				}
			}
			for _, label := range []string{"refresh-empty-cancel_instance_refresh", "refresh-empty-rollback_instance_refresh", "refresh-empty-describe_instance_refreshes", "refresh-bad-strategy", "refresh-rollback-without-desired", "refresh-bad-checkpoints", "refresh-bad-range", "refresh-default-start"} {
				replay(label)
			}
			name := ecsControlBody(t, fixture.row(t, "refresh-group-zero").Input)["AutoScalingGroupName"].(string)
			history := &autoscaling.DescribeInstanceRefreshesInput{AutoScalingGroupName: &name}
			describe := func() asgtypes.InstanceRefresh {
				t.Helper()
				out, err := asgClient(clients, fixture.Region, asgRoot(), clients.server.Client()).DescribeInstanceRefreshes(t.Context(), history)
				if err != nil {
					t.Fatal(err)
				}
				if len(out.InstanceRefreshes) == 0 {
					t.Fatal("refresh history lost")
				}
				return out.InstanceRefreshes[0]
			}
			advance := func(d time.Duration) {
				t.Helper()
				if err := source.Advance(d); err != nil {
					t.Fatal(err)
				}
				if _, err := cloud.RunDueJobs(t.Context(), 100); err != nil {
					t.Fatal(err)
				}
			}
			until := func(status asgtypes.InstanceRefreshStatus) asgtypes.InstanceRefresh {
				t.Helper()
				for range 40 {
					r := describe()
					if r.Status == status {
						return r
					}
					advance(time.Second)
				}
				t.Fatalf("refresh did not reach %s: %+v", status, describe())
				return asgtypes.InstanceRefresh{}
			}
			successful := until(asgtypes.InstanceRefreshStatusSuccessful)
			replay("refresh-default-done-1")
			template := asgReplace(ecsControlBody(t, fixture.row(t, "refresh-template-one").Output)["LaunchTemplate"].(map[string]any)["LaunchTemplateId"].(string), bindings)
			client := asgClient(clients, fixture.Region, asgRoot(), clients.server.Client())
			started, err := client.StartInstanceRefresh(t.Context(), &autoscaling.StartInstanceRefreshInput{AutoScalingGroupName: &name, DesiredConfiguration: &asgtypes.DesiredConfiguration{LaunchTemplate: &asgtypes.LaunchTemplateSpecification{LaunchTemplateId: &template, Version: aws.String("2")}}, Preferences: &asgtypes.RefreshPreferences{BakeTime: aws.Int32(120)}})
			if err != nil {
				t.Fatal(err)
			}
			history.InstanceRefreshIds = []string{aws.ToString(started.InstanceRefreshId)}
			baking := until(asgtypes.InstanceRefreshStatusBaking)
			// A zero-member refresh may complete before another HTTP request.
			// The manual clock holds this refresh in Baking, so the native
			// concurrent-admission rejection has a stable active prerequisite.
			replay("refresh-concurrent-start")
			clients = reopen()
			client = asgClient(clients, fixture.Region, asgRoot(), clients.server.Client())
			retained := describe()
			if aws.ToString(retained.InstanceRefreshId) != aws.ToString(started.InstanceRefreshId) || retained.Status != asgtypes.InstanceRefreshStatusBaking {
				t.Fatalf("bake state not retained: %+v", retained)
			}
			if !reflect.DeepEqual(baking.StartTime, retained.StartTime) || retained.EndTime != nil {
				t.Fatalf("reopen changed active refresh timestamps: before=%+v after=%+v", baking, retained)
			}
			groups, err := client.DescribeAutoScalingGroups(t.Context(), &autoscaling.DescribeAutoScalingGroupsInput{AutoScalingGroupNames: []string{name}})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(groups.AutoScalingGroups[0].LaunchTemplate.Version) != "1" {
				t.Fatal("desired launch configuration committed before bake completion")
			}
			_, err = client.UpdateAutoScalingGroup(t.Context(), &autoscaling.UpdateAutoScalingGroupInput{AutoScalingGroupName: &name, LaunchTemplate: &asgtypes.LaunchTemplateSpecification{LaunchTemplateId: &template, Version: aws.String("2")}})
			assertAPIError(t, err, "ValidationError")
			advance(120 * time.Second)
			until(asgtypes.InstanceRefreshStatusSuccessful)
			groups, err = client.DescribeAutoScalingGroups(t.Context(), &autoscaling.DescribeAutoScalingGroupsInput{AutoScalingGroupNames: []string{name}})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(groups.AutoScalingGroups[0].LaunchTemplate.Version) != "2" {
				t.Fatal("successful refresh did not commit desired configuration")
			}
			page, err := client.DescribeInstanceRefreshes(t.Context(), &autoscaling.DescribeInstanceRefreshesInput{AutoScalingGroupName: &name, MaxRecords: aws.Int32(1)})
			if err != nil {
				t.Fatal(err)
			}
			next, err := client.DescribeInstanceRefreshes(t.Context(), &autoscaling.DescribeInstanceRefreshesInput{AutoScalingGroupName: &name, NextToken: page.NextToken})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.InstanceRefreshes) != 1 || len(next.InstanceRefreshes) != 1 || aws.ToString(next.InstanceRefreshes[0].InstanceRefreshId) == aws.ToString(page.InstanceRefreshes[0].InstanceRefreshId) {
				t.Fatalf("history cursor repeated or lost refresh: %+v %+v", page, next)
			}
			for _, historical := range append(page.InstanceRefreshes, next.InstanceRefreshes...) {
				if aws.ToString(historical.InstanceRefreshId) == aws.ToString(successful.InstanceRefreshId) &&
					(!reflect.DeepEqual(historical.StartTime, successful.StartTime) || !reflect.DeepEqual(historical.EndTime, successful.EndTime)) {
					t.Fatalf("completed refresh timestamps changed in history: before=%+v after=%+v", successful, historical)
				}
			}
		})
	}
}

// Absolute native timestamps relocate independently by field, not by their
// serialized value: distinct transitions may share one AWS timestamp second,
// and SDK decoding canonicalizes botocore's +00:00 representation to Z.
func normalizeRefreshHistoryTimes(t *testing.T, label string, want, got *autoscaling.DescribeInstanceRefreshesOutput) {
	t.Helper()
	if len(want.InstanceRefreshes) != len(got.InstanceRefreshes) {
		t.Fatalf("%s refresh history count: want %d, got %d", label, len(want.InstanceRefreshes), len(got.InstanceRefreshes))
	}
	for i := range want.InstanceRefreshes {
		expected, actual := &want.InstanceRefreshes[i], &got.InstanceRefreshes[i]
		for _, stamp := range []struct {
			name string
			want **time.Time
			got  *time.Time
		}{{"StartTime", &expected.StartTime, actual.StartTime}, {"EndTime", &expected.EndTime, actual.EndTime}} {
			if (*stamp.want == nil) != (stamp.got == nil) || stamp.got != nil && stamp.got.IsZero() {
				t.Fatalf("%s[%d].%s timestamp presence or validity changed: want %v, got %v", label, i, stamp.name, *stamp.want, stamp.got)
			}
			*stamp.want = stamp.got
		}
		if actual.StartTime != nil && actual.EndTime != nil && actual.EndTime.Before(*actual.StartTime) {
			t.Fatalf("%s[%d] refresh ended before it started: %+v", label, i, actual)
		}
	}
}
