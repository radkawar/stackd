package stackd_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	asgtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/internal/awstest"
)

// These fixtures use the existing EC2 running-observation precondition, never a
// fake power executor. Running-pool membership and hook transitions need no VM
// power effects; the executable warm-pool smoke proves stop/hibernate/restore.
func warmPoolState(t *testing.T, r *retentionCloud, state string) asgtypes.Instance {
	t.Helper()
	for range 40 {
		r.advance(time.Second)
		out, err := r.asg().DescribeWarmPool(t.Context(), &autoscaling.DescribeWarmPoolInput{AutoScalingGroupName: aws.String(r.name)})
		r.check(err)
		for _, instance := range out.Instances {
			if aws.ToString(instance.InstanceId) == r.instance && string(instance.LifecycleState) == state {
				return instance
			}
		}
	}
	t.Fatalf("warm instance did not reach %s", state)
	return asgtypes.Instance{}
}

func warmPoolComplete(r *retentionCloud, hook, result string) {
	r.t.Helper()
	_, err := r.asg().CompleteLifecycleAction(r.t.Context(), &autoscaling.CompleteLifecycleActionInput{AutoScalingGroupName: aws.String(r.name), LifecycleHookName: aws.String(hook), InstanceId: aws.String(r.instance), LifecycleActionResult: aws.String(result)})
	r.check(err)
}

func TestAutoScalingWarmPoolOwnershipRetentionAndReopen(t *testing.T) {
	fixture := asgFixture(t, "retention_native")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newRetentionCloud(t, backend, fixture, true)
			var nativeMembership autoscaling.DescribeAutoScalingInstancesOutput
			r.check(awstest.DecodeSDK(fixture.row(t, "explicit-original-inservice-observed-membership").Output, &nativeMembership))
			details, err := r.asg().DescribeAutoScalingInstances(t.Context(), &autoscaling.DescribeAutoScalingInstancesInput{InstanceIds: []string{r.instance}})
			r.check(err)
			if len(details.AutoScalingInstances) != 1 || aws.ToString(details.AutoScalingInstances[0].HealthStatus) != aws.ToString(nativeMembership.AutoScalingInstances[0].HealthStatus) || aws.ToString(details.AutoScalingInstances[0].LifecycleState) != aws.ToString(nativeMembership.AutoScalingInstances[0].LifecycleState) {
				t.Fatalf("normal membership projection differs from native retention fixture: %+v", details)
			}
			_, err = r.asg().UpdateAutoScalingGroup(t.Context(), &autoscaling.UpdateAutoScalingGroupInput{AutoScalingGroupName: aws.String(r.name), MaxSize: aws.Int32(1)})
			r.check(err)
			_, err = r.asg().EnableMetricsCollection(t.Context(), &autoscaling.EnableMetricsCollectionInput{AutoScalingGroupName: aws.String(r.name), Granularity: aws.String("1Minute")})
			r.check(err)
			_, err = r.asg().PutWarmPool(t.Context(), &autoscaling.PutWarmPoolInput{AutoScalingGroupName: aws.String(r.name), PoolState: asgtypes.WarmPoolStateRunning, MaxGroupPreparedCapacity: aws.Int32(1), InstanceReusePolicy: &asgtypes.InstanceReusePolicy{ReuseOnScaleIn: aws.Bool(true)}})
			r.check(err)
			_, err = r.asg().SetDesiredCapacity(t.Context(), &autoscaling.SetDesiredCapacityInput{AutoScalingGroupName: aws.String(r.name), DesiredCapacity: aws.Int32(0)})
			r.check(err)
			warmPoolState(t, r, "Warmed:Pending:Wait")
			group := r.group()
			if len(group.Instances) != 0 || aws.ToInt32(group.DesiredCapacity) != 0 || aws.ToInt32(group.WarmPoolSize) != 1 {
				t.Fatalf("warm return leaked into active capacity: %+v", group)
			}
			r.original("running")
			warmPoolComplete(r, "terminate", "CONTINUE")
			ready := warmPoolState(t, r, "Warmed:Running")
			if ready.ProtectedFromScaleIn != nil || aws.ToString(ready.HealthStatus) != "Healthy" {
				t.Fatalf("warm projection: %+v", ready)
			}
			r.reopenCloud()
			warmPoolState(t, r, "Warmed:Running")
			r.assertGauges(map[string]float64{"WarmPoolDesiredCapacity": 1, "WarmPoolWarmedCapacity": 1, "WarmPoolTotalCapacity": 1, "GroupTotalInstances": 0, "GroupAndWarmPoolTotalCapacity": 1})
			_, err = r.asg().PutWarmPool(t.Context(), &autoscaling.PutWarmPoolInput{AutoScalingGroupName: aws.String(r.name), MinSize: aws.Int32(2), MaxGroupPreparedCapacity: aws.Int32(2)})
			r.check(err)
			r.assertGauges(map[string]float64{"WarmPoolMinSize": 2, "WarmPoolDesiredCapacity": 2, "WarmPoolTotalCapacity": 1, "GroupAndWarmPoolDesiredCapacity": 2})
			_, err = r.asg().PutWarmPool(t.Context(), &autoscaling.PutWarmPoolInput{AutoScalingGroupName: aws.String(r.name), MinSize: aws.Int32(0), MaxGroupPreparedCapacity: aws.Int32(1)})
			r.check(err)
			membership, err := r.asg().DescribeAutoScalingInstances(t.Context(), &autoscaling.DescribeAutoScalingInstancesInput{InstanceIds: []string{r.instance}})
			r.check(err)
			if len(membership.AutoScalingInstances) != 1 || aws.ToString(membership.AutoScalingInstances[0].AutoScalingGroupName) != r.name || aws.ToString(membership.AutoScalingInstances[0].HealthStatus) != "HEALTHY" {
				t.Fatalf("warm instance lost its unique ASG membership: %+v", membership)
			}
			_, err = r.asg().DeleteWarmPool(t.Context(), &autoscaling.DeleteWarmPoolInput{AutoScalingGroupName: aws.String(r.name)})
			assertAPIError(t, err, "ResourceInUse")
			_, err = r.asg().PutLifecycleHook(t.Context(), &autoscaling.PutLifecycleHookInput{AutoScalingGroupName: aws.String(r.name), LifecycleHookName: aws.String("activate"), LifecycleTransition: aws.String("autoscaling:EC2_INSTANCE_LAUNCHING"), HeartbeatTimeout: aws.Int32(300), DefaultResult: aws.String("ABANDON")})
			r.check(err)
			_, err = r.asg().SetDesiredCapacity(t.Context(), &autoscaling.SetDesiredCapacityInput{AutoScalingGroupName: aws.String(r.name), DesiredCapacity: aws.Int32(1)})
			r.check(err)
			_, err = r.asg().ResumeProcesses(t.Context(), &autoscaling.ResumeProcessesInput{AutoScalingGroupName: aws.String(r.name), ScalingProcesses: []string{"Launch"}})
			r.check(err)
			r.untilState("Pending:Wait")
			out, err := r.asg().DescribeWarmPool(t.Context(), &autoscaling.DescribeWarmPoolInput{AutoScalingGroupName: aws.String(r.name)})
			r.check(err)
			if len(out.Instances) != 0 {
				t.Fatalf("activated instance remains in two memberships: %+v", out)
			}
			warmPoolComplete(r, "activate", "CONTINUE")
			r.untilState("InService")
			r.original("running")
			_, err = r.asg().SuspendProcesses(t.Context(), &autoscaling.SuspendProcessesInput{AutoScalingGroupName: aws.String(r.name), ScalingProcesses: []string{"Launch"}})
			r.check(err)
			_, err = r.asg().PutWarmPool(t.Context(), &autoscaling.PutWarmPoolInput{AutoScalingGroupName: aws.String(r.name), MinSize: aws.Int32(1)})
			r.check(err)
			r.assertGauges(map[string]float64{"WarmPoolMinSize": 1, "WarmPoolDesiredCapacity": 1, "WarmPoolTotalCapacity": 0, "GroupDesiredCapacity": 1, "GroupTotalInstances": 1, "GroupAndWarmPoolDesiredCapacity": 2})
			_, err = r.asg().PutWarmPool(t.Context(), &autoscaling.PutWarmPoolInput{AutoScalingGroupName: aws.String(r.name), MinSize: aws.Int32(0)})
			r.check(err)
			_, err = r.asg().SetDesiredCapacity(t.Context(), &autoscaling.SetDesiredCapacityInput{AutoScalingGroupName: aws.String(r.name), DesiredCapacity: aws.Int32(0)})
			r.check(err)
			warmPoolState(t, r, "Warmed:Pending:Wait")
			warmPoolComplete(r, "terminate", "ABANDON")
			warmPoolState(t, r, "Warmed:Pending:Retained")
			r.reopenCloud()
			warmPoolState(t, r, "Warmed:Pending:Retained")
			r.original("running")
			r.assertGauges(map[string]float64{"WarmPoolPendingRetainedCapacity": 1, "WarmPoolTerminatingRetainedCapacity": 0, "WarmPoolDesiredCapacity": 1, "WarmPoolWarmedCapacity": 0, "WarmPoolTotalCapacity": 1, "GroupTotalInstances": 0})
			_, err = r.asg().TerminateInstanceInAutoScalingGroup(t.Context(), &autoscaling.TerminateInstanceInAutoScalingGroupInput{InstanceId: aws.String(r.instance), ShouldDecrementDesiredCapacity: aws.Bool(true)})
			assertAPIError(t, err, "ValidationError")
			_, err = r.asg().TerminateInstanceInAutoScalingGroup(t.Context(), &autoscaling.TerminateInstanceInAutoScalingGroupInput{InstanceId: aws.String(r.instance), ShouldDecrementDesiredCapacity: aws.Bool(false)})
			r.check(err)
			warmPoolState(t, r, "Warmed:Terminating:Wait")
			warmPoolComplete(r, "terminate", "ABANDON")
			warmPoolState(t, r, "Warmed:Terminating:Retained")
			r.assertGauges(map[string]float64{"WarmPoolPendingRetainedCapacity": 0, "WarmPoolTerminatingRetainedCapacity": 1, "WarmPoolTotalCapacity": 1, "GroupTotalInstances": 0})
			_, err = r.asg().TerminateInstanceInAutoScalingGroup(t.Context(), &autoscaling.TerminateInstanceInAutoScalingGroupInput{InstanceId: aws.String(r.instance), ShouldDecrementDesiredCapacity: aws.Bool(false)})
			r.check(err)
			warmPoolState(t, r, "Warmed:Terminating:Wait")
			warmPoolComplete(r, "terminate", "CONTINUE")
			r.untilTerminationAdmitted()
		})
	}
}

func warmPoolNativeAudit(t *testing.T, name string) map[string]map[string]any {
	t.Helper()
	var evidence struct {
		CloudTrail struct {
			Events []struct {
				Label string `json:"call_label"`
				Event map[string]any
			}
		}
	}
	awsReadFixture(t, "autoscaling/"+name+".json", &evidence)
	audit := map[string]map[string]any{}
	for _, row := range evidence.CloudTrail.Events {
		audit[row.Label] = row.Event
	}
	return audit
}

func TestAutoScalingNativeWarmPoolControlsAuthorityAndAudit(t *testing.T) {
	fixture := asgFixture(t, "warm_pool_native")
	audit := warmPoolNativeAudit(t, "warm_pool_native")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newRetentionCloud(t, backend, asgFixture(t, "retention_native"), true)
			_, err := r.asg().UpdateAutoScalingGroup(t.Context(), &autoscaling.UpdateAutoScalingGroupInput{AutoScalingGroupName: aws.String(r.name), MaxSize: aws.Int32(1)})
			r.check(err)
			rejectedCreate := asgFixture(t, "warm_pool_retention_native").row(t, "warm-create-zero")
			var create autoscaling.CreateAutoScalingGroupInput
			r.check(awstest.DecodeSDK(rejectedCreate.Input, &create))
			create.AutoScalingGroupName = aws.String("retention-invalid-hook")
			create.LaunchTemplate = r.group().LaunchTemplate
			create.VPCZoneIdentifier = r.group().VPCZoneIdentifier
			_, err = r.asg().CreateAutoScalingGroup(t.Context(), &create)
			assertAPIError(t, err, rejectedCreate.Code)
			absent, err := r.asg().DescribeAutoScalingGroups(t.Context(), &autoscaling.DescribeAutoScalingGroupsInput{AutoScalingGroupNames: []string{*create.AutoScalingGroupName}})
			r.check(err)
			if len(absent.AutoScalingGroups) != 0 {
				t.Fatal("rejected retained group creation leaked a group")
			}
			nativeName := ecsControlBody(t, fixture.row(t, "warm-zero-defaults").Input)["AutoScalingGroupName"].(string)
			bindings := map[string]string{nativeName: r.name}
			replay := func(label string, identity aws.Credentials) {
				t.Helper()
				row := fixture.row(t, label)
				actual, callErr := awstest.CallSDK(t.Context(), asgClient(r.clients, fixture.Region, identity, r.clients.server.Client()), row.Operation, json.RawMessage(asgReplace(string(row.Input), bindings)))
				if row.Code == "Success" {
					r.check(callErr)
					expected := reflect.New(reflect.TypeOf(actual).Elem()).Interface()
					r.check(awstest.DecodeSDK(row.Output, expected))
					asgCompare(t, label, ec2NetworkDocument(t, expected), ec2NetworkDocument(t, actual), bindings)
				} else {
					assertAPIError(t, callErr, row.Code)
				}
				native, ok := audit[label]
				if !ok {
					t.Fatalf("missing exact-request native audit for %s", label)
				}
				got := auditLookupRecord(t, organizationTrailClient(r.clients, fixture.Account, fixture.Region), nativeAuditRequestID(t, actual, callErr), row.Operation)
				for _, field := range []string{"eventSource", "eventName", "readOnly", "eventCategory", "managementEvent", "requestParameters", "responseElements", "errorCode"} {
					wantValue, wantPresent := native[field]
					gotValue, gotPresent := got[field]
					if wantPresent != gotPresent {
						t.Fatalf("%s audit %s presence: native=%v actual=%v", label, field, wantPresent, gotPresent)
					}
					asgCompare(t, label+".audit."+field, wantValue, gotValue, bindings)
				}
			}
			// Live-member reconciliation legitimately assumes the execution role;
			// it must not invent RunInstances admission for zero-size pool controls.
			admissionEvents := func() int {
				count := 0
				pages := cloudtrail.NewLookupEventsPaginator(organizationTrailClient(r.clients, fixture.Account, fixture.Region), &cloudtrail.LookupEventsInput{MaxResults: aws.Int32(50), LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("RunInstances")}}})
				for pages.HasMorePages() {
					page, err := pages.NextPage(t.Context())
					r.check(err)
					count += len(page.Events)
				}
				return count
			}
			beforeControls := admissionEvents()
			for _, label := range []string{"warm-absent-describe", "warm-absent-delete", "warm-zero-defaults", "warm-zero-defaults-described", "warm-zero-explicit", "warm-zero-explicit-described", "warm-zero-omitted-update", "warm-zero-omitted-update-described", "warm-zero-clear-prepared", "warm-zero-clear-prepared-described", "warm-hibernated-unconfigured-template", "warm-after-hibernated-request", "warm-zero-restore-stopped", "warm-invalid-negative-min", "warm-invalid-invalid-state", "warm-invalid-invalid-prepared", "warm-invalid-pagination", "warm-maxrecords-one"} {
				replay(label, asgRoot())
				r.reopenCloud()
			}
			if after := admissionEvents(); beforeControls != after {
				t.Fatalf("zero-size warm controls invented compute admissions: before=%v after=%v", beforeControls, after)
			}
			role, err := r.clients.iam("test", "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("warm-controls"), AssumeRolePolicyDocument: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}}`, fixture.Account))})
			r.check(err)
			_, err = r.clients.iam("test", "test", "").PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("warm-controls"), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"autoscaling:*","Resource":"*"}}`)})
			r.check(err)
			for _, scenario := range []struct{ label, deny string }{{"warm-iam-deny-put", "autoscaling:PutWarmPool"}, {"warm-iam-deny-describe", "autoscaling:DescribeWarmPool"}, {"warm-iam-deny-delete", "autoscaling:DeleteWarmPool"}, {"warm-iam-deny-run", "ec2:RunInstances"}, {"warm-iam-deny-pass", "iam:PassRole"}} {
				session, err := r.clients.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String(scenario.label), Policy: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":%q,"Resource":"*"}]}`, scenario.deny))})
				r.check(err)
				replay(scenario.label, aws.Credentials{AccessKeyID: aws.ToString(session.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(session.Credentials.SecretAccessKey), SessionToken: aws.ToString(session.Credentials.SessionToken)})
			}
			for _, isolated := range []struct {
				region   string
				identity aws.Credentials
			}{{"us-west-2", asgRoot()}, {fixture.Region, aws.Credentials{AccessKeyID: "999999999999", SecretAccessKey: "test"}}} {
				_, err := asgClient(r.clients, isolated.region, isolated.identity, r.clients.server.Client()).DescribeWarmPool(t.Context(), &autoscaling.DescribeWarmPoolInput{AutoScalingGroupName: aws.String(r.name)})
				assertAPIError(t, err, "ValidationError")
			}
			replay("warm-empty-delete", asgRoot())
			for range 40 {
				r.advance(time.Second)
				out, err := r.asg().DescribeWarmPool(t.Context(), &autoscaling.DescribeWarmPoolInput{AutoScalingGroupName: aws.String(r.name)})
				r.check(err)
				if out.WarmPoolConfiguration == nil {
					r.reopenCloud()
					replay("warm-absent-describe", asgRoot())
					source := r.group()
					emptyName := r.name + "-empty"
					_, err = r.asg().CreateAutoScalingGroup(t.Context(), &autoscaling.CreateAutoScalingGroupInput{AutoScalingGroupName: aws.String(emptyName), MinSize: aws.Int32(0), MaxSize: aws.Int32(0), DesiredCapacity: aws.Int32(0), LaunchTemplate: source.LaunchTemplate, VPCZoneIdentifier: source.VPCZoneIdentifier})
					r.check(err)
					_, err = r.asg().PutWarmPool(t.Context(), &autoscaling.PutWarmPoolInput{AutoScalingGroupName: aws.String(emptyName), MinSize: aws.Int32(0), MaxGroupPreparedCapacity: aws.Int32(0)})
					r.check(err)
					_, err = r.asg().DeleteAutoScalingGroup(t.Context(), &autoscaling.DeleteAutoScalingGroupInput{AutoScalingGroupName: aws.String(emptyName)})
					r.check(err)
					for range 40 {
						r.advance(time.Second)
						groups, err := r.asg().DescribeAutoScalingGroups(t.Context(), &autoscaling.DescribeAutoScalingGroupsInput{AutoScalingGroupNames: []string{emptyName}})
						r.check(err)
						if len(groups.AutoScalingGroups) == 0 {
							return
						}
					}
					t.Fatal("configured empty warm pool blocked group deletion")
					return
				}
			}
			t.Fatal("empty warm-pool deletion did not settle")
		})
	}
}

func TestAutoScalingWarmPoolHealthDoesNotBorrowGroupGrace(t *testing.T) {
	fixture := asgFixture(t, "warm_pool_pending_retention_native")
	audit := warmPoolNativeAudit(t, "warm_pool_pending_retention_native")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newRetentionCloud(t, backend, asgFixture(t, "retention_native"), true)
			_, err := r.asg().UpdateAutoScalingGroup(t.Context(), &autoscaling.UpdateAutoScalingGroupInput{AutoScalingGroupName: aws.String(r.name), MaxSize: aws.Int32(1), HealthCheckGracePeriod: aws.Int32(3600)})
			r.check(err)
			_, err = r.asg().PutWarmPool(t.Context(), &autoscaling.PutWarmPoolInput{AutoScalingGroupName: aws.String(r.name), PoolState: asgtypes.WarmPoolStateRunning, InstanceReusePolicy: &asgtypes.InstanceReusePolicy{ReuseOnScaleIn: aws.Bool(true)}})
			r.check(err)
			_, err = r.asg().SetDesiredCapacity(t.Context(), &autoscaling.SetDesiredCapacityInput{AutoScalingGroupName: aws.String(r.name), DesiredCapacity: aws.Int32(0)})
			r.check(err)
			warmPoolState(t, r, "Warmed:Pending:Wait")
			warmPoolComplete(r, "terminate", "CONTINUE")
			warmPoolState(t, r, "Warmed:Running")
			_, err = r.asg().SetInstanceHealth(t.Context(), &autoscaling.SetInstanceHealthInput{InstanceId: aws.String(r.instance), HealthStatus: aws.String("Unhealthy"), ShouldRespectGracePeriod: aws.Bool(true)})
			r.check(err)
			warmPoolState(t, r, "Warmed:Terminating:Wait")
			warmPoolComplete(r, "terminate", "ABANDON")
			retained := warmPoolState(t, r, "Warmed:Terminating:Retained")
			if aws.ToString(retained.HealthStatus) != "Unhealthy" || len(r.group().Instances) != 0 || aws.ToInt32(r.group().DesiredCapacity) != 0 {
				t.Fatalf("warm health replacement changed active capacity or lost health: %+v", retained)
			}
			r.original("running")
			_, err = r.asg().DeleteWarmPool(t.Context(), &autoscaling.DeleteWarmPoolInput{AutoScalingGroupName: aws.String(r.name)})
			nativeDelete := fixture.row(t, "retention-pending-normal-delete-pool")
			assertAPIError(t, err, nativeDelete.Code)
			rejected := auditLookupRecord(t, organizationTrailClient(r.clients, fixture.Account, fixture.Region), nativeAuditRequestID(t, nil, err), nativeDelete.Operation)
			asgCompare(t, "nonempty warm-pool deletion audit exception", audit[nativeDelete.Label]["errorCode"], rejected["errorCode"], nil)
			forced, err := r.asg().DeleteWarmPool(t.Context(), &autoscaling.DeleteWarmPoolInput{AutoScalingGroupName: aws.String(r.name), ForceDelete: aws.Bool(true)})
			r.check(err)
			nativeForce := fixture.row(t, "retention-pending-force-delete-pool")
			forceRecord := auditLookupRecord(t, organizationTrailClient(r.clients, fixture.Account, fixture.Region), nativeAuditRequestID(t, forced, err), nativeForce.Operation)
			bindings := map[string]string{ecsControlBody(t, nativeForce.Input)["AutoScalingGroupName"].(string): r.name}
			for _, field := range []string{"requestParameters", "responseElements", "errorCode"} {
				asgCompare(t, "force warm-pool deletion audit "+field, audit[nativeForce.Label][field], forceRecord[field], bindings)
			}
			warmPoolState(t, r, "Warmed:Terminating:Wait")
			r.original("running")
			warmPoolComplete(r, "terminate", "ABANDON")
			// Native warm_pool_force_retained_native starts another hook without
			// a second force request, manual release, or policy mutation.
			r.reopenCloud()
			warmPoolState(t, r, "Warmed:Terminating:Wait")
			warmPoolComplete(r, "terminate", "CONTINUE")
			r.untilTerminationAdmitted()
			deleting, err := r.asg().DescribeWarmPool(t.Context(), &autoscaling.DescribeWarmPoolInput{AutoScalingGroupName: aws.String(r.name)})
			r.check(err)
			config := deleting.WarmPoolConfiguration
			if config == nil || config.Status != asgtypes.WarmPoolStatusPendingDelete || config.MaxGroupPreparedCapacity == nil || aws.ToInt32(config.MaxGroupPreparedCapacity) != 0 || aws.ToInt32(config.MinSize) != 0 || config.PoolState != asgtypes.WarmPoolStateRunning || config.InstanceReusePolicy == nil || !aws.ToBool(config.InstanceReusePolicy.ReuseOnScaleIn) {
				t.Fatalf("warm deletion did not clear prepared capacity while preserving power/reuse configuration: %+v", config)
			}
		})
	}
}

func TestAutoScalingWarmPoolReuseAbandonWithoutRetention(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			// Native warm_pool_return_abandon_native keeps the same running guest:
			// ABANDON skips remaining hooks, not the configured reuse destination.
			r := newRetentionCloud(t, backend, asgFixture(t, "retention_native"), false)
			_, err := r.asg().UpdateAutoScalingGroup(t.Context(), &autoscaling.UpdateAutoScalingGroupInput{AutoScalingGroupName: aws.String(r.name), MaxSize: aws.Int32(1), InstanceLifecyclePolicy: &asgtypes.InstanceLifecyclePolicy{RetentionTriggers: &asgtypes.RetentionTriggers{TerminateHookAbandon: "terminate"}}})
			r.check(err)
			_, err = r.asg().PutWarmPool(t.Context(), &autoscaling.PutWarmPoolInput{AutoScalingGroupName: aws.String(r.name), PoolState: asgtypes.WarmPoolStateRunning, InstanceReusePolicy: &asgtypes.InstanceReusePolicy{ReuseOnScaleIn: aws.Bool(true)}})
			r.check(err)
			_, err = r.asg().SetDesiredCapacity(t.Context(), &autoscaling.SetDesiredCapacityInput{AutoScalingGroupName: aws.String(r.name), DesiredCapacity: aws.Int32(0)})
			r.check(err)
			warmPoolState(t, r, "Warmed:Pending:Wait")
			warmPoolComplete(r, "terminate", "ABANDON")
			warmPoolState(t, r, "Warmed:Running")
			r.original("running")
			r.reopenCloud()
			_, err = r.asg().SetDesiredCapacity(t.Context(), &autoscaling.SetDesiredCapacityInput{AutoScalingGroupName: aws.String(r.name), DesiredCapacity: aws.Int32(1)})
			r.check(err)
			_, err = r.asg().ResumeProcesses(t.Context(), &autoscaling.ResumeProcessesInput{AutoScalingGroupName: aws.String(r.name), ScalingProcesses: []string{"Launch"}})
			r.check(err)
			r.untilState("InService")
			r.original("running")
			pool, err := r.asg().DescribeWarmPool(t.Context(), &autoscaling.DescribeWarmPoolInput{AutoScalingGroupName: aws.String(r.name)})
			r.check(err)
			if len(pool.Instances) != 0 || aws.ToInt32(r.group().DesiredCapacity) != 1 {
				t.Fatalf("abandoned return was not reused as active capacity: %+v", pool)
			}
			_, err = r.asg().SetDesiredCapacity(t.Context(), &autoscaling.SetDesiredCapacityInput{AutoScalingGroupName: aws.String(r.name), DesiredCapacity: aws.Int32(0)})
			r.check(err)
			warmPoolState(t, r, "Warmed:Pending:Wait")
			warmPoolComplete(r, "terminate", "CONTINUE")
			warmPoolState(t, r, "Warmed:Running")
			_, err = r.asg().DeleteWarmPool(t.Context(), &autoscaling.DeleteWarmPoolInput{AutoScalingGroupName: aws.String(r.name), ForceDelete: aws.Bool(true)})
			r.check(err)
			warmPoolState(t, r, "Warmed:Terminating:Wait")
			r.original("running")
			_, err = r.asg().DeleteWarmPool(t.Context(), &autoscaling.DeleteWarmPoolInput{AutoScalingGroupName: aws.String(r.name), ForceDelete: aws.Bool(true)})
			r.check(err)
			warmPoolState(t, r, "Warmed:Terminating:Wait")
			r.original("running")
			warmPoolComplete(r, "terminate", "CONTINUE")
			r.untilTerminationAdmitted()
		})
	}
}
