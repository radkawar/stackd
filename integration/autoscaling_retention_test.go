package stackd_test

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	asgtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"stackd"
	"stackd/clock"
	ec2api "stackd/internal/awsapi/ec2"
	"stackd/internal/awstest"
	ebsdomain "stackd/internal/services/ebs"
	ec2store "stackd/storage/ec2"
)

// As in the instance-profile consumer fixtures, only the already-running EC2
// precondition is seeded. Every ASG membership, hook, policy, IAM decision,
// activity and gauge goes through the assembled owners and signed Go SDKs.
// Launch is suspended after attachment: these tests do not invent successful
// QEMU execution. autoscaling_retention_smoke.py proves the replacement guest,
// unchanged original boot, ALB drain and final physical retirement.
type retentionCloud struct {
	t              *testing.T
	clients        cloudClients
	reopen         func() cloudClients
	stack          *stackd.Stack
	clock          *clock.Manual
	repository     ec2store.Repository
	fixture        asgControlFixture
	name, instance string
}

func newRetentionCloud(t *testing.T, backend string, fixture asgControlFixture, policyAtCreate bool) *retentionCloud {
	t.Helper()
	r := &retentionCloud{t: t, fixture: fixture, name: "retained-sdk-group", instance: "i-0123456789abcdef0",
		clock: clock.NewManual(fixture.row(t, "retention-create-zero").StartedAt)}
	r.clients, r.reopen = retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: r.clock}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		r.repository = config.Storage.EC2
		cloud, server := startPublicCloud(t, config)
		r.stack = cloud
		return cloud, server
	})
	direct := ebs.New(ebs.Options{Region: fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	snapshot, err := direct.StartSnapshot(t.Context(), &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1)})
	r.check(err)
	_, err = direct.CompleteSnapshot(t.Context(), &ebs.CompleteSnapshotInput{SnapshotId: snapshot.SnapshotId, ChangedBlocksCount: aws.Int32(0)})
	r.check(err)
	r.advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
	image, err := r.ec2().RegisterImage(t.Context(), &ec2.RegisterImageInput{Name: aws.String("retained-control-image"), Architecture: ec2types.ArchitectureValuesX8664, VirtualizationType: aws.String("hvm"), RootDeviceName: aws.String("/dev/xvda"), BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: aws.String("/dev/xvda"), Ebs: &ec2types.EbsBlockDevice{SnapshotId: snapshot.SnapshotId, VolumeSize: aws.Int32(1), VolumeType: ec2types.VolumeTypeGp3, DeleteOnTermination: aws.Bool(true)}}}})
	r.check(err)
	vpc, err := r.ec2().CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.233.0.0/24")})
	r.check(err)
	subnet, err := r.ec2().CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: aws.String("10.233.0.0/25"), AvailabilityZone: aws.String(fixture.Region + "a")})
	r.check(err)
	template, err := r.ec2().CreateLaunchTemplate(t.Context(), &ec2.CreateLaunchTemplateInput{LaunchTemplateName: aws.String(r.name), LaunchTemplateData: &ec2types.RequestLaunchTemplateData{ImageId: image.ImageId, InstanceType: ec2types.InstanceTypeT3Nano}})
	r.check(err)
	var create autoscaling.CreateAutoScalingGroupInput
	r.check(awstest.DecodeSDK(fixture.row(t, "retention-create-zero").Input, &create))
	create.AutoScalingGroupName = aws.String(r.name)
	create.LaunchTemplate = &asgtypes.LaunchTemplateSpecification{LaunchTemplateId: template.LaunchTemplate.LaunchTemplateId, Version: aws.String("1")}
	create.VPCZoneIdentifier = subnet.Subnet.SubnetId
	if !policyAtCreate {
		create.InstanceLifecyclePolicy = nil
	}
	_, err = r.asg().CreateAutoScalingGroup(t.Context(), &create)
	r.check(err)
	if !policyAtCreate {
		var update autoscaling.UpdateAutoScalingGroupInput
		r.check(awstest.DecodeSDK(fixture.row(t, "retained-policy-restore-retain").Input, &update))
		update.AutoScalingGroupName = aws.String(r.name)
		_, err = r.asg().UpdateAutoScalingGroup(t.Context(), &update)
		r.check(err)
	}
	// A real EC2 owner row/reservation, not an ASG member or activity fixture.
	// AttachInstances must establish the current service-owned relationship.
	scope := ec2store.Scope{Partition: "aws", AccountID: fixture.Account, Region: fixture.Region}
	r.check(r.repository.Update(t.Context(), func(tx ec2store.Transaction) error {
		if err := tx.PutReservation(ec2store.ReservationRecord{Key: ec2store.ResourceKey{Scope: scope, ID: "r-0123456789abcdef0"}, InstanceIDs: []string{r.instance}}); err != nil {
			return err
		}
		return tx.PutInstance(ec2store.InstanceRecord{Key: ec2store.ResourceKey{Scope: scope, ID: r.instance}, ReservationID: "r-0123456789abcdef0", Intent: "observe", Generation: 1, Data: ec2api.Instance{
			InstanceId: new(ec2api.String(r.instance)), ImageId: new(ec2api.String(*image.ImageId)), InstanceType: new(ec2api.InstanceType("t3.nano")),
			VpcId: new(ec2api.String(*vpc.Vpc.VpcId)), SubnetId: new(ec2api.String(*subnet.Subnet.SubnetId)),
			Placement: &ec2api.Placement{AvailabilityZone: new(ec2api.String(*subnet.Subnet.AvailabilityZone))},
			State:     &ec2api.InstanceState{Name: new(ec2api.InstanceStateName("running")), Code: new(ec2api.Integer(16))}, LaunchTime: new(ec2api.DateTime(r.clock.Now())),
		}})
	}))
	_, err = r.asg().AttachInstances(t.Context(), &autoscaling.AttachInstancesInput{AutoScalingGroupName: aws.String(r.name), InstanceIds: []string{r.instance}})
	r.check(err)
	_, err = r.asg().SuspendProcesses(t.Context(), &autoscaling.SuspendProcessesInput{AutoScalingGroupName: aws.String(r.name), ScalingProcesses: []string{"Launch"}})
	r.check(err)
	r.untilState("InService")
	return r
}

func (r *retentionCloud) check(err error) {
	r.t.Helper()
	if err != nil {
		r.t.Fatal(err)
	}
}
func (r *retentionCloud) asg() *autoscaling.Client {
	return asgClient(r.clients, r.fixture.Region, asgRoot(), r.clients.server.Client())
}
func (r *retentionCloud) ec2() *ec2.Client { return asgEC2(r.clients, r.fixture.Region) }
func (r *retentionCloud) advance(d time.Duration) {
	r.t.Helper()
	r.check(r.clock.Advance(d))
	_, err := r.stack.RunDueJobs(r.t.Context(), 100)
	r.check(err)
}
func (r *retentionCloud) group() asgtypes.AutoScalingGroup {
	r.t.Helper()
	out, err := r.asg().DescribeAutoScalingGroups(r.t.Context(), &autoscaling.DescribeAutoScalingGroupsInput{AutoScalingGroupNames: []string{r.name}})
	r.check(err)
	if len(out.AutoScalingGroups) != 1 {
		r.t.Fatalf("group inventory: %+v", out.AutoScalingGroups)
	}
	return out.AutoScalingGroups[0]
}
func (r *retentionCloud) untilState(want string) asgtypes.AutoScalingGroup {
	r.t.Helper()
	for range 12 {
		r.advance(time.Second)
		group := r.group()
		for _, member := range group.Instances {
			if aws.ToString(member.InstanceId) == r.instance && string(member.LifecycleState) == want {
				return group
			}
		}
	}
	r.t.Fatalf("member did not reach %s: %+v", want, r.group())
	return asgtypes.AutoScalingGroup{}
}
func (r *retentionCloud) observedEC2() ec2types.Instance {
	r.t.Helper()
	out, err := r.ec2().DescribeInstances(r.t.Context(), &ec2.DescribeInstancesInput{InstanceIds: []string{r.instance}})
	r.check(err)
	if len(out.Reservations) != 1 || len(out.Reservations[0].Instances) != 1 {
		r.t.Fatalf("EC2 ownership lost: %+v", out.Reservations)
	}
	return out.Reservations[0].Instances[0]
}
func (r *retentionCloud) original(want string) ec2types.Instance {
	r.t.Helper()
	instance := r.observedEC2()
	if instance.State == nil || string(instance.State.Name) != want {
		r.t.Fatalf("original EC2 state: got %+v, want %s", instance.State, want)
	}
	for _, tag := range instance.Tags {
		if aws.ToString(tag.Key) == "aws:autoscaling:groupName" && aws.ToString(tag.Value) == r.name {
			return instance
		}
	}
	r.t.Fatalf("retained original lost its ASG ownership tag: %+v", instance.Tags)
	return instance
}
func (r *retentionCloud) untilTerminationAdmitted() {
	r.t.Helper()
	// These control fixtures have no VM runtime. Assert the EC2 handoff;
	// the actual-guest executable proves physical retirement and group cleanup.
	var state ec2types.InstanceStateName
	for range 12 {
		instance := r.observedEC2()
		if instance.State != nil {
			state = instance.State.Name
		}
		if state == ec2types.InstanceStateNameShuttingDown {
			return
		}
		r.advance(time.Second)
	}
	r.t.Fatalf("EC2 termination was not admitted: state=%s", state)
}

func (r *retentionCloud) reopenCloud() { r.clients = r.reopen() }

func TestAutoScalingNativeRetentionAcrossReopen(t *testing.T) {
	fixture := asgFixture(t, "retention_native")
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range []struct {
			name, capture, evidence string
			explicit                bool
		}{
			{"explicit-abandon-created-policy", "retention_native", "explicit-retention-observed-observed", true},
			{"expired-default-updated-policy", "retention_intervention", "intervention-before", false},
		} {
			t.Run(backend+"/"+scenario.name, func(t *testing.T) {
				r := newRetentionCloud(t, backend, fixture, scenario.explicit)
				observed := asgFixture(t, scenario.capture)
				var native autoscaling.DescribeAutoScalingGroupsOutput
				r.check(awstest.DecodeSDK(observed.row(t, scenario.evidence+"-group").Output, &native))
				if len(native.AutoScalingGroups) != 1 {
					t.Fatal("native retained group missing")
				}
				var retained asgtypes.Instance
				for _, member := range native.AutoScalingGroups[0].Instances {
					if member.LifecycleState == asgtypes.LifecycleStateTerminatingRetained {
						retained = member
						break
					}
				}
				if retained.InstanceId == nil {
					t.Fatal("native retained member missing")
				}
				before := r.original("running")
				_, err := r.asg().EnableMetricsCollection(t.Context(), &autoscaling.EnableMetricsCollectionInput{AutoScalingGroupName: aws.String(r.name), Granularity: aws.String("1Minute"), Metrics: []string{"GroupDesiredCapacity", "GroupInServiceInstances", "GroupTerminatingInstances", "GroupTerminatingRetainedInstances", "GroupTotalInstances"}})
				r.check(err)
				requested, err := r.asg().TerminateInstanceInAutoScalingGroup(t.Context(), &autoscaling.TerminateInstanceInAutoScalingGroupInput{InstanceId: aws.String(r.instance), ShouldDecrementDesiredCapacity: aws.Bool(false)})
				r.check(err)
				if requested.Activity == nil || requested.Activity.ActivityId == nil {
					t.Fatal("termination activity identity missing")
				}
				r.untilState("Terminating:Wait")
				r.reopenCloud()
				if scenario.explicit {
					var complete autoscaling.CompleteLifecycleActionInput
					r.check(awstest.DecodeSDK(fixture.row(t, "explicit-abandon").Input, &complete))
					complete.AutoScalingGroupName, complete.InstanceId, complete.LifecycleActionToken = aws.String(r.name), aws.String(r.instance), nil
					_, err = r.asg().CompleteLifecycleAction(t.Context(), &complete)
					r.check(err)
				} else {
					hooks, err := r.asg().DescribeLifecycleHooks(t.Context(), &autoscaling.DescribeLifecycleHooksInput{AutoScalingGroupName: aws.String(r.name)})
					r.check(err)
					if len(hooks.LifecycleHooks) != 1 {
						t.Fatalf("termination hook: %+v", hooks)
					}
					r.advance(time.Duration(aws.ToInt32(hooks.LifecycleHooks[0].HeartbeatTimeout)+1) * time.Second)
				}
				group := r.untilState(string(retained.LifecycleState))
				if aws.ToInt32(group.DesiredCapacity) != aws.ToInt32(native.AutoScalingGroups[0].DesiredCapacity) {
					t.Fatalf("retention changed desired capacity: %+v", group)
				}
				if group.InstanceLifecyclePolicy == nil || group.InstanceLifecyclePolicy.RetentionTriggers == nil || group.InstanceLifecyclePolicy.RetentionTriggers.TerminateHookAbandon != asgtypes.RetentionActionRetain {
					t.Fatalf("retention policy lost: %+v", group.InstanceLifecyclePolicy)
				}
				r.assertRetainedControls()
				var nativeActivities autoscaling.DescribeScalingActivitiesOutput
				r.check(awstest.DecodeSDK(observed.row(t, scenario.evidence+"-activities").Output, &nativeActivities))
				activityLabel := "explicit-terminate-no-decrement-request"
				if !scenario.explicit {
					activityLabel = "retained-manual-release-false"
				}
				var accepted autoscaling.TerminateInstanceInAutoScalingGroupOutput
				r.check(awstest.DecodeSDK(fixture.row(t, activityLabel).Output, &accepted))
				if accepted.Activity == nil || accepted.Activity.ActivityId == nil {
					t.Fatal("native termination activity identity missing")
				}
				var cancelled *asgtypes.Activity
				for i := range nativeActivities.Activities {
					a := &nativeActivities.Activities[i]
					if a.StatusCode == asgtypes.ScalingActivityStatusCodeCancelled && aws.ToString(a.ActivityId) == *accepted.Activity.ActivityId {
						cancelled = a
						break
					}
				}
				if cancelled == nil || cancelled.EndTime == nil {
					t.Fatal("native terminal cancelled activity missing")
				}
				r.reopenCloud()
				r.advance(10 * time.Minute)
				group = r.untilState("Terminating:Retained")
				if aws.ToInt32(group.DesiredCapacity) != 1 || len(group.Instances) != 1 {
					t.Fatalf("restart counted retained member active: %+v", group)
				}
				after := r.original("running")
				if !aws.ToTime(before.LaunchTime).Equal(aws.ToTime(after.LaunchTime)) {
					t.Fatal("retention replaced original EC2 incarnation")
				}
				out, err := r.asg().DescribeScalingActivities(t.Context(), &autoscaling.DescribeScalingActivitiesInput{AutoScalingGroupName: aws.String(r.name), ActivityIds: []string{*requested.Activity.ActivityId}})
				r.check(err)
				if len(out.Activities) != 1 || out.Activities[0].StatusCode != cancelled.StatusCode || out.Activities[0].StartTime == nil || out.Activities[0].EndTime == nil || out.Activities[0].EndTime.Before(*out.Activities[0].StartTime) {
					t.Fatalf("retained termination is not terminal: %+v", out.Activities)
				}
				// Native retention-metrics-after-cleanup includes the retained
				// guest in total capacity, but not InService or Terminating.
				r.assertGauges(map[string]float64{"GroupDesiredCapacity": 1, "GroupInServiceInstances": 0, "GroupTerminatingInstances": 0, "GroupTerminatingRetainedInstances": 1, "GroupTotalInstances": 1})
				// Force is rejected by the retention policy before it changes
				// any membership; the native failure is preserved in cleanup.
				var force asgControlRow
				for _, row := range fixture.Calls {
					if row.Operation != "DeleteAutoScalingGroup" {
						continue
					}
					var request autoscaling.DeleteAutoScalingGroupInput
					r.check(awstest.DecodeSDK(row.Input, &request))
					if aws.ToBool(request.ForceDelete) && row.Code != "Success" {
						force = row
						break
					}
				}
				if force.Label == "" {
					t.Fatal("native force-retain rejection missing")
				}
				_, err = r.asg().DeleteAutoScalingGroup(t.Context(), &autoscaling.DeleteAutoScalingGroupInput{AutoScalingGroupName: aws.String(r.name), ForceDelete: aws.Bool(true)})
				assertAPIError(t, err, force.Code)
				r.untilState("Terminating:Retained")
				r.original("running")
				// Changing policy applies to future abandonment, not previously
				// retained ownership. Advance and reopen before checking survival.
				var update autoscaling.UpdateAutoScalingGroupInput
				r.check(awstest.DecodeSDK(fixture.row(t, "retained-policy-change-terminate").Input, &update))
				update.AutoScalingGroupName = aws.String(r.name)
				_, err = r.asg().UpdateAutoScalingGroup(t.Context(), &update)
				r.check(err)
				r.reopenCloud()
				r.advance(time.Minute)
				r.untilState("Terminating:Retained")
				r.original("running")
				_, err = r.asg().DeleteAutoScalingGroup(t.Context(), &autoscaling.DeleteAutoScalingGroupInput{AutoScalingGroupName: aws.String(r.name)})
				assertAPIError(t, err, fixture.row(t, "retained-delete-nonforce").Code)
				if scenario.explicit {
					r.check(awstest.DecodeSDK(fixture.row(t, "retained-policy-restore-retain").Input, &update))
					update.AutoScalingGroupName = aws.String(r.name)
					_, err = r.asg().UpdateAutoScalingGroup(t.Context(), &update)
					r.check(err)
					r.releaseWithCurrentAuthority(*requested.Activity.ActivityId)
				} else {
					r.forceAfterPolicyChange()
				}
			})
		}
	}
}

func (r *retentionCloud) assertRetainedControls() {
	t := r.t
	t.Helper()
	before := r.group()
	membership := asgFixture(t, "retention_membership_native")
	row := membership.row(t, "membership-retained-protection-true")
	var protection autoscaling.SetInstanceProtectionInput
	r.check(awstest.DecodeSDK(row.Input, &protection))
	protection.AutoScalingGroupName, protection.InstanceIds = aws.String(r.name), []string{r.instance}
	_, err := r.asg().SetInstanceProtection(t.Context(), &protection)
	assertAPIError(t, err, row.Code)
	if aws.ToInt32(before.DesiredCapacity) > aws.ToInt32(before.MinSize) {
		// The AWS detach guide, not a captured native error, requires false
		// for retained instances. Keep desired above min to distinguish this
		// admission rule from ordinary capacity validation.
		// https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-detach-attach-instances.html
		_, err = r.asg().DetachInstances(t.Context(), &autoscaling.DetachInstancesInput{AutoScalingGroupName: aws.String(r.name), InstanceIds: []string{r.instance}, ShouldDecrementDesiredCapacity: aws.Bool(true)})
		assertAPIError(t, err, "ValidationError")
	}
	contrast := asgFixture(t, "retention_decrement_native")
	var health autoscaling.SetInstanceHealthInput
	r.check(awstest.DecodeSDK(contrast.row(t, "contrast-retained-health-healthy").Input, &health))
	health.InstanceId = aws.String(r.instance)
	_, err = r.asg().SetInstanceHealth(t.Context(), &health)
	r.check(err)
	r.reopenCloud()
	after := r.untilState("Terminating:Retained")
	if aws.ToInt32(after.DesiredCapacity) != aws.ToInt32(before.DesiredCapacity) {
		t.Fatalf("retained health/protection changed desired capacity: %+v", after)
	}
	for _, member := range after.Instances {
		if aws.ToString(member.InstanceId) == r.instance && (aws.ToString(member.HealthStatus) != aws.ToString(health.HealthStatus) || aws.ToBool(member.ProtectedFromScaleIn)) {
			t.Fatalf("retained health/protection mutation: %+v", member)
		}
	}
	r.original("running")
}

func TestAutoScalingNativeRetainedDetachAcrossReopen(t *testing.T) {
	base := asgFixture(t, "retention_native")
	fixture := asgFixture(t, "retention_membership_native")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newRetentionCloud(t, backend, base, true)
			var terminate autoscaling.TerminateInstanceInAutoScalingGroupInput
			r.check(awstest.DecodeSDK(fixture.row(t, "membership-prepare-scale-in-request").Input, &terminate))
			terminate.InstanceId = aws.String(r.instance)
			_, err := r.asg().TerminateInstanceInAutoScalingGroup(t.Context(), &terminate)
			r.check(err)
			r.untilState("Terminating:Wait")
			var abandon autoscaling.CompleteLifecycleActionInput
			r.check(awstest.DecodeSDK(fixture.row(t, "membership-prepare-abandon").Input, &abandon))
			abandon.AutoScalingGroupName, abandon.InstanceId, abandon.LifecycleActionToken = aws.String(r.name), aws.String(r.instance), nil
			_, err = r.asg().CompleteLifecycleAction(t.Context(), &abandon)
			r.check(err)
			r.untilState("Terminating:Retained")
			r.assertRetainedControls()
			before := r.original("running")
			var detach autoscaling.DetachInstancesInput
			r.check(awstest.DecodeSDK(fixture.row(t, "membership-retained-detach-false").Input, &detach))
			detach.AutoScalingGroupName, detach.InstanceIds = aws.String(r.name), []string{r.instance}
			_, err = r.asg().DetachInstances(t.Context(), &detach)
			r.check(err)
			r.reopenCloud()
			for range 12 {
				r.advance(time.Second)
				if len(r.group().Instances) == 0 {
					break
				}
			}
			group := r.group()
			var native autoscaling.DescribeAutoScalingGroupsOutput
			r.check(awstest.DecodeSDK(fixture.row(t, "membership-detached-observed-group").Output, &native))
			if len(native.AutoScalingGroups) != 1 {
				t.Fatal("native detached group missing")
			}
			if len(group.Instances) != 0 || aws.ToInt32(group.DesiredCapacity) != aws.ToInt32(native.AutoScalingGroups[0].DesiredCapacity) {
				t.Fatalf("retained detach changed desired capacity or kept membership: %+v", group)
			}
			row := fixture.row(t, "membership-empty-force-retain")
			_, err = r.asg().DeleteAutoScalingGroup(t.Context(), &autoscaling.DeleteAutoScalingGroupInput{AutoScalingGroupName: aws.String(r.name), ForceDelete: aws.Bool(true)})
			assertAPIError(t, err, row.Code)
			r.reopenCloud()
			if len(r.group().Instances) != 0 {
				t.Fatal("force rejection changed detached membership")
			}
			var deleteGroup autoscaling.DeleteAutoScalingGroupInput
			r.check(awstest.DecodeSDK(fixture.row(t, "membership-empty-ordinary-delete").Input, &deleteGroup))
			deleteGroup.AutoScalingGroupName = aws.String(r.name)
			_, err = r.asg().DeleteAutoScalingGroup(t.Context(), &deleteGroup)
			r.check(err)
			var groups *autoscaling.DescribeAutoScalingGroupsOutput
			for range 12 {
				r.advance(time.Second)
				groups, err = r.asg().DescribeAutoScalingGroups(t.Context(), &autoscaling.DescribeAutoScalingGroupsInput{AutoScalingGroupNames: []string{r.name}})
				r.check(err)
				if len(groups.AutoScalingGroups) == 0 {
					break
				}
			}
			if len(groups.AutoScalingGroups) != 0 {
				t.Fatalf("ordinary deletion retained empty group: %+v", groups)
			}
			r.reopenCloud()
			r.advance(time.Minute)
			after := r.observedEC2()
			if after.State == nil || after.State.Name != ec2types.InstanceStateNameRunning {
				t.Fatalf("detached instance stopped running: %+v", after.State)
			}
			if !aws.ToTime(before.LaunchTime).Equal(aws.ToTime(after.LaunchTime)) {
				t.Fatal("detaching retained instance replaced its EC2 incarnation")
			}
			for _, tag := range after.Tags {
				if aws.ToString(tag.Key) == "aws:autoscaling:groupName" {
					t.Fatalf("detached guest retained group ownership: %+v", after.Tags)
				}
			}
		})
	}
}

func (r *retentionCloud) forceAfterPolicyChange() {
	t := r.t
	t.Helper()
	contrast := asgFixture(t, "retention_decrement_native")
	var request autoscaling.DeleteAutoScalingGroupInput
	r.check(awstest.DecodeSDK(contrast.row(t, "contrast-remedial-force-delete").Input, &request))
	request.AutoScalingGroupName = aws.String(r.name)
	_, err := r.asg().DeleteAutoScalingGroup(t.Context(), &request)
	r.check(err)
	group := r.untilState("Terminating:Wait")
	var native autoscaling.DescribeAutoScalingGroupsOutput
	r.check(awstest.DecodeSDK(contrast.row(t, "contrast-force-group-absent-3").Output, &native))
	if len(native.AutoScalingGroups) != 1 {
		t.Fatal("native force-deleting group missing")
	}
	want := native.AutoScalingGroups[0]
	if aws.ToInt32(group.DesiredCapacity) != aws.ToInt32(want.DesiredCapacity) || aws.ToString(group.Status) != aws.ToString(want.Status) {
		t.Fatalf("retained force deletion did not establish fresh termination: %+v", group)
	}
	r.original("running")
	r.reopenCloud()
	hooks, err := r.asg().DescribeLifecycleHooks(t.Context(), &autoscaling.DescribeLifecycleHooksInput{AutoScalingGroupName: aws.String(r.name)})
	r.check(err)
	if len(hooks.LifecycleHooks) != 1 {
		t.Fatalf("force termination hook missing: %+v", hooks)
	}
	// The hook still defaults to ABANDON. The changed policy must now proceed
	// to the EC2 owner, not retain the same guest and stall group deletion.
	r.advance(time.Duration(aws.ToInt32(hooks.LifecycleHooks[0].HeartbeatTimeout)+1) * time.Second)
	r.untilTerminationAdmitted()
}

func (r *retentionCloud) assertGauges(expected map[string]float64) {
	r.t.Helper()
	at := r.clock.Now().Truncate(time.Minute).Add(time.Minute)
	r.advance(at.Sub(r.clock.Now()))
	r.reopenCloud()
	r.advance(0)
	client := cloudwatch.New(cloudwatch.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	for name, want := range expected {
		out, err := client.GetMetricStatistics(r.t.Context(), &cloudwatch.GetMetricStatisticsInput{Namespace: aws.String("AWS/AutoScaling"), MetricName: aws.String(name), Dimensions: []cwtypes.Dimension{{Name: aws.String("AutoScalingGroupName"), Value: aws.String(r.name)}}, StartTime: aws.Time(at), EndTime: aws.Time(at.Add(time.Minute)), Period: aws.Int32(60), Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage, cwtypes.StatisticSampleCount}})
		r.check(err)
		if len(out.Datapoints) != 1 || aws.ToFloat64(out.Datapoints[0].Average) != want || aws.ToFloat64(out.Datapoints[0].SampleCount) != 1 || out.Datapoints[0].Unit != cwtypes.StandardUnitNone {
			r.t.Fatalf("%s retained/reopened gauge=%+v, want %v once", name, out.Datapoints, want)
		}
	}
}

func (r *retentionCloud) releaseWithCurrentAuthority(previousActivity string) {
	t := r.t
	t.Helper()
	contrast := asgFixture(t, "retention_decrement_native")
	rejected := contrast.row(t, "contrast-retained-manual-release-true")
	var decrement autoscaling.TerminateInstanceInAutoScalingGroupInput
	r.check(awstest.DecodeSDK(rejected.Input, &decrement))
	decrement.InstanceId = aws.String(r.instance)
	before := r.group()
	if aws.ToInt32(before.DesiredCapacity) != 1 || aws.ToInt32(before.MinSize) != 0 {
		t.Fatalf("retained decrement rejection must not be a minimum-size failure: %+v", before)
	}
	_, decrementErr := r.asg().TerminateInstanceInAutoScalingGroup(t.Context(), &decrement)
	assertAPIError(t, decrementErr, rejected.Code)
	r.reopenCloud()
	unchanged := r.untilState("Terminating:Retained")
	if aws.ToInt32(unchanged.DesiredCapacity) != 1 {
		t.Fatalf("rejected retained decrement changed desired capacity: %+v", unchanged)
	}
	r.original("running")
	_, key, secret := r.clients.user(t, r.fixture.Account, "retained-operator")
	arn := aws.ToString(r.group().AutoScalingGroupARN)
	putUserPolicy(t, r.clients.iam("test", "test", ""), "retained-operator", fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"autoscaling:TerminateInstanceInAutoScalingGroup","Resource":%q}}`, arn))
	operator := func() *autoscaling.Client {
		return asgClient(r.clients, r.fixture.Region, aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}, r.clients.server.Client())
	}
	var request autoscaling.TerminateInstanceInAutoScalingGroupInput
	r.check(awstest.DecodeSDK(r.fixture.row(t, "retained-manual-release-false").Input, &request))
	request.InstanceId = aws.String(r.instance)
	// Revoke the same caller's current authority after credentials were issued.
	putUserPolicy(t, r.clients.iam("test", "test", ""), "retained-operator", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"autoscaling:TerminateInstanceInAutoScalingGroup","Resource":%q},{"Effect":"Deny","Action":"autoscaling:TerminateInstanceInAutoScalingGroup","Resource":%q}]}`, arn, arn))
	r.reopenCloud()
	_, err := operator().TerminateInstanceInAutoScalingGroup(t.Context(), &request)
	assertAPIError(t, err, "AccessDenied")
	r.advance(time.Minute)
	r.untilState("Terminating:Retained")
	r.original("running")
	putUserPolicy(t, r.clients.iam("test", "test", ""), "retained-operator", fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"autoscaling:TerminateInstanceInAutoScalingGroup","Resource":%q}}`, arn))
	released, err := operator().TerminateInstanceInAutoScalingGroup(t.Context(), &request)
	r.check(err)
	if released.Activity == nil || released.Activity.ActivityId == nil || *released.Activity.ActivityId == previousActivity {
		t.Fatalf("manual release reused terminal activity: %+v", released.Activity)
	}
	group := r.untilState("Terminating:Wait")
	r.original("running")
	if aws.ToInt32(group.DesiredCapacity) != 1 {
		t.Fatalf("manual retained release decremented desired: %+v", group)
	}
	_, err = r.asg().CompleteLifecycleAction(t.Context(), &autoscaling.CompleteLifecycleActionInput{AutoScalingGroupName: aws.String(r.name), LifecycleHookName: aws.String("terminate"), InstanceId: aws.String(r.instance), LifecycleActionResult: aws.String("CONTINUE")})
	r.check(err)
	r.untilTerminationAdmitted()
	_, err = r.asg().RecordLifecycleActionHeartbeat(t.Context(), &autoscaling.RecordLifecycleActionHeartbeatInput{AutoScalingGroupName: aws.String(r.name), LifecycleHookName: aws.String("terminate"), InstanceId: aws.String(r.instance)})
	assertAPIError(t, err, "ValidationError")
}
