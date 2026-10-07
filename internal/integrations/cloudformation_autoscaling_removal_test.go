package integrations

import (
	"errors"
	"reflect"
	"testing"

	api "stackd/internal/awsapi/autoscaling"
	ebsapi "stackd/internal/awsapi/ebs"
	ec2api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscommands"
	"stackd/internal/awswire"
	asg "stackd/internal/services/autoscaling"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ebs"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
)

// Native EBS completion, image registration and EC2 DryRun admit real group
// configuration without installing an execution engine or launching a guest.
func cfnScalingGroupDependencies(t *testing.T, f *cfnComputeOwnerFixture) (StepFunctionsCommands, string, string) {
	t.Helper()
	volumes := ebs.New(ebs.Config{Clock: f.base.clock, Authorizer: f.base.roles.Authorizer})
	t.Cleanup(func() { _ = volumes.Close() })
	repository := ec2.NewMemoryRepository(nil)
	instances := ec2.New(ec2.Config{Repository: repository, Clock: f.base.clock, Authorizer: f.base.roles.Authorizer, ImageSnapshots: volumes, InstanceVolumes: volumes, Volumes: volumes})
	t.Cleanup(func() { _ = instances.Close() })
	f.base.adapter.EC2 = instances
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": instances, "ebs": volumes, "iam": f.identity})
	snapshot, err := cfnComputeCall[ebsapi.StartSnapshotOutput](f.base.root, commands, "ebs", "StartSnapshot", map[string]any{"VolumeSize": 8})
	if err != nil {
		t.Fatal(err)
	}
	if err := cfnComputeRun(f.base.root, commands, "ebs", "CompleteSnapshot", map[string]any{"SnapshotId": cfnComputeValue(snapshot.SnapshotId), "ChangedBlocksCount": 0}); err != nil {
		t.Fatal(err)
	}
	if err := f.base.clock.Advance(ebs.CompletionDelay + ebs.ReadinessDelay); err != nil {
		t.Fatal(err)
	}
	if _, err := volumes.JobDriver().RunDue(f.base.root, 100); err != nil {
		t.Fatal(err)
	}
	image, err := cfnComputeCall[ec2api.RegisterImageOutput](f.base.root, commands, "ec2", "RegisterImage", map[string]any{
		"Name": "declarative-group-image", "Architecture": "x86_64", "VirtualizationType": "hvm", "RootDeviceName": "/dev/xvda",
		"BlockDeviceMappings": []any{map[string]any{"DeviceName": "/dev/xvda", "Ebs": map[string]any{"SnapshotId": cfnComputeValue(snapshot.SnapshotId), "VolumeSize": 8, "VolumeType": "gp3"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	template, err := cfnComputeCall[ec2api.CreateLaunchTemplateOutput](f.base.root, commands, "ec2", "CreateLaunchTemplate", map[string]any{"LaunchTemplateName": "declarative-group", "LaunchTemplateData": map[string]any{"ImageId": cfnComputeValue(image.ImageId), "InstanceType": "t3.micro"}})
	if err != nil {
		t.Fatal(err)
	}
	vpc, err := cfnComputeCall[ec2api.CreateVpcOutput](f.base.root, commands, "ec2", "CreateVpc", map[string]any{"CidrBlock": "10.85.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := cfnComputeCall[ec2api.CreateSubnetOutput](f.base.root, commands, "ec2", "CreateSubnet", map[string]any{"VpcId": cfnComputeValue(vpc.Vpc.VpcId), "CidrBlock": "10.85.1.0/24", "AvailabilityZone": "us-east-1a"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := cfnComputeCall[ec2api.CreateSubnetOutput](f.base.root, commands, "ec2", "CreateSubnet", map[string]any{"VpcId": cfnComputeValue(vpc.Vpc.VpcId), "CidrBlock": "10.85.2.0/24", "AvailabilityZone": "us-east-1b"})
	if err != nil {
		t.Fatal(err)
	}
	// Default subnet designation is a native dependency fixture: the public
	// CreateDefaultSubnet action is not implemented. Selection still runs the
	// real EC2 DescribeAvailabilityZones/DescribeSubnets and linked-role IAM.
	key := ec2.ResourceKey{Scope: ec2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: cfnComputeValue(second.Subnet.SubnetId)}
	if err := repository.Update(f.base.root, func(tx ec2.Transaction) error {
		subnet, err := tx.Subnet(key)
		if err != nil {
			return err
		}
		subnet.Data.DefaultForAz = new(ec2api.Boolean(true))
		return tx.PutSubnet(subnet)
	}); err != nil {
		t.Fatal(err)
	}
	// Include both native dependency identifiers without copying their state.
	return commands, cfnComputeValue(template.LaunchTemplate.LaunchTemplateId), cfnComputeValue(first.Subnet.SubnetId)
}

func cfnScalingGroupSettings(g *api.AutoScalingGroup) api.AutoScalingGroup {
	return api.AutoScalingGroup{
		DefaultCooldown: g.DefaultCooldown, DefaultInstanceWarmup: g.DefaultInstanceWarmup,
		HealthCheckType: g.HealthCheckType, HealthCheckGracePeriod: g.HealthCheckGracePeriod,
		TerminationPolicies: g.TerminationPolicies, NewInstancesProtectedFromScaleIn: g.NewInstancesProtectedFromScaleIn,
		ServiceLinkedRoleARN: g.ServiceLinkedRoleARN, AvailabilityZoneDistribution: g.AvailabilityZoneDistribution,
		AvailabilityZoneImpairmentPolicy: g.AvailabilityZoneImpairmentPolicy, CapacityRebalance: g.CapacityRebalance,
		CapacityReservationSpecification: g.CapacityReservationSpecification, Context: g.Context,
		DesiredCapacityType: g.DesiredCapacityType, DeletionProtection: g.DeletionProtection,
		InstanceLifecyclePolicy: g.InstanceLifecyclePolicy, InstanceMaintenancePolicy: g.InstanceMaintenancePolicy,
		MaxInstanceLifetime: g.MaxInstanceLifetime, MixedInstancesPolicy: g.MixedInstancesPolicy,
		LaunchConfigurationName: g.LaunchConfigurationName, PlacementGroup: g.PlacementGroup,
	}
}

func TestComputeGroupDeclarativeRemovalsRestoreNativeCreateDefaults(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNComputeOwnerFixture(t, backend, nil)
			dependencies, template, subnet := cfnScalingGroupDependencies(t, f)
			role, err := cfnComputeCall[iamapi.CreateServiceLinkedRoleOutput](f.base.root, dependencies, "iam", "CreateServiceLinkedRole", map[string]any{"AWSServiceName": asg.ServicePrincipal, "CustomSuffix": "declarative"})
			if err != nil {
				t.Fatal(err)
			}
			minimal := cloudformation.Properties{"AutoScalingGroupName": "declarative-workers", "MinSize": 0, "MaxSize": 3, "LaunchTemplate": map[string]any{"LaunchTemplateId": template, "Version": "1"}, "VPCZoneIdentifier": []any{subnet}}
			configured := cfnComputeCopy(minimal, "AutoScalingGroupName", "MinSize", "MaxSize", "LaunchTemplate", "VPCZoneIdentifier")
			for key, value := range (cloudformation.Properties{
				"DesiredCapacity": 0, "Cooldown": 49, "DefaultInstanceWarmup": 180, "HealthCheckType": "ELB", "HealthCheckGracePeriod": 300,
				"TerminationPolicies": []any{"NewestInstance"}, "NewInstancesProtectedFromScaleIn": true,
				"ServiceLinkedRoleARN": cfnComputeValue(role.Role.Arn), "AvailabilityZoneDistribution": map[string]any{"CapacityDistributionStrategy": "balanced-only"},
				"CapacityRebalance": false, "CapacityReservationSpecification": map[string]any{"CapacityReservationPreference": "default"},
				"Context": "configured", "DesiredCapacityType": "units", "DeletionProtection": "prevent-force-deletion", "MaxInstanceLifetime": 86400,
				"InstanceLifecyclePolicy":        map[string]any{"RetentionTriggers": map[string]any{"TerminateHookAbandon": "retain"}},
				"LifecycleHookSpecificationList": []any{map[string]any{"LifecycleHookName": "retain", "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING", "DefaultResult": "ABANDON", "HeartbeatTimeout": 30}},
			}) {
				configured[key] = value
			}
			group := f.request(cfnASGGroupType, "Group", configured)
			f.create(t, &group)
			f.native(t, "autoscaling", "CreateAutoScalingGroup", map[string]any{"AutoScalingGroupName": "omission-baseline", "MinSize": 0, "MaxSize": 3, "LaunchTemplate": minimal["LaunchTemplate"], "VPCZoneIdentifier": subnet})
			baseline, err := cfnASGGet(f.base.root, f.commands, "omission-baseline")
			if err != nil {
				t.Fatal(err)
			}
			// Native omission is merge, including protection and every optional
			// setting; a consumer removal must not change that public contract.
			f.native(t, "autoscaling", "UpdateAutoScalingGroup", map[string]any{"AutoScalingGroupName": group.PhysicalID, "DesiredCapacity": 2})
			before, err := cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil || before.NewInstancesProtectedFromScaleIn == nil || !bool(*before.NewInstancesProtectedFromScaleIn) || int(*before.DefaultCooldown) != 49 || cfnComputeValue(before.ServiceLinkedRoleARN) != cfnComputeValue(role.Role.Arn) {
				t.Fatalf("ordinary native merge cleared configured settings: %+v %v", before, err)
			}
			f.reopen(t)
			update := group
			update.Previous = configured
			update.Properties = minimal
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatalf("declarative removal: %v", err)
			}
			actual, err := cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfnScalingGroupSettings(actual), cfnScalingGroupSettings(baseline)) {
				t.Fatalf("removed settings differ from real native creation omission: actual=%+v baseline=%+v", cfnScalingGroupSettings(actual), cfnScalingGroupSettings(baseline))
			}
			if int(*actual.DesiredCapacity) != 2 || cfnComputeValue(actual.VPCZoneIdentifier) != subnet || cfnComputeValue(actual.LaunchTemplate.LaunchTemplateId) != template {
				t.Fatalf("removal reset desired capacity or retained placement/launch mode: %+v", actual)
			}
			// Removed deletion protection must affect the native control, not
			// merely a projected CloudFormation model.
			f.native(t, "autoscaling", "SuspendProcesses", map[string]any{"AutoScalingGroupName": group.PhysicalID, "ScalingProcesses": []string{"Launch"}})
			// Omitted desired capacity still clamps to bounds in both directions.
			lower := cfnComputeCopy(minimal, "AutoScalingGroupName", "MinSize", "MaxSize", "LaunchTemplate", "VPCZoneIdentifier")
			lower["MaxSize"] = 1
			update.Previous, update.Properties = minimal, lower
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatal(err)
			}
			actual, err = cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil || int(*actual.DesiredCapacity) != 1 {
				t.Fatalf("omitted desired capacity did not clamp down: %+v %v", actual, err)
			}
			raised := cfnComputeCopy(minimal, "AutoScalingGroupName", "MinSize", "MaxSize", "LaunchTemplate", "VPCZoneIdentifier")
			raised["MinSize"] = 2
			update.Previous, update.Properties = lower, raised
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatal(err)
			}
			actual, err = cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil || int(*actual.DesiredCapacity) != 2 {
				t.Fatalf("omitted desired capacity did not clamp up: %+v %v", actual, err)
			}
			// Rollback restores the explicit model and its native defaults/role.
			update.Previous, update.Properties = raised, configured
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatal(err)
			}
			actual, err = cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil || !reflect.DeepEqual(cfnScalingGroupSettings(actual), cfnScalingGroupSettings(before)) {
				t.Fatalf("rollback did not restore configured native settings: %+v %v", actual, err)
			}
			update.Previous, update.Properties = configured, minimal
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatal(err)
			}
			f.native(t, "autoscaling", "DeleteAutoScalingGroup", map[string]any{"AutoScalingGroupName": group.PhysicalID, "ForceDelete": true})
		})
	}
}

func TestComputeGroupPlacementRemovalChangesNativePlacementMode(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNComputeOwnerFixture(t, backend, nil)
			dependencies, template, subnet := cfnScalingGroupDependencies(t, f)
			p := cloudformation.Properties{"AutoScalingGroupName": "placement-workers", "MinSize": 0, "MaxSize": 2, "DesiredCapacity": 0, "LaunchTemplate": map[string]any{"LaunchTemplateId": template, "Version": "1"}, "VPCZoneIdentifier": []any{subnet}, "AvailabilityZones": []any{"us-east-1a"}}
			group := f.request(cfnASGGroupType, "Group", p)
			f.create(t, &group)
			f.reopen(t)
			zones := cfnComputeCopy(p, "AutoScalingGroupName", "MinSize", "MaxSize", "DesiredCapacity", "LaunchTemplate")
			zones["AvailabilityZones"] = []any{"us-east-1b"}
			update := group
			update.Previous, update.Properties = p, zones
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatalf("subnet-to-zone removal retained old subnet constraints: %v", err)
			}
			selected, err := cfnComputeCall[ec2api.DescribeSubnetsOutput](f.base.root, dependencies, "ec2", "DescribeSubnets", map[string]any{"Filters": []any{map[string]any{"Name": "default-for-az", "Values": []string{"true"}}, map[string]any{"Name": "availability-zone", "Values": []string{"us-east-1b"}}}})
			if err != nil || len(selected.Subnets) != 1 {
				t.Fatalf("native default subnet fixture: %+v %v", selected, err)
			}
			actual, err := cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil || cfnComputeValue(actual.VPCZoneIdentifier) != cfnComputeValue(selected.Subnets[0].SubnetId) || !reflect.DeepEqual(actual.AvailabilityZones, api.AvailabilityZones{"us-east-1b"}) || !reflect.DeepEqual(actual.AvailabilityZoneIds, api.AvailabilityZoneIds{api.XmlStringMaxLen255(cfnComputeValue(selected.Subnets[0].AvailabilityZoneId))}) {
				t.Fatalf("zone mode did not use native default placement: %+v %v", actual, err)
			}
			// Reverse mode removal must discard the old zone selection as well.
			subnets := cfnComputeCopy(p, "AutoScalingGroupName", "MinSize", "MaxSize", "DesiredCapacity", "LaunchTemplate", "VPCZoneIdentifier")
			update.Previous, update.Properties = zones, subnets
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatal(err)
			}
			actual, err = cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil || cfnComputeValue(actual.VPCZoneIdentifier) != subnet || !reflect.DeepEqual(actual.AvailabilityZones, api.AvailabilityZones{"us-east-1a"}) {
				t.Fatalf("subnet mode retained old zone constraints: %+v %v", actual, err)
			}
			// Removing all placement is still the native invalid omission. A
			// declarative seam must not retain stale subnets to bypass validation.
			missing := cfnComputeCopy(subnets, "AutoScalingGroupName", "MinSize", "MaxSize", "DesiredCapacity", "LaunchTemplate")
			update.Previous, update.Properties = subnets, missing
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err == nil {
				t.Fatal("missing placement kept a stale native placement")
			}
			unchanged, err := cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil || !reflect.DeepEqual(actual, unchanged) {
				t.Fatalf("rejected placement removal changed native state: %+v %v", unchanged, err)
			}
			missingLaunch := cfnComputeCopy(subnets, "AutoScalingGroupName", "MinSize", "MaxSize", "DesiredCapacity", "VPCZoneIdentifier")
			update.Previous, update.Properties = subnets, missingLaunch
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err == nil {
				t.Fatal("missing launch mode retained the old native template")
			}
			unchanged, err = cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil || !reflect.DeepEqual(actual, unchanged) {
				t.Fatalf("rejected launch removal changed native state: %+v %v", unchanged, err)
			}
			// A persisted legacy-mode fixture must not contaminate a supported
			// template cutover. Legacy creation/execution remains unsupported.
			key := asg.GroupKey{Scope: f.base.group.Key.Scope, Name: group.PhysicalID}
			if err := f.asgRepo.Update(f.base.root, func(tx asg.Transaction) error {
				legacy, err := tx.Group(key)
				if err != nil {
					return err
				}
				legacy.Data.LaunchTemplate = nil
				legacy.Data.LaunchConfigurationName = new(api.XmlStringMaxLen255("legacy-configuration"))
				return tx.PutGroup(legacy)
			}); err != nil {
				t.Fatal(err)
			}
			legacy := cfnComputeCopy(missingLaunch, "AutoScalingGroupName", "MinSize", "MaxSize", "DesiredCapacity", "VPCZoneIdentifier")
			legacy["LaunchConfigurationName"] = "legacy-configuration"
			update.Previous, update.Properties = legacy, subnets
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatalf("template cutover retained old launch-mode constraints: %v", err)
			}
			actual, err = cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil || actual.LaunchConfigurationName != nil || actual.LaunchTemplate == nil || cfnComputeValue(actual.LaunchTemplate.LaunchTemplateId) != template {
				t.Fatalf("template cutover failed to remove old launch mode: %+v %v", actual, err)
			}
		})
	}
}

func TestComputeGroupDeclarativeRemovalRetainsCurrentIAMAndPrivateAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNComputeOwnerFixture(t, backend, nil)
			dependencies, template, subnet := cfnScalingGroupDependencies(t, f)
			configured := cloudformation.Properties{"AutoScalingGroupName": "authority-workers", "MinSize": 0, "MaxSize": 2, "DesiredCapacity": 0, "LaunchTemplate": map[string]any{"LaunchTemplateId": template, "Version": "1"}, "VPCZoneIdentifier": []any{subnet}, "NewInstancesProtectedFromScaleIn": true}
			group := f.request(cfnASGGroupType, "Group", configured)
			f.create(t, &group)
			f.reopen(t)
			removed := cfnComputeCopy(configured, "AutoScalingGroupName", "MinSize", "MaxSize", "DesiredCapacity", "LaunchTemplate", "VPCZoneIdentifier")
			update := group
			update.Previous, update.Properties = configured, removed
			update.Token = "foreign-incarnation"
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err == nil {
				t.Fatal("declarative removal bypassed private group authority")
			}
			putPolicy := func(document string) {
				t.Helper()
				if err := cfnComputeRun(f.base.root, dependencies, "iam", "PutUserPolicy", map[string]any{"UserName": f.base.user.UserName, "PolicyName": "scaling-removal", "PolicyDocument": document}); err != nil {
					t.Fatal(err)
				}
			}
			putPolicy(`{"Statement":{"Effect":"Allow","Action":"autoscaling:*","Resource":"*"}}`)
			update.Token = group.Token
			update.CloudControl = true
			barrier := &cfnScalingMutationBarrier{owner: f.groups, operation: "UpdateAutoScalingGroup", before: func() {
				putPolicy(`{"Statement":[{"Effect":"Allow","Action":"autoscaling:Describe*","Resource":"*"},{"Effect":"Deny","Action":"autoscaling:UpdateAutoScalingGroup","Resource":"*"}]}`)
			}}
			handlers := CloudFormationComputeServiceHandlers(NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"autoscaling": barrier}))
			_, err := handlers[group.Type].Update(f.base.caller, update)
			var denied *awswire.Error
			if barrier.before != nil || !errors.As(err, &denied) || denied.Code != "AccessDenied" {
				t.Fatalf("removal did not recheck current native IAM after adapter read: %v", err)
			}
			actual, err := cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil || actual.NewInstancesProtectedFromScaleIn == nil || !bool(*actual.NewInstancesProtectedFromScaleIn) {
				t.Fatalf("rejected removal changed native scale-in protection: %+v %v", actual, err)
			}
			// A denied declarative mutation must not erase its existing private
			// claim; the admitted incarnation can still replay under current IAM.
			replay := group
			replay.PhysicalID = ""
			if out, err := f.handlers[group.Type].Create(f.base.root, replay); err != nil || out.PhysicalID != group.PhysicalID {
				t.Fatalf("rejected removal lost admitted private incarnation: %+v %v", out, err)
			}
		})
	}
}

func TestComputeGroupRemovedCustomRoleUsesAuthoritativeDefaultRole(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNComputeOwnerFixture(t, backend, nil)
			dependencies, template, subnet := cfnScalingGroupDependencies(t, f)
			role, err := cfnComputeCall[iamapi.CreateServiceLinkedRoleOutput](f.base.root, dependencies, "iam", "CreateServiceLinkedRole", map[string]any{"AWSServiceName": asg.ServicePrincipal, "CustomSuffix": "standalone"})
			if err != nil {
				t.Fatal(err)
			}
			configured := cloudformation.Properties{"AutoScalingGroupName": "custom-role-workers", "MinSize": 0, "MaxSize": 2, "DesiredCapacity": 0, "LaunchTemplate": map[string]any{"LaunchTemplateId": template, "Version": "1"}, "VPCZoneIdentifier": []any{subnet}, "ServiceLinkedRoleARN": cfnComputeValue(role.Role.Arn)}
			group := f.request(cfnASGGroupType, "Group", configured)
			f.create(t, &group)
			// The group has only ever used the custom role. Remove the unused
			// default fixture so omission has to admit the real IAM-owned role.
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			if err := f.base.iam.Update(f.base.root, func(tx iam.WriteTx) error { return tx.DeleteRole(scope, "AWSServiceRoleForAutoScaling") }); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			update := group
			update.Previous = configured
			update.Properties = cfnComputeCopy(configured, "AutoScalingGroupName", "MinSize", "MaxSize", "DesiredCapacity", "LaunchTemplate", "VPCZoneIdentifier")
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatalf("removed custom role did not admit native default: %v", err)
			}
			actual, err := cfnASGGet(f.base.root, f.commands, group.PhysicalID)
			if err != nil || cfnComputeValue(actual.ServiceLinkedRoleARN) != "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling" {
				t.Fatalf("custom role removal retained wrong execution role: %+v %v", actual, err)
			}
			if err := f.base.iam.View(f.base.root, func(tx iam.ReadTx) error {
				owned, err := tx.Role(scope, "AWSServiceRoleForAutoScaling")
				if err == nil && (owned.ServiceLinkedService != asg.ServicePrincipal || owned.Arn != cfnComputeValue(actual.ServiceLinkedRoleARN) || len(owned.IdentityPolicies.Attached) == 0) {
					t.Fatalf("reset role was not admitted by authoritative IAM: %+v", owned)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
