package iam_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

type linkedUsage struct {
	mu      sync.Mutex
	usage   []iam.ServiceLinkedRoleUsage
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (u *linkedUsage) WithServiceLinkedRoleUsage(ctx context.Context, _ iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	u.once.Do(func() {
		if u.entered != nil {
			close(u.entered)
		}
	})
	if u.release != nil {
		select {
		case <-u.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return fn(ctx, u.usage)
}

func registerAutoScalingUsage(t *testing.T, s *iam.Service, usage iam.ServiceLinkedRoleUsageProvider) {
	t.Helper()
	for _, template := range s.ServiceLinkedRoleTemplates() {
		if template.ServiceName == "autoscaling.amazonaws.com" {
			if err := s.RegisterServiceLinkedRole(template, usage); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("Auto Scaling template missing")
}

func waitLinkedStatus(t *testing.T, c *sdkiam.Client, id string, want types.DeletionTaskStatusType) *sdkiam.GetServiceLinkedRoleDeletionStatusOutput {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out, err := c.GetServiceLinkedRoleDeletionStatus(context.Background(), &sdkiam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: aws.String(id)})
		if err != nil {
			t.Fatal(err)
		}
		if out.Status == want {
			return out
		}
		if out.Status == types.DeletionTaskStatusTypeFailed || out.Status == types.DeletionTaskStatusTypeSucceeded {
			t.Fatalf("terminal status %s, want %s: %+v", out.Status, want, out.Reason)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("deletion worker did not reach expected status")
	return nil
}

func TestServiceLinkedRoleAWSLifecycle(t *testing.T) {
	ctx := context.Background()
	s := iam.New()
	t.Cleanup(func() { _ = s.Close() })
	usage := &linkedUsage{entered: make(chan struct{}), release: make(chan struct{})}
	registerAutoScalingUsage(t, s, usage)
	c := clientFor(t, s, "123456789012", "us-east-1")
	data, err := os.ReadFile("testdata/service_linked_roles_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Name   string `json:"name"`
			Error  string `json:"error"`
			Role   struct{ Path, RoleName string }
			Status string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	wantErrors := make(map[string]string)
	for _, observation := range fixture.Observations {
		if observation.Error != "" {
			wantErrors[observation.Name] = observation.Error
		}
	}
	membershipData, err := os.ReadFile("testdata/service_linked_membership_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var membership struct {
		Observations []struct {
			Name  string `json:"name"`
			Error string `json:"error"`
		}
	}
	if err := json.Unmarshal(membershipData, &membership); err != nil {
		t.Fatal(err)
	}
	for _, observation := range membership.Observations {
		wantErrors[observation.Name] = observation.Error
	}
	out, err := c.CreateServiceLinkedRole(ctx, &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("autoscaling.amazonaws.com"), CustomSuffix: aws.String("stackdprobe")})
	if err != nil {
		t.Fatal(err)
	}
	name := aws.ToString(out.Role.RoleName)
	if name != fixture.Observations[0].Role.RoleName || aws.ToString(out.Role.Path) != fixture.Observations[0].Role.Path || len(aws.ToString(out.Role.RoleId)) != 21 || out.Role.MaxSessionDuration != nil {
		t.Fatalf("create response differs from AWS: %+v", out.Role)
	}
	doc, err := url.QueryUnescape(aws.ToString(out.Role.AssumeRolePolicyDocument))
	if err != nil || !strings.Contains(doc, `"autoscaling.amazonaws.com"`) {
		t.Fatalf("trust = %s, %v", doc, err)
	}
	_, err = c.CreateServiceLinkedRole(ctx, &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("autoscaling.amazonaws.com"), CustomSuffix: aws.String("stackdprobe")})
	requireCode(t, err, wantErrors["duplicate-create"])
	attached, err := c.ListAttachedRolePolicies(ctx, &sdkiam.ListAttachedRolePoliciesInput{RoleName: aws.String(name)})
	if err != nil || len(attached.AttachedPolicies) != 1 || aws.ToString(attached.AttachedPolicies[0].PolicyArn) != "arn:aws:iam::aws:policy/aws-service-role/AutoScalingServiceRolePolicy" {
		t.Fatalf("policy source: %+v, %v", attached, err)
	}
	inline, err := c.ListRolePolicies(ctx, &sdkiam.ListRolePoliciesInput{RoleName: aws.String(name)})
	if err != nil || len(inline.PolicyNames) != 0 {
		t.Fatalf("unexpected inline permissions: %+v, %v", inline, err)
	}
	_, err = c.UpdateRoleDescription(ctx, &sdkiam.UpdateRoleDescriptionInput{RoleName: aws.String(name), Description: aws.String("edited")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.UpdateRole(ctx, &sdkiam.UpdateRoleInput{RoleName: aws.String(name), Description: aws.String("edited again")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.TagRole(ctx, &sdkiam.TagRoleInput{RoleName: aws.String(name), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("platform")}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("linked-role-profile")}); err != nil {
		t.Fatal(err)
	}
	ordinary, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("ordinary"), AssumeRolePolicyDocument: aws.String(trustEC2)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.DeleteServiceLinkedRole(ctx, &sdkiam.DeleteServiceLinkedRoleInput{RoleName: ordinary.Role.RoleName})
	requireCode(t, err, wantErrors["delete-ordinary-as-service-linked"])
	negative := []struct {
		name string
		call func() error
	}{
		{"update-duration", func() error {
			_, err := c.UpdateRole(ctx, &sdkiam.UpdateRoleInput{RoleName: aws.String(name), MaxSessionDuration: aws.Int32(7200)})
			return err
		}},
		{"update-trust", func() error {
			_, err := c.UpdateAssumeRolePolicy(ctx, &sdkiam.UpdateAssumeRolePolicyInput{RoleName: aws.String(name), PolicyDocument: aws.String(trustEC2)})
			return err
		}},
		{"put-inline-policy", func() error {
			_, err := c.PutRolePolicy(ctx, &sdkiam.PutRolePolicyInput{RoleName: aws.String(name), PolicyName: aws.String("test"), PolicyDocument: aws.String(allowRead)})
			return err
		}},
		{"delete-inline", func() error {
			_, err := c.DeleteRolePolicy(ctx, &sdkiam.DeleteRolePolicyInput{RoleName: aws.String(name), PolicyName: aws.String("absent")})
			return err
		}},
		{"attach-policy", func() error {
			_, err := c.AttachRolePolicy(ctx, &sdkiam.AttachRolePolicyInput{RoleName: aws.String(name), PolicyArn: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess")})
			return err
		}},
		{"detach-policy", func() error {
			_, err := c.DetachRolePolicy(ctx, &sdkiam.DetachRolePolicyInput{RoleName: aws.String(name), PolicyArn: attached.AttachedPolicies[0].PolicyArn})
			return err
		}},
		{"put-boundary", func() error {
			_, err := c.PutRolePermissionsBoundary(ctx, &sdkiam.PutRolePermissionsBoundaryInput{RoleName: aws.String(name), PermissionsBoundary: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess")})
			return err
		}},
		{"delete-boundary", func() error {
			_, err := c.DeleteRolePermissionsBoundary(ctx, &sdkiam.DeleteRolePermissionsBoundaryInput{RoleName: aws.String(name)})
			return err
		}},
		{"delete-role-directly", func() error {
			_, err := c.DeleteRole(ctx, &sdkiam.DeleteRoleInput{RoleName: aws.String(name)})
			return err
		}},
		{"add-to-instance-profile", func() error {
			_, err := c.AddRoleToInstanceProfile(ctx, &sdkiam.AddRoleToInstanceProfileInput{RoleName: aws.String(name), InstanceProfileName: aws.String("linked-role-profile")})
			return err
		}},
		{"remove-from-instance-profile", func() error {
			_, err := c.RemoveRoleFromInstanceProfile(ctx, &sdkiam.RemoveRoleFromInstanceProfileInput{RoleName: aws.String(name), InstanceProfileName: aws.String("linked-role-profile")})
			return err
		}},
	}
	for _, test := range negative {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			requireCode(t, err, wantErrors[test.name])
			var typed *types.UnmodifiableEntityException
			if !errors.As(err, &typed) {
				t.Fatalf("SDK did not decode modeled protected-role error: %v", err)
			}
		})
	}
	for _, service := range []string{"ecs.amazonaws.com", "elasticloadbalancing.amazonaws.com", "rds.amazonaws.com"} {
		_, err := c.CreateServiceLinkedRole(ctx, &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String(service), CustomSuffix: aws.String("probe")})
		requireCode(t, err, wantErrors["suffix-"+service])
	}
	del, err := c.DeleteServiceLinkedRole(ctx, &sdkiam.DeleteServiceLinkedRoleInput{RoleName: aws.String(strings.ToLower(name))})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-usage.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker never ran")
	}
	repeat, err := c.DeleteServiceLinkedRole(ctx, &sdkiam.DeleteServiceLinkedRoleInput{RoleName: aws.String(name)})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(repeat.DeletionTaskId) != aws.ToString(del.DeletionTaskId) {
		t.Fatal("pending deletion request not idempotent")
	}
	status, err := c.GetServiceLinkedRoleDeletionStatus(ctx, &sdkiam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: del.DeletionTaskId})
	if err != nil || status.Status != types.DeletionTaskStatusTypeInProgress {
		t.Fatalf("pending status: %+v, %v", status, err)
	}
	close(usage.release)
	waitLinkedStatus(t, c, aws.ToString(del.DeletionTaskId), types.DeletionTaskStatusTypeSucceeded)
	_, err = c.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: aws.String(name)})
	requireCode(t, err, wantErrors["get-deleted-role"])
	_, err = c.GetServiceLinkedRoleDeletionStatus(ctx, &sdkiam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: aws.String("not-a-task")})
	requireCode(t, err, wantErrors["malformed-task"])
	unknown := "task/aws-service-role/autoscaling.amazonaws.com/" + name + "/00000000-0000-0000-0000-000000000000"
	_, err = c.GetServiceLinkedRoleDeletionStatus(ctx, &sdkiam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: aws.String(unknown)})
	requireCode(t, err, wantErrors["unknown-task"])
	other := clientFor(t, s, "222222222222", "us-east-1")
	_, err = other.GetServiceLinkedRoleDeletionStatus(ctx, &sdkiam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: del.DeletionTaskId})
	requireCode(t, err, "NoSuchEntity")
	regional := clientFor(t, s, "123456789012", "eu-west-1")
	if _, err := regional.GetServiceLinkedRoleDeletionStatus(ctx, &sdkiam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: del.DeletionTaskId}); err != nil {
		t.Fatalf("IAM tasks should be region global: %v", err)
	}
	_, err = c.CreateServiceLinkedRole(ctx, &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("autoscaling.amazonaws.com"), CustomSuffix: aws.String("stackdprobe")})
	if err != nil {
		t.Fatal(err)
	}
	// Terminal jobs are retained across reuse of the role name and cannot
	// mutate the newly created identity when their status is read.
	waitLinkedStatus(t, c, aws.ToString(del.DeletionTaskId), types.DeletionTaskStatusTypeSucceeded)
	if _, err := c.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: aws.String(name)}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceLinkedRoleUsageFailureAndRetry(t *testing.T) {
	s := iam.New()
	t.Cleanup(func() { _ = s.Close() })
	u := &linkedUsage{usage: []iam.ServiceLinkedRoleUsage{{Region: "eu-west-1", ResourceARNs: []string{"arn:aws:autoscaling:eu-west-1:123456789012:autoScalingGroup:group"}}}}
	registerAutoScalingUsage(t, s, u)
	c := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	created, err := c.CreateServiceLinkedRole(ctx, &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("autoscaling.amazonaws.com")})
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.DeleteServiceLinkedRole(ctx, &sdkiam.DeleteServiceLinkedRoleInput{RoleName: created.Role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	out := waitLinkedStatus(t, c, aws.ToString(first.DeletionTaskId), types.DeletionTaskStatusTypeFailed)
	if out.Reason == nil || len(out.Reason.RoleUsageList) != 1 || aws.ToString(out.Reason.RoleUsageList[0].Region) != "eu-west-1" || len(out.Reason.RoleUsageList[0].Resources) != 1 {
		t.Fatalf("usage failure lost details: %+v", out)
	}
	if _, err := c.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: created.Role.RoleName}); err != nil {
		t.Fatal("failed task removed role", err)
	}
	u.mu.Lock()
	u.usage = nil
	u.mu.Unlock()
	second, err := c.DeleteServiceLinkedRole(ctx, &sdkiam.DeleteServiceLinkedRoleInput{RoleName: created.Role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(first.DeletionTaskId) == aws.ToString(second.DeletionTaskId) {
		t.Fatal("failed deletion retry reused terminal task")
	}
	waitLinkedStatus(t, c, aws.ToString(second.DeletionTaskId), types.DeletionTaskStatusTypeSucceeded)
	waitLinkedStatus(t, c, aws.ToString(first.DeletionTaskId), types.DeletionTaskStatusTypeFailed)
	_, err = c.CreateServiceLinkedRole(ctx, &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("not-supported.amazonaws.com")})
	requireCode(t, err, "NotImplemented")
}

func TestServiceLinkedRoleCreateDescriptionMatchesAWS(t *testing.T) {
	data, err := os.ReadFile("testdata/service_linked_description_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Name string `json:"name"`
			Role map[string]json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Observations) != 2 {
		t.Fatal("description fixture missing observations")
	}
	if _, present := fixture.Observations[0].Role["Description"]; present {
		t.Fatal("AWS create response now includes description; revisit the response contract")
	}
	var description string
	if err := json.Unmarshal(fixture.Observations[1].Role["Description"], &description); err != nil {
		t.Fatal(err)
	}
	s := iam.New()
	t.Cleanup(func() { _ = s.Close() })
	c := clientFor(t, s, "123456789012", "us-east-1")
	created, err := c.CreateServiceLinkedRole(context.Background(), &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("autoscaling.amazonaws.com"), CustomSuffix: aws.String("description"), Description: aws.String(description)})
	if err != nil {
		t.Fatal(err)
	}
	if created.Role.Description != nil || created.Role.MaxSessionDuration != nil {
		t.Fatalf("creation leaked fields AWS omits: %+v", created.Role)
	}
	get, err := c.GetRole(context.Background(), &sdkiam.GetRoleInput{RoleName: created.Role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(get.Role.Description) != description || aws.ToInt32(get.Role.MaxSessionDuration) != 3600 || get.Role.RoleLastUsed == nil {
		t.Fatalf("GetRole lost stored fields: %+v", get.Role)
	}
}
