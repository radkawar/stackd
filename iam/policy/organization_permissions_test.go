package policy

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestOrganizationPotentialPermissions(t *testing.T) {
	// AWS Organizations requires an allow at each level of the hierarchy:
	// https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html
	parse := func(document string) *PermissionSummary {
		t.Helper()
		summary, err := ParsePermissionSummary([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		return summary
	}
	full := parse(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	s3 := parse(`{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)
	sqs := parse(`{"Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*"}}`)
	denyS3 := parse(`{"Statement":{"Effect":"Deny","Action":"s3:*","Resource":"*"}}`)
	conditional := parse(`{"Statement":{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/restricted"}}}}`)
	resources := map[string][]string{"s3:GetObject": {"arn:${Partition}:s3:::${BucketName}/${ObjectName}"}, "sqs:SendMessage": {"arn:${Partition}:sqs:${Region}:${Account}:${QueueName}"}}
	cases := []struct {
		name   string
		levels [][]*PermissionSummary
		want   []string
	}{
		{"management unrestricted", nil, []string{"s3:GetObject", "sqs:SendMessage"}},
		{"empty root denies", [][]*PermissionSummary{{}}, nil},
		{"empty intermediate denies", [][]*PermissionSummary{{full}, {}, {full}}, nil},
		{"union within root", [][]*PermissionSummary{{s3, sqs}, {full}}, []string{"s3:GetObject", "sqs:SendMessage"}},
		{"intersection with child", [][]*PermissionSummary{{s3, sqs}, {s3}}, []string{"s3:GetObject"}},
		{"root deny prevails", [][]*PermissionSummary{{full, denyS3}, {s3, sqs}}, []string{"sqs:SendMessage"}},
		{"child deny prevails", [][]*PermissionSummary{{full}, {full, denyS3}}, []string{"sqs:SendMessage"}},
		{"deny alone does not allow others", [][]*PermissionSummary{{denyS3}}, nil},
		{"conditional deny remains potential", [][]*PermissionSummary{{full}, {full, conditional}}, []string{"s3:GetObject", "sqs:SendMessage"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := PotentialActions(t.Context(), tt.levels, resources)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(actual, tt.want) {
				t.Fatalf("actions=%v want %v", actual, tt.want)
			}
		})
	}
}

func TestOrganizationPotentialPermissionsNeedCommonResource(t *testing.T) {
	parse := func(document string) *PermissionSummary {
		t.Helper()
		summary, err := ParsePermissionSummary([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		return summary
	}
	first := parse(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-a/*"}}`)
	disjoint := parse(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-b/*"}}`)
	overlap := parse(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-a/public/*"}}`)
	exclusion := parse(`{"Statement":{"Effect":"Deny","Action":"s3:GetObject","NotResource":"arn:aws:s3:::bucket-a/private/*"}}`)
	resources := map[string][]string{"s3:GetObject": {"arn:${Partition}:s3:::${BucketName}/${ObjectName}"}}
	for _, tt := range []struct {
		name   string
		levels [][]*PermissionSummary
		want   bool
	}{
		{"disjoint allows", [][]*PermissionSummary{{first}, {disjoint}}, false},
		{"overlapping allows", [][]*PermissionSummary{{first}, {overlap}}, true},
		{"deny intersection", [][]*PermissionSummary{{first, exclusion}, {overlap}}, false},
		{"within level alternative restores overlap", [][]*PermissionSummary{{first}, {disjoint, overlap}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := PotentialActions(t.Context(), tt.levels, resources)
			if err != nil {
				t.Fatal(err)
			}
			if (len(actual) > 0) != tt.want {
				t.Fatalf("actions=%v want allowed %v", actual, tt.want)
			}
		})
	}
}

type cancelOnCheckContext struct {
	context.Context
	cancel     context.CancelFunc
	checks, at int
}

func (c *cancelOnCheckContext) Err() error {
	c.checks++
	if c.checks == c.at {
		c.cancel()
	}
	return c.Context.Err()
}

func TestPotentialPermissionsCancellation(t *testing.T) {
	summary, err := ParsePermissionSummary([]byte(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-a/*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-a/*"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resources := map[string][]string{"s3:GetObject": {"arn:${Partition}:s3:::${BucketName}/${ObjectName}"}}
	// The third check starts the resource search. Cancel later to prove that
	// traversal, not merely the outer action loop, observes cancellation.
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &cancelOnCheckContext{Context: base, cancel: cancel, at: 12}
	actions, err := PotentialActions(ctx, [][]*PermissionSummary{{summary}}, resources)
	if !errors.Is(err, context.Canceled) || actions != nil {
		t.Fatalf("result=%v err=%v", actions, err)
	}
	for _, levels := range [][][]*PermissionSummary{nil, {{summary}}, {{}}} {
		actions, err := PotentialActions(base, levels, resources)
		if !errors.Is(err, context.Canceled) || actions != nil {
			t.Fatalf("cancelled hierarchy result=%v err=%v", actions, err)
		}
	}
	if granted, err := summary.GrantsService(base, "s3", nil); !errors.Is(err, context.Canceled) || granted {
		t.Fatalf("cancelled discovery=%v %v", granted, err)
	}
}
