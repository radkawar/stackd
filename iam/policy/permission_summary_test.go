package policy

import (
	"fmt"
	"slices"
	"testing"
)

func TestPermissionReportsResourceAndDenySelection(t *testing.T) {
	const object = "arn:aws:s3:::bucket-a/*"
	const other = "arn:aws:s3:::bucket-b/*"
	const objectTemplate = "arn:${Partition}:s3:::${BucketName}/${ObjectName}"
	actions := map[string][]string{"s3:GetObject": {objectTemplate}}
	tests := []struct {
		name, allow, deny string
		list, report      bool
	}{
		{"unrestricted", `"Resource":"*"`, "", true, true},
		{"bucket resource", `"Resource":"arn:aws:s3:::bucket-a"`, "", true, false},
		{"wrong service", `"Resource":"arn:aws:iam::123456789012:user/a"`, "", false, false},
		{"same resource", fmt.Sprintf(`"Resource":%q`, object), fmt.Sprintf(`,"Effect":"Deny","Action":"s3:*","Resource":%q`, object), true, false},
		{"disjoint resource", fmt.Sprintf(`"Resource":%q`, object), fmt.Sprintf(`,"Effect":"Deny","Action":"s3:*","Resource":%q`, other), true, true},
		{"exact action global deny", `"Resource":"*"`, `,"Effect":"Deny","Action":"s3:GetObject","Resource":"*"`, true, false},
		{"service global deny", `"Resource":"*"`, `,"Effect":"Deny","Action":"s3:*","Resource":"*"`, false, false},
		{"conditional deny", `"Resource":"*"`, `,"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"Null":{"aws:username":"true"}}`, true, true},
		{"conditional allow", `"Resource":"*","Condition":{"StringEquals":{"aws:username":"nobody"}}`, "", true, true},
		{"deny except allowed", fmt.Sprintf(`"Resource":%q`, object), fmt.Sprintf(`,"Effect":"Deny","Action":"s3:GetObject","NotResource":%q`, object), true, true},
		{"deny except disjoint", fmt.Sprintf(`"Resource":%q`, object), fmt.Sprintf(`,"Effect":"Deny","Action":"s3:GetObject","NotResource":%q`, other), true, false},
		{"notresource all", `"NotResource":"*"`, "", false, false},
		{"scoped partial deny", `"Resource":"*"`, fmt.Sprintf(`,"Effect":"Deny","Action":"s3:GetObject","Resource":%q`, object), true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			document := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject",` + tt.allow + `}`
			if tt.deny != "" {
				document += `,{` + tt.deny[1:] + `}`
			}
			document += `]}`
			summary, err := ParsePermissionSummary([]byte(document))
			if err != nil {
				t.Fatal(err)
			}
			if got := reportedService(t, summary, "s3", []string{"arn:${Partition}:s3:::${BucketName}", objectTemplate}); got != tt.list {
				t.Errorf("service discovery=%v want %v", got, tt.list)
			}
			if got := len(reportedActions(t, []*PermissionSummary{summary}, actions)) > 0; got != tt.report {
				t.Errorf("report=%v want %v", got, tt.report)
			}
		})
	}
}

func TestPermissionReportsUnionAndNotAction(t *testing.T) {
	parse := func(document string) *PermissionSummary {
		t.Helper()
		s, err := ParsePermissionSummary([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	allow := parse(`{"Statement":{"Effect":"Allow","Action":"S3:GetObject","Resource":"arn:aws:s3:::bucket/?"}}`)
	denyA := parse(`{"Statement":{"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::bucket/a"}}`)
	denyRest := parse(`{"Statement":{"Effect":"Deny","Action":"s3:*","NotResource":"arn:aws:s3:::bucket/a"}}`)
	actions := map[string][]string{"s3:GetObject": {"arn:${Partition}:s3:::${BucketName}/${ObjectName}"}}
	if len(reportedActions(t, []*PermissionSummary{allow, denyA}, actions)) != 1 {
		t.Fatal("partial deny consumed other one-character keys")
	}
	if len(reportedActions(t, []*PermissionSummary{allow, denyA, denyRest}, actions)) != 0 {
		t.Fatal("union of denies failed to cover grant")
	}
	notAction := parse(`{"Statement":{"Effect":"Allow","NotAction":"s3:*","Resource":"*"}}`)
	if reportedService(t, notAction, "s3", nil) || !reportedService(t, notAction, "iam", nil) {
		t.Fatal("NotAction namespace complement")
	}
	if got := reportedActions(t, []*PermissionSummary{notAction}, map[string][]string{"s3:GetObject": nil, "iam:GetUser": nil}); !slices.Equal(got, []string{"iam:GetUser"}) {
		t.Fatal(got)
	}
	unknown := parse(`{"Statement":{"Effect":"Allow","Action":"s3:UnmodeledAction","Resource":"*"}}`)
	if !reportedService(t, unknown, "s3", nil) || len(reportedActions(t, []*PermissionSummary{unknown}, actions)) != 0 {
		t.Fatal("literal namespace selection must not manufacture SAR actions")
	}
}

func TestPermissionSummaryImmutableAndInvalid(t *testing.T) {
	input := []byte(`{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)
	summary, err := ParsePermissionSummary(input)
	if err != nil {
		t.Fatal(err)
	}
	clear(input)
	if !reportedService(t, summary, "s3", nil) {
		t.Fatal("retained mutable document bytes")
	}
	for _, input := range []string{"", `{}`, `{"Statement":[]}`, `{"Statement":{"Effect":"Other","Action":"*","Resource":"*"}}`, `{"Statement":{"Effect":"Allow","Action":"*","NotAction":"*","Resource":"*"}}`} {
		if _, err := ParsePermissionSummary([]byte(input)); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
	if reportedService(t, &PermissionSummary{}, "s3", nil) {
		t.Fatal("zero summary granted")
	}
}

func reportedActions(t *testing.T, summaries []*PermissionSummary, resources map[string][]string) []string {
	t.Helper()
	result, err := PotentialActions(t.Context(), [][]*PermissionSummary{summaries}, resources)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func reportedService(t *testing.T, summary *PermissionSummary, namespace string, templates []string) bool {
	t.Helper()
	result, err := summary.GrantsService(t.Context(), namespace, templates)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
