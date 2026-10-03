package iam_test

import (
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/clock"
	"stackd/internal/services/iam"
)

type accountAuthorizationFixture struct {
	CleanupVerified bool `json:"cleanup_verified"`
	CaptureComplete bool `json:"capture_complete"`
	Observations    []struct {
		Case          string                      `json:"case"`
		Operation     string                      `json:"operation"`
		Code          string                      `json:"code"`
		Input         json.RawMessage             `json:"input"`
		Counts        map[string]int              `json:"counts"`
		OwnedEntities map[string][]map[string]any `json:"owned_entities"`
	} `json:"observations"`
}

func loadAccountAuthorizationFixture(t *testing.T) accountAuthorizationFixture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/iam/account_reporting.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture accountAuthorizationFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.CleanupVerified || !fixture.CaptureComplete {
		t.Fatal("AWS reporting probe capture or cleanup is incomplete")
	}
	return fixture
}

func (f accountAuthorizationFixture) entities(t *testing.T, prefix, section string) []map[string]any {
	t.Helper()
	var result []map[string]any
	seen := make(map[string]bool)
	for _, observation := range f.Observations {
		if !strings.HasPrefix(observation.Case, prefix+":page") {
			continue
		}
		for _, entity := range observation.OwnedEntities[section] {
			arn := authorizationFixtureString(t, entity, "Arn")
			if seen[arn] {
				t.Fatalf("fixture repeats entity %s across pages of %s", arn, prefix)
			}
			seen[arn] = true
			result = append(result, entity)
		}
	}
	if len(result) == 0 {
		t.Fatalf("fixture has no %s entities for %s", section, prefix)
	}
	return result
}

func TestAccountAuthorizationDetailsAWSFixtureReplay(t *testing.T) {
	fixture := loadAccountAuthorizationFixture(t)
	source := clock.NewManual(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	client := clientFor(t, iam.NewWithConfig(iam.Config{Clock: source}), "123456789012", "us-east-1")
	users := fixture.entities(t, "bare_user", "UserDetailList")
	groups := fixture.entities(t, "bare_group", "GroupDetailList")
	roles := fixture.entities(t, "bare_role", "RoleDetailList")
	policies := fixture.entities(t, "unattached_policy_details", "Policies")
	for _, user := range users {
		_, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String(authorizationFixtureString(t, user, "UserName")), Path: aws.String(authorizationFixtureString(t, user, "Path")), Tags: authorizationFixtureTags(t, user["Tags"])})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, group := range groups {
		_, err := client.CreateGroup(t.Context(), &sdkiam.CreateGroupInput{GroupName: aws.String(authorizationFixtureString(t, group, "GroupName")), Path: aws.String(authorizationFixtureString(t, group, "Path"))})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range roles {
		name := authorizationFixtureString(t, role, "RoleName")
		_, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String(name), Path: aws.String(authorizationFixtureString(t, role, "Path")), AssumeRolePolicyDocument: aws.String(authorizationFixtureJSON(t, role["AssumeRolePolicyDocument"])), Tags: authorizationFixtureTags(t, role["Tags"]), Description: aws.String("description omitted from account report"), MaxSessionDuration: aws.Int32(7200)})
		if err != nil {
			t.Fatal(err)
		}
		profiles, ok := role["InstanceProfileList"].([]any)
		if !ok {
			t.Fatal("fixture role lacks profile list")
		}
		for _, raw := range profiles {
			profile, ok := raw.(map[string]any)
			if !ok {
				t.Fatal("invalid fixture profile")
			}
			profileName := authorizationFixtureString(t, profile, "InstanceProfileName")
			_, err := client.CreateInstanceProfile(t.Context(), &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String(profileName), Path: aws.String(authorizationFixtureString(t, profile, "Path")), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("profile tags omitted from report")}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.AddRoleToInstanceProfile(t.Context(), &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String(profileName), RoleName: aws.String(name)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, policy := range policies {
		versions, ok := policy["PolicyVersionList"].([]any)
		if !ok || len(versions) == 0 {
			t.Fatal("fixture policy lacks versions")
		}
		// Live AWS returns newest versions first; replay their creation oldest first.
		versions = slices.Clone(versions)
		slices.Reverse(versions)
		var arn *string
		for index, raw := range versions {
			version, ok := raw.(map[string]any)
			if !ok {
				t.Fatal("invalid fixture policy version")
			}
			document := authorizationFixtureJSON(t, version["Document"])
			if index == 0 {
				created, err := client.CreatePolicy(t.Context(), &sdkiam.CreatePolicyInput{PolicyName: aws.String(authorizationFixtureString(t, policy, "PolicyName")), Path: aws.String(authorizationFixtureString(t, policy, "Path")), PolicyDocument: aws.String(document), Description: aws.String("policy description omitted from account report"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("policy tags omitted from report")}}})
				if err != nil {
					t.Fatal(err)
				}
				arn = created.Policy.Arn
				continue
			}
			if err := source.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			_, err := client.CreatePolicyVersion(t.Context(), &sdkiam.CreatePolicyVersionInput{PolicyArn: arn, PolicyDocument: aws.String(document), SetAsDefault: version["IsDefaultVersion"] == true})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	out, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: authorizationDetailLocalFilters, MaxItems: aws.Int32(1000)})
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []struct {
		name     string
		actual   any
		expected []map[string]any
	}{
		{"UserDetailList", out.UserDetailList, users}, {"GroupDetailList", out.GroupDetailList, groups},
		{"RoleDetailList", out.RoleDetailList, roles}, {"Policies", out.Policies, policies},
	} {
		t.Run(section.name, func(t *testing.T) {
			assertAuthorizationFixtureEntities(t, section.actual, section.expected)
		})
	}
	configuredUsers := fixture.entities(t, "configured_user", "UserDetailList")
	configuredGroups := fixture.entities(t, "configured_group", "GroupDetailList")
	configuredRoles := fixture.entities(t, "configured_role", "RoleDetailList")
	for _, section := range []struct {
		kind     string
		entities []map[string]any
	}{{"User", configuredUsers}, {"Group", configuredGroups}, {"Role", configuredRoles}} {
		for _, entity := range section.entities {
			name := authorizationFixtureString(t, entity, section.kind+"Name")
			inline, ok := entity[section.kind+"PolicyList"].([]any)
			if !ok {
				t.Fatal("configured fixture lacks inline policies")
			}
			for _, raw := range inline {
				policy := raw.(map[string]any)
				policyName, document := aws.String(authorizationFixtureString(t, policy, "PolicyName")), aws.String(authorizationFixtureJSON(t, policy["PolicyDocument"]))
				var err error
				switch section.kind {
				case "User":
					_, err = client.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: aws.String(name), PolicyName: policyName, PolicyDocument: document})
				case "Group":
					_, err = client.PutGroupPolicy(t.Context(), &sdkiam.PutGroupPolicyInput{GroupName: aws.String(name), PolicyName: policyName, PolicyDocument: document})
				case "Role":
					_, err = client.PutRolePolicy(t.Context(), &sdkiam.PutRolePolicyInput{RoleName: aws.String(name), PolicyName: policyName, PolicyDocument: document})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, raw := range entity["AttachedManagedPolicies"].([]any) {
				arn := aws.String(authorizationFixtureString(t, raw.(map[string]any), "PolicyArn"))
				var err error
				switch section.kind {
				case "User":
					_, err = client.AttachUserPolicy(t.Context(), &sdkiam.AttachUserPolicyInput{UserName: aws.String(name), PolicyArn: arn})
				case "Group":
					_, err = client.AttachGroupPolicy(t.Context(), &sdkiam.AttachGroupPolicyInput{GroupName: aws.String(name), PolicyArn: arn})
				case "Role":
					_, err = client.AttachRolePolicy(t.Context(), &sdkiam.AttachRolePolicyInput{RoleName: aws.String(name), PolicyArn: arn})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if boundary, ok := entity["PermissionsBoundary"].(map[string]any); ok {
				arn := aws.String(authorizationFixtureString(t, boundary, "PermissionsBoundaryArn"))
				var err error
				switch section.kind {
				case "User":
					_, err = client.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: aws.String(name), PermissionsBoundary: arn})
				case "Role":
					_, err = client.PutRolePermissionsBoundary(t.Context(), &sdkiam.PutRolePermissionsBoundaryInput{RoleName: aws.String(name), PermissionsBoundary: arn})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for _, user := range configuredUsers {
		for _, group := range user["GroupList"].([]any) {
			if _, err := client.AddUserToGroup(t.Context(), &sdkiam.AddUserToGroupInput{UserName: aws.String(authorizationFixtureString(t, user, "UserName")), GroupName: aws.String(group.(string))}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, role := range configuredRoles {
		for _, raw := range role["InstanceProfileList"].([]any) {
			profile := raw.(map[string]any)
			name := aws.String(authorizationFixtureString(t, profile, "InstanceProfileName"))
			if _, err := client.CreateInstanceProfile(t.Context(), &sdkiam.CreateInstanceProfileInput{InstanceProfileName: name, Path: aws.String(authorizationFixtureString(t, profile, "Path")), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("profile tags omitted from report")}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.AddRoleToInstanceProfile(t.Context(), &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: name, RoleName: aws.String(authorizationFixtureString(t, role, "RoleName"))}); err != nil {
				t.Fatal(err)
			}
		}
	}
	configured, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeUser, types.EntityTypeGroup, types.EntityTypeRole}, MaxItems: aws.Int32(1000)})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("configured_user", func(t *testing.T) { assertAuthorizationFixtureEntities(t, configured.UserDetailList, configuredUsers) })
	t.Run("configured_group", func(t *testing.T) {
		assertAuthorizationFixtureEntities(t, configured.GroupDetailList, configuredGroups)
	})
	t.Run("configured_role", func(t *testing.T) { assertAuthorizationFixtureEntities(t, configured.RoleDetailList, configuredRoles) })
	negativeCases := 0
	for _, observation := range fixture.Observations {
		if observation.Operation != "GetAccountAuthorizationDetails" || observation.Code != "ValidationError" || strings.Contains(string(observation.Input), "<opaque-marker>") {
			continue
		}
		negativeCases++
		t.Run(observation.Case, func(t *testing.T) {
			var input sdkiam.GetAccountAuthorizationDetailsInput
			if err := json.Unmarshal(observation.Input, &input); err != nil {
				t.Fatal(err)
			}
			output, err := client.GetAccountAuthorizationDetails(t.Context(), &input)
			requireCode(t, err, observation.Code)
			if output != nil {
				t.Fatal("invalid fixture request returned report data")
			}
		})
	}
	if negativeCases < 4 {
		t.Fatalf("only %d recorded service error cases replayed", negativeCases)
	}
}

func assertAuthorizationFixtureEntities(t *testing.T, output any, expected []map[string]any) {
	t.Helper()
	var actual []map[string]any
	if err := json.Unmarshal([]byte(authorizationFixtureJSON(t, output)), &actual); err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(expected) {
		t.Fatalf("entity count=%d; AWS owned count=%d", len(actual), len(expected))
	}
	for _, want := range expected {
		arn := authorizationFixtureString(t, want, "Arn")
		index := slices.IndexFunc(actual, func(got map[string]any) bool { return got["Arn"] == arn })
		if index < 0 {
			t.Fatalf("missing AWS fixture entity %s", arn)
		}
		gotNormalized, wantNormalized := normalizeAuthorizationFixture(t, "", actual[index]), normalizeAuthorizationFixture(t, "", want)
		if !reflect.DeepEqual(gotNormalized, wantNormalized) {
			t.Fatalf("%s differs from captured AWS shape/content\ngot:  %s\nwant: %s", arn, authorizationFixtureJSON(t, gotNormalized), authorizationFixtureJSON(t, wantNormalized))
		}
	}
}

func authorizationFixtureString(t *testing.T, value map[string]any, key string) string {
	t.Helper()
	result, ok := value[key].(string)
	if !ok || result == "" {
		t.Fatalf("fixture lacks nonempty string %s", key)
	}
	return result
}

func authorizationFixtureJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func authorizationFixtureTags(t *testing.T, raw any) []types.Tag {
	t.Helper()
	var tags []types.Tag
	if err := json.Unmarshal([]byte(authorizationFixtureJSON(t, raw)), &tags); err != nil {
		t.Fatal(err)
	}
	return tags
}

// Normalize only generated IDs/timestamps and the SDK's encoded document form.
// Field presence, names, paths, ARNs, tags, documents, counters and version order
// remain exact comparisons against the owned-resource AWS capture.
func normalizeAuthorizationFixture(t *testing.T, key string, value any) any {
	t.Helper()
	if value == nil {
		return nil
	}
	switch key {
	case "UserId", "GroupId", "RoleId", "PolicyId", "InstanceProfileId":
		if text, ok := value.(string); !ok || text == "" {
			t.Fatalf("missing %s", key)
		}
		return "<generated-id>"
	case "CreateDate", "UpdateDate", "LastUsedDate":
		text, ok := value.(string)
		if !ok {
			t.Fatalf("invalid timestamp %s=%v", key, value)
		}
		if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
			t.Fatal(err)
		}
		return "<timestamp>"
	case "Document", "PolicyDocument", "AssumeRolePolicyDocument":
		if encoded, ok := value.(string); ok {
			decoded, err := url.QueryUnescape(encoded)
			if err != nil || decoded == encoded {
				t.Fatalf("policy document is not URL-encoded: %q %v", encoded, err)
			}
			if err := json.Unmarshal([]byte(decoded), &value); err != nil {
				t.Fatal(err)
			}
		}
		// Policy contents are opaque to output normalization: a condition named
		// UserId or CreateDate must retain its actual value.
		return value
	}
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any)
		for childKey, child := range value {
			if child != nil {
				out[childKey] = normalizeAuthorizationFixture(t, childKey, child)
			}
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, child := range value {
			out[i] = normalizeAuthorizationFixture(t, "", child)
		}
		switch key {
		case "AttachedManagedPolicies", "GroupList", "Tags", "InstanceProfileList":
			// AWS does not document a sort for these relationships. Sanitizing
			// resource names can also change their apparent lexical order.
			slices.SortFunc(out, func(a, b any) int {
				return strings.Compare(authorizationFixtureJSON(t, a), authorizationFixtureJSON(t, b))
			})
		}
		return out
	default:
		return value
	}
}

func TestAccountAuthorizationDetailsAWSManagedPolicyUsage(t *testing.T) {
	fixture := loadAccountAuthorizationFixture(t)
	var policyARN string
	for _, policy := range fixture.entities(t, "aws_boundary_only_details", "Policies") {
		if policy["PolicyName"] == "AWSCloud9SSMInstanceProfile" {
			if policy["AttachmentCount"] != float64(0) || policy["PermissionsBoundaryUsageCount"] != float64(1) {
				t.Fatal("fixture does not prove boundary-only AWS policy inclusion")
			}
			policyARN = authorizationFixtureString(t, policy, "Arn")
		}
	}
	if policyARN == "" {
		t.Fatal("fixture lacks boundary-only AWS policy")
	}
	service := iam.New()
	client := clientFor(t, service, "123456789012", "us-east-1")
	user, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("Cloud9User")})
	if err != nil {
		t.Fatal(err)
	}
	assertPolicies := func(client *sdkiam.Client, count int, attachments, boundaries int32) {
		t.Helper()
		out, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeAWSManagedPolicy}})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Policies) != count || out.IsTruncated {
			t.Fatalf("referenced AWS policy count=%d truncated=%v", len(out.Policies), out.IsTruncated)
		}
		if count == 1 && (aws.ToString(out.Policies[0].Arn) != policyARN || aws.ToInt32(out.Policies[0].AttachmentCount) != attachments || aws.ToInt32(out.Policies[0].PermissionsBoundaryUsageCount) != boundaries) {
			t.Fatalf("AWS policy usage=%+v", out.Policies[0])
		}
	}
	assertPolicies(client, 0, 0, 0)
	if _, err := client.AttachUserPolicy(t.Context(), &sdkiam.AttachUserPolicyInput{UserName: user.User.UserName, PolicyArn: aws.String(policyARN)}); err != nil {
		t.Fatal(err)
	}
	assertPolicies(client, 1, 1, 0)
	assertPolicies(clientFor(t, service, "999999999999", "us-east-1"), 0, 0, 0)
	if _, err := client.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: user.User.UserName, PermissionsBoundary: aws.String(policyARN)}); err != nil {
		t.Fatal(err)
	}
	assertPolicies(client, 1, 1, 1)
	if _, err := client.DetachUserPolicy(t.Context(), &sdkiam.DetachUserPolicyInput{UserName: user.User.UserName, PolicyArn: aws.String(policyARN)}); err != nil {
		t.Fatal(err)
	}
	assertPolicies(client, 1, 0, 1)
	if _, err := client.DeleteUserPermissionsBoundary(t.Context(), &sdkiam.DeleteUserPermissionsBoundaryInput{UserName: user.User.UserName}); err != nil {
		t.Fatal(err)
	}
	assertPolicies(client, 0, 0, 0)
}

func TestAccountAuthorizationDetailsAWSFamilyOrder(t *testing.T) {
	fixture := loadAccountAuthorizationFixture(t)
	client := clientFor(t, iam.New(), "123456789012", "us-east-1")
	if _, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("one-user")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateGroup(t.Context(), &sdkiam.CreateGroupInput{GroupName: aws.String("one-group")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("one-role"), AssumeRolePolicyDocument: aws.String(trustEC2)}); err != nil {
		t.Fatal(err)
	}
	mustCreatePolicy(t, client, "one-policy")
	counts := func(out *sdkiam.GetAccountAuthorizationDetailsOutput) map[string]int {
		return map[string]int{"UserDetailList": len(out.UserDetailList), "RoleDetailList": len(out.RoleDetailList), "GroupDetailList": len(out.GroupDetailList), "Policies": len(out.Policies)}
	}
	checked := 0
	for _, observation := range fixture.Observations {
		if !strings.HasPrefix(observation.Case, "section_order_") {
			continue
		}
		checked++
		t.Run(observation.Case, func(t *testing.T) {
			var input sdkiam.GetAccountAuthorizationDetailsInput
			if err := json.Unmarshal(observation.Input, &input); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				out, err := client.GetAccountAuthorizationDetails(t.Context(), &input)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(counts(out), observation.Counts) {
					t.Fatalf("family priority for %v=%v; AWS=%v", input.Filter, counts(out), observation.Counts)
				}
				slices.Reverse(input.Filter)
			}
		})
	}
	if checked != 3 {
		t.Fatalf("expected three recorded pairwise ordering cases, got %d", checked)
	}
	for _, test := range []struct {
		name    string
		filters []types.EntityType
	}{
		{"default then explicit all", nil},
		{"reordered explicit all", []types.EntityType{types.EntityTypeLocalManagedPolicy, types.EntityTypeGroup, types.EntityTypeRole, types.EntityTypeUser, types.EntityTypeAWSManagedPolicy}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := &sdkiam.GetAccountAuthorizationDetailsInput{Filter: test.filters, MaxItems: aws.Int32(1)}
			for index, family := range []string{"UserDetailList", "RoleDetailList", "GroupDetailList", "Policies"} {
				out, err := client.GetAccountAuthorizationDetails(t.Context(), input)
				if err != nil {
					t.Fatal(err)
				}
				if len(authorizationDetailARNs(out)) != 1 || counts(out)[family] != 1 || out.IsTruncated != (index < 3) {
					t.Fatalf("page %d=%v truncated=%v; want one %s", index, counts(out), out.IsTruncated, family)
				}
				if index == 0 {
					_, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: authorizationDetailLocalFilters, MaxItems: aws.Int32(1), Marker: out.Marker})
					requireCode(t, err, "ValidationError")
				}
				input.Filter = []types.EntityType{types.EntityTypeAWSManagedPolicy, types.EntityTypeGroup, types.EntityTypeLocalManagedPolicy, types.EntityTypeUser, types.EntityTypeRole}
				input.Marker = out.Marker
			}
		})
	}
}
