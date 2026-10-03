package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

type effectivePolicyObservation struct {
	Case, Action, Actor, Code string
	Input                     json.RawMessage
	Output                    struct {
		EffectivePolicy *struct {
			PolicyContent        string
			LastUpdatedTimestamp float64
			TargetID             string `json:"TargetId"`
		}
	}
}

func TestOrganizationsEffectivePolicyAWSAndRecovery(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/organizations_effective_policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct{ Observations []effectivePolicyObservation }
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			suite := t
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "effective.sqlite")
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(suite, path)
			}
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			cloud, c, closeCloud := creationEventCloud(suite, backends, source)
			f := organizationFixture(t, c, source)
			member := f.account(t, f.rootID, "effective-member")
			organization, err := f.org.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
			if err != nil {
				t.Fatal(err)
			}
			owner := *organization.Organization.MasterAccountId
			replacer := strings.NewReplacer("111111111111", owner, "222222222222", member, "r-example", f.rootID, "o-exampleorgid", *organization.Organization.Id)
			policies := map[string]string{}
			documents := map[string]string{}
			previousNative := map[string]float64{}
			previousLocal := map[string]time.Time{}
			for _, row := range capture.Observations {
				// Malformed wire inputs use the direct/gateway SDK replay in the
				// provider package; client validation must not hide those checks.
				if row.Case == "missing-kind" || strings.HasPrefix(row.Case, "invalid-kind-") {
					continue
				}
				t.Run(row.Case, func(t *testing.T) {
					source.Advance(time.Second)
					switch row.Case {
					case "enabled-empty":
						_, err = f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeTagPolicy})
					case "attached-0", "attached-1", "attached-2", "first-reattached":
						index := strings.TrimPrefix(row.Case, "attached-")
						if row.Case == "first-reattached" {
							index = "0"
						}
						target := f.rootID
						if index == "2" {
							target = member
						}
						_, err = f.org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: aws.String(policies[index]), TargetId: &target})
					case "metadata-update":
						_, err = f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: aws.String(policies["0"]), Description: aws.String("Changed metadata only")})
					case "unchanged-content-update":
						_, err = f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: aws.String(policies["0"]), Content: aws.String(documents["0"])})
					case "first-detached":
						_, err = f.org.DetachPolicy(t.Context(), &organizations.DetachPolicyInput{PolicyId: aws.String(policies["0"]), TargetId: &f.rootID})
					}
					if err != nil {
						t.Fatal(err)
					}
					if row.Action == "CreatePolicy" {
						var input organizations.CreatePolicyInput
						if err := json.Unmarshal(row.Input, &input); err != nil {
							t.Fatal(err)
						}
						out, callErr := f.org.CreatePolicy(t.Context(), &input)
						if row.Code != "Success" {
							assertAPIError(t, callErr, row.Code)
							return
						}
						if callErr != nil {
							t.Fatal(callErr)
						}
						if strings.HasPrefix(row.Case, "create-") {
							index := strings.TrimPrefix(row.Case, "create-")
							policies[index], documents[index] = *out.Policy.PolicySummary.Id, *input.Content
						} else if _, err := f.org.DeletePolicy(t.Context(), &organizations.DeletePolicyInput{PolicyId: out.Policy.PolicySummary.Id}); err != nil {
							t.Fatal(err)
						}
						return
					}
					settleEffectivePolicies(t, cloud, source)
					client := f.org
					if row.Actor == "member" {
						client = c.organizations(member, "test")
					}
					if strings.HasPrefix(row.Case, "session-") {
						resource := "arn:aws:organizations::" + owner + ":account/" + *organization.Organization.Id + "/" + member
						conditions := map[string]any{}
						switch row.Case {
						case "session-wrong-arn":
							resource = strings.ReplaceAll(resource, member, owner)
						case "session-resource-owner":
							conditions["StringEquals"] = map[string]string{"aws:ResourceAccount": owner}
						case "session-resource-member":
							conditions["StringEquals"] = map[string]string{"aws:ResourceAccount": member}
						case "session-policy-type":
							conditions["StringEquals"] = map[string]string{"organizations:PolicyType": "TAG_POLICY"}
						}
						policy, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": "organizations:DescribeEffectivePolicy", "Resource": resource, "Condition": conditions}}})
						assumed, callErr := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: aws.String("arn:aws:iam::" + member + ":role/OrganizationAccountAccessRole"), RoleSessionName: aws.String("effective-policy"), Policy: aws.String(string(policy))})
						if callErr != nil {
							t.Fatal(callErr)
						}
						v := assumed.Credentials
						client = organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), HTTPClient: c.server.Client(), RetryMaxAttempts: 1, Credentials: credentials.NewStaticCredentialsProvider(*v.AccessKeyId, *v.SecretAccessKey, *v.SessionToken)})
					}
					var input organizations.DescribeEffectivePolicyInput
					if err := json.Unmarshal([]byte(replacer.Replace(string(row.Input))), &input); err != nil {
						t.Fatal(err)
					}
					out, callErr := client.DescribeEffectivePolicy(t.Context(), &input)
					if row.Code != "Success" {
						assertAPIError(t, callErr, row.Code)
						return
					}
					if callErr != nil {
						t.Fatal(callErr)
					}
					var got, want any
					if err := json.Unmarshal([]byte(*out.EffectivePolicy.PolicyContent), &got); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal([]byte(row.Output.EffectivePolicy.PolicyContent), &want); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("effective content:\ngot %s\nwant %s", *out.EffectivePolicy.PolicyContent, row.Output.EffectivePolicy.PolicyContent)
					}
					if string(out.EffectivePolicy.PolicyType) != "TAG_POLICY" || *out.EffectivePolicy.TargetId != replacer.Replace(row.Output.EffectivePolicy.TargetID) {
						t.Fatal("wrong effective policy target/type", out.EffectivePolicy)
					}
					if out.EffectivePolicy.LastUpdatedTimestamp == nil {
						t.Fatal("missing generation time")
					}
					target := *out.EffectivePolicy.TargetId
					last := *out.EffectivePolicy.LastUpdatedTimestamp
					if before, ok := previousNative[target]; ok {
						nativeChanged := before != row.Output.EffectivePolicy.LastUpdatedTimestamp
						if nativeChanged != last.After(previousLocal[target]) {
							t.Fatalf("generation change = %v, native = %v", last.After(previousLocal[target]), nativeChanged)
						}
					}
					previousNative[target], previousLocal[target] = row.Output.EffectivePolicy.LastUpdatedTimestamp, last
					if row.Case == "attached-2" {
						closeCloud()
						closeDB()
						if backend == "sqlite" {
							backends, closeDB = openSQLiteBackends(suite, path)
						}
						cloud, c, closeCloud = creationEventCloud(suite, backends, source)
						f.cloud, f.org = c, c.organizations("test", "test")
					}
				})
				if t.Failed() {
					break
				}
			}
			if !t.Failed() {
				_, err := f.org.DisablePolicyType(t.Context(), &organizations.DisablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeTagPolicy})
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.org.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy, TargetId: &member})
				assertAPIError(t, err, "EffectivePolicyNotFoundException")
			}
			closeCloud()
			closeDB()
		})
	}
}

func effectivePolicyDocument(key string, values ...string) string {
	data, _ := json.Marshal(map[string]any{"tags": map[string]any{key: map[string]any{"tag_value": map[string]any{"@@assign": values}}}})
	return string(data)
}

func createTagPolicy(t *testing.T, f organizationReportFixture, name, content, target string) string {
	t.Helper()
	out, err := f.org.CreatePolicy(t.Context(), &organizations.CreatePolicyInput{Name: &name, Description: aws.String("effective policy integration"), Type: orgtypes.PolicyTypeTagPolicy, Content: &content})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: out.Policy.PolicySummary.Id, TargetId: &target}); err != nil {
		t.Fatal(err)
	}
	return *out.Policy.PolicySummary.Id
}

func TestOrganizationsEffectivePolicyHierarchyAndIsolation(t *testing.T) {
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	cloud, c, _ := creationEventCloud(t, storage.NewMemory(), source)
	f := organizationFixture(t, c, source)
	_, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeTagPolicy})
	if err != nil {
		t.Fatal(err)
	}
	unit := f.unit(t, f.rootID, "effective-unit")
	member := f.account(t, unit, "effective-hierarchy")
	createTagPolicy(t, f, "root-tags", effectivePolicyDocument("cost", "root"), f.rootID)
	createTagPolicy(t, f, "unit-tags", effectivePolicyDocument("cost", "unit"), unit)
	read := func(want string) {
		t.Helper()
		out, err := f.org.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy, TargetId: &member})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(*out.EffectivePolicy.PolicyContent, fmt.Sprintf(`"tag_value":[%q]`, want)) {
			t.Fatal(*out.EffectivePolicy.PolicyContent)
		}
	}
	settleEffectivePolicies(t, cloud, source)
	read("unit")
	_, err = f.org.MoveAccount(t.Context(), &organizations.MoveAccountInput{AccountId: &member, SourceParentId: &unit, DestinationParentId: &f.rootID})
	if err != nil {
		t.Fatal(err)
	}
	read("unit") // Moving changes inheritance only after publication.
	settleEffectivePolicies(t, cloud, source)
	read("root")
	other := f.cloud.organizations("444444444444", "test")
	_, err = other.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll})
	if err != nil {
		t.Fatal(err)
	}
	_, err = other.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy, TargetId: &member})
	assertAPIError(t, err, "TargetNotFoundException")
}

func settleEffectivePolicies(t *testing.T, cloud *stackd.Stack, source *clock.Manual) {
	t.Helper()
	source.Advance(time.Second)
	if _, err := cloud.RunDueJobs(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
}
