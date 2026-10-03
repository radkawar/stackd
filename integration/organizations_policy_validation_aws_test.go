package stackd_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	"stackd/storage"
)

func TestOrganizationsPolicyValidationAWS(t *testing.T) {
	for _, name := range []string{"organizations_policy_validation", "organizations_policy_limits", "organizations_policy_limit_details", "organizations_backup_inheritance", "organizations_backup_copy_inheritance", "organizations_backup_copy_duplicates", "organizations_chat_effective"} {
		t.Run(name, func(t *testing.T) { replayPolicyValidationAWS(t, "../testdata/aws/iam/"+name+".json") })
	}
}

func replayPolicyValidationAWS(t *testing.T, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Cleanup      bool
		Observations []struct {
			Case, Action, Code string
			Input, Output      json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil || !capture.Cleanup {
		t.Fatal("incomplete AWS capture", err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			suite := t
			path := filepath.Join(t.TempDir(), "validation.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			cloud, clients, closeCloud := creationEventCloud(t, backends, source)
			f := organizationFixture(t, clients, source)
			member := f.account(t, f.rootID, "validation-member")
			org, err := f.org.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
			if err != nil {
				t.Fatal(err)
			}
			replacements := []string{"111111111111", *org.Organization.MasterAccountId, "222222222222", member, "r-example", f.rootID, "o-exampleorgid", *org.Organization.Id}
			for _, row := range capture.Observations {
				// The wire replay covers missing required fields. Immediate reads
				// can observe the previous native generation; settled reads below
				// compare the actual diagnostics and retained effective document.
				if row.Case == "missing-account" || row.Case == "missing-type" || strings.HasSuffix(row.Case, "-attached") {
					continue
				}
				if !t.Run(row.Case, func(t *testing.T) {
					replacer := strings.NewReplacer(replacements...)
					decode := func(raw json.RawMessage, target any) {
						t.Helper()
						if err := json.Unmarshal([]byte(replacer.Replace(string(raw))), target); err != nil {
							t.Fatal(err)
						}
					}
					var callErr error
					switch row.Action {
					case "EnablePolicyType":
						var in organizations.EnablePolicyTypeInput
						decode(row.Input, &in)
						_, callErr = f.org.EnablePolicyType(t.Context(), &in)
					case "CreatePolicy":
						var in organizations.CreatePolicyInput
						decode(row.Input, &in)
						out, err := f.org.CreatePolicy(t.Context(), &in)
						callErr = err
						if err == nil {
							var native organizations.CreatePolicyOutput
							decode(row.Output, &native)
							// Include quotes so POLICY_1 cannot replace POLICY_10.
							replacements = append(replacements, `"`+*native.Policy.PolicySummary.Id+`"`, `"`+*out.Policy.PolicySummary.Id+`"`)
						}
					case "AttachPolicy":
						var in organizations.AttachPolicyInput
						decode(row.Input, &in)
						_, callErr = f.org.AttachPolicy(t.Context(), &in)
					case "DetachPolicy":
						var in organizations.DetachPolicyInput
						decode(row.Input, &in)
						_, callErr = f.org.DetachPolicy(t.Context(), &in)
					case "UpdatePolicy":
						var in organizations.UpdatePolicyInput
						decode(row.Input, &in)
						_, callErr = f.org.UpdatePolicy(t.Context(), &in)
						if callErr == nil && backend == "sqlite" {
							// Resume the pending invalidation through the normal
							// worker after closing the actual durable backend.
							closeCloud()
							closeDB()
							backends, closeDB = openSQLiteBackends(suite, path)
							cloud, clients, closeCloud = creationEventCloud(suite, backends, source)
							f.org = clients.organizations("test", "test")
						}
					case "DescribeEffectivePolicy":
						settleEffectivePolicies(t, cloud, source)
						var in organizations.DescribeEffectivePolicyInput
						decode(row.Input, &in)
						out, err := f.org.DescribeEffectivePolicy(t.Context(), &in)
						callErr = err
						if err == nil {
							var native struct {
								EffectivePolicy struct{ PolicyContent string }
							}
							decode(row.Output, &native)
							var got, want any
							decode(json.RawMessage(*out.EffectivePolicy.PolicyContent), &got)
							decode(json.RawMessage(native.EffectivePolicy.PolicyContent), &want)
							if !reflect.DeepEqual(got, want) {
								t.Fatalf("published policy = %s; want %s", *out.EffectivePolicy.PolicyContent, native.EffectivePolicy.PolicyContent)
							}
						}
					case "ListEffectivePolicyValidationErrors":
						settleEffectivePolicies(t, cloud, source)
						var in organizations.ListEffectivePolicyValidationErrorsInput
						decode(row.Input, &in)
						out, err := f.org.ListEffectivePolicyValidationErrors(t.Context(), &in)
						callErr = err
						if err != nil {
							break
						}
						var native struct {
							AccountId, PolicyType           string
							Path                            *string
							EvaluationTimestamp             *float64
							EffectivePolicyValidationErrors []orgtypes.EffectivePolicyValidationError
						}
						decode(row.Output, &native)
						if aws.ToString(out.AccountId) != native.AccountId || string(out.PolicyType) != native.PolicyType || aws.ToString(out.Path) != aws.ToString(native.Path) || (out.Path == nil) != (native.Path == nil) || (out.EvaluationTimestamp == nil) != (native.EvaluationTimestamp == nil) {
							t.Fatalf("report scope/time presence = %#v; want %#v", out, native)
						}
						if row.Case == "max-one" {
							var all []orgtypes.EffectivePolicyValidationError
							pager := organizations.NewListEffectivePolicyValidationErrorsPaginator(f.org, &in)
							for pager.HasMorePages() {
								page, err := pager.NextPage(t.Context())
								if err != nil {
									t.Fatal(err)
								}
								if len(page.EffectivePolicyValidationErrors) > 1 {
									t.Fatal("page exceeds MaxResults")
								}
								all = append(all, page.EffectivePolicyValidationErrors...)
							}
							in.MaxResults = nil
							whole, err := f.org.ListEffectivePolicyValidationErrors(t.Context(), &in)
							if err != nil {
								t.Fatal(err)
							}
							assertPolicyDiagnostics(t, all, whole.EffectivePolicyValidationErrors)
						} else {
							assertPolicyDiagnostics(t, out.EffectivePolicyValidationErrors, native.EffectivePolicyValidationErrors)
						}
					default:
						t.Fatal("unhandled captured operation", row.Action)
					}
					if row.Code == "Success" {
						if callErr != nil {
							t.Fatal(callErr)
						}
					} else {
						assertAPIError(t, callErr, row.Code)
						var native struct{ Reason string }
						decode(row.Output, &native)
						if native.Reason != "" {
							var invalid *orgtypes.InvalidInputException
							if !errors.As(callErr, &invalid) || string(invalid.Reason) != native.Reason {
								t.Fatalf("reason = %v; want %s", callErr, native.Reason)
							}
						}
					}
				}) {
					return
				}
			}
		})
	}
}

func assertPolicyDiagnostics(t *testing.T, got, want []orgtypes.EffectivePolicyValidationError) {
	t.Helper()
	canonical := func(values []orgtypes.EffectivePolicyValidationError) []string {
		result := make([]string, 0, len(values))
		for _, value := range values {
			ids := slices.Clone(value.ContributingPolicies)
			slices.Sort(ids)
			result = append(result, aws.ToString(value.ErrorCode)+"|"+aws.ToString(value.PathToError)+"|"+aws.ToString(value.ErrorMessage)+"|"+strings.Join(ids, ","))
		}
		slices.Sort(result)
		return result
	}
	if !slices.Equal(canonical(got), canonical(want)) {
		t.Fatalf("diagnostics:\ngot %v\nwant %v", canonical(got), canonical(want))
	}
}
