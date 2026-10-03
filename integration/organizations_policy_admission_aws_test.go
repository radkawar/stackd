package stackd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

func TestOrganizationsPolicyAdmissionAWS(t *testing.T) {
	paths := []string{"../testdata/aws/iam/organizations_ai_policy.json", "../testdata/aws/iam/organizations_ai_policy_details.json", "../testdata/aws/iam/organizations_tags_controls.json", "../testdata/aws/iam/organizations_plans_controls.json"}
	for _, name := range []string{"policy", "policy_details", "policy_overrides", "policy_wildcards", "policy_controls"} {
		paths = append(paths, "../testdata/aws/iam/organizations_chat_"+name+".json")
	}
	for _, name := range []string{"policy", "extended", "numeric", "schedule", "schedule_details", "archive_plan", "archive_rule", "calendar", "calendar_details", "calendar_selectors", "cron_grammar", "cadence"} {
		paths = append(paths, "../testdata/aws/iam/organizations_backup_"+name+".json")
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var capture struct {
			RetrievedAt  time.Time `json:"retrieved_at"`
			Observations []effectivePolicyObservation
		}
		if err := json.Unmarshal(data, &capture); err != nil {
			t.Fatal(err)
		}
		source := clock.NewManual(capture.RetrievedAt)
		f := organizationFixture(t, clockCloud(t, stackd.Config{Clock: source}), source)
		for _, row := range capture.Observations {
			t.Run(path+"/"+row.Case, func(t *testing.T) {
				var input organizations.CreatePolicyInput
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				out, err := f.org.CreatePolicy(t.Context(), &input)
				if row.Code != "Success" {
					if err == nil {
						_, _ = f.org.DeletePolicy(t.Context(), &organizations.DeletePolicyInput{PolicyId: out.Policy.PolicySummary.Id})
					}
					assertAPIError(t, err, row.Code)
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if *out.Policy.Content != *input.Content {
					t.Fatal("admission rewrote the stored source policy")
				}
				if _, err := f.org.DeletePolicy(t.Context(), &organizations.DeletePolicyInput{PolicyId: out.Policy.PolicySummary.Id}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestOrganizationsAIPolicyUpdateAWS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/organizations_ai_policy_updates.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		RetrievedAt  time.Time `json:"retrieved_at"`
		Initial      organizations.CreatePolicyInput
		Observations []struct {
			Case, Code string
			Input      organizations.UpdatePolicyInput
			State      organizations.DescribePolicyOutput
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				var closeDB func()
				backends, closeDB = openSQLiteBackends(t, filepath.Join(t.TempDir(), "admission.sqlite"))
				t.Cleanup(closeDB)
			}
			source := clock.NewManual(capture.RetrievedAt)
			f := organizationFixture(t, clockCloud(t, stackd.Config{Clock: source, Storage: backends}), source)
			created, err := f.org.CreatePolicy(t.Context(), &capture.Initial)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range capture.Observations {
				t.Run(row.Case, func(t *testing.T) {
					input := row.Input
					input.PolicyId = created.Policy.PolicySummary.Id
					_, err := f.org.UpdatePolicy(t.Context(), &input)
					if row.Code == "Success" {
						if err != nil {
							t.Fatal(err)
						}
					} else {
						assertAPIError(t, err, row.Code)
					}
					state, err := f.org.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: input.PolicyId})
					if err != nil {
						t.Fatal(err)
					}
					got, want := state.Policy, row.State.Policy
					if aws.ToString(got.Content) != aws.ToString(want.Content) || aws.ToString(got.PolicySummary.Name) != aws.ToString(want.PolicySummary.Name) || aws.ToString(got.PolicySummary.Description) != aws.ToString(want.PolicySummary.Description) {
						t.Fatalf("stored policy after update differs from AWS: got %s / %s / %s; want %s / %s / %s", aws.ToString(got.Content), aws.ToString(got.PolicySummary.Name), aws.ToString(got.PolicySummary.Description), aws.ToString(want.Content), aws.ToString(want.PolicySummary.Name), aws.ToString(want.PolicySummary.Description))
					}
				})
			}
		})
	}
}
