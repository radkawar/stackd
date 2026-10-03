package stackd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	"stackd/storage"
)

func TestOrganizationsBackupCalendarRolloverAWS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/organizations_backup_rollover.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		RetrievedAt  time.Time `json:"retrieved_at"`
		Observations []struct {
			Case, Action, Code string
			At                 time.Time
			Input              json.RawMessage
			Output             organizations.DescribePolicyOutput
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			suite := t
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "calendar.sqlite")
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(capture.RetrievedAt)
			cloud, clients, closeCloud := creationEventCloud(t, backends, source)
			f := organizationFixture(t, clients, source)
			if _, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeBackupPolicy}); err != nil {
				t.Fatal(err)
			}
			// Supply the other plan fields independently. The captured schedule
			// fragment must continue to participate in inheritance after it no
			// longer satisfies fresh admission at the new service time.
			base := `{"plans":{"daily":{"regions":{"@@assign":["us-east-1"]},"rules":{"daily":{"target_backup_vault_name":{"@@assign":"Vault"}}},"selections":{"tags":{"cost":{"iam_role_arn":{"@@assign":"arn:aws:iam::$account:role/Backup"},"tag_key":{"@@assign":"cost"},"tag_value":{"@@assign":["one"]}}}}}}}`
			basePolicy, err := f.org.CreatePolicy(t.Context(), &organizations.CreatePolicyInput{Name: aws.String("calendar-base"), Description: aws.String("Calendar inheritance"), Type: orgtypes.PolicyTypeBackupPolicy, Content: &base})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: basePolicy.Policy.PolicySummary.Id, TargetId: &f.rootID}); err != nil {
				t.Fatal(err)
			}
			var id, sourceContent string
			for _, row := range capture.Observations {
				if !t.Run(row.Case, func(t *testing.T) {
					if row.At.After(source.Now()) {
						advanceClock(t, source, row.At.Sub(source.Now()))
					}
					input := []byte(strings.ReplaceAll(string(row.Input), "POLICY_ID", id))
					var callErr error
					switch row.Action {
					case "CreatePolicy":
						var in organizations.CreatePolicyInput
						if err := json.Unmarshal(input, &in); err != nil {
							t.Fatal(err)
						}
						out, err := f.org.CreatePolicy(t.Context(), &in)
						callErr = err
						if err == nil {
							id, sourceContent = *out.Policy.PolicySummary.Id, *in.Content
							if _, err := f.org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: &id, TargetId: &f.rootID}); err != nil {
								t.Fatal(err)
							}
						}
					case "UpdatePolicy":
						var in organizations.UpdatePolicyInput
						if err := json.Unmarshal(input, &in); err != nil {
							t.Fatal(err)
						}
						_, callErr = f.org.UpdatePolicy(t.Context(), &in)
						if callErr == nil && backend == "sqlite" {
							closeCloud()
							closeDB()
							backends, closeDB = openSQLiteBackends(suite, path)
							cloud, clients, closeCloud = creationEventCloud(suite, backends, source)
							f.org = clients.organizations("test", "test")
						}
					case "DescribePolicy":
						out, err := f.org.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &id})
						callErr = err
						if err == nil && (*out.Policy.Content != sourceContent || *out.Policy.PolicySummary.Description != *row.Output.Policy.PolicySummary.Description) {
							t.Fatal("read changed accepted policy", out)
						}
					}
					if row.Code == "Success" {
						if callErr != nil {
							t.Fatal(callErr)
						}
					} else {
						assertAPIError(t, callErr, row.Code)
					}
				}) {
					return
				}
			}
			settleEffectivePolicies(t, cloud, source)
			out, err := f.org.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeBackupPolicy})
			if err != nil {
				t.Fatal(err)
			}
			var expected, actual struct {
				Plans map[string]struct {
					Rules map[string]map[string]json.RawMessage
				}
			}
			if err := json.Unmarshal([]byte(sourceContent), &expected); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(*out.EffectivePolicy.PolicyContent), &actual); err != nil {
				t.Fatal(err)
			}
			var assignment struct {
				Assign string `json:"@@assign"`
			}
			if err := json.Unmarshal(expected.Plans["daily"].Rules["daily"]["schedule_expression"], &assignment); err != nil {
				t.Fatal(err)
			}
			var schedule string
			if err := json.Unmarshal(actual.Plans["daily"].Rules["daily"]["schedule_expression"], &schedule); err != nil || schedule != assignment.Assign {
				t.Fatal("publication revalidated accepted schedule", out, err)
			}
		})
	}
}
