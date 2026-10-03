package stackd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
)

type publicationObservation struct {
	Code    string
	Content map[string]any
}

func TestOrganizationsPolicyPublicationAWSAndPendingRecovery(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/organizations_policy_publication.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Transitions []struct {
			Case      string
			Mutations []struct {
				Action string
				Input  json.RawMessage
			}
			Observations []publicationObservation
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			suite := t
			path := filepath.Join(t.TempDir(), "publication.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			open := func() {
				if backend == "sqlite" {
					backends, closeDB = openSQLiteBackends(suite, path)
				}
			}
			open()
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			cloud, c, closeCloud := creationEventCloud(suite, backends, source)
			f := organizationFixture(t, c, source)
			member := f.account(t, f.rootID, "publication-member")
			created, err := f.org.CreatePolicy(t.Context(), &organizations.CreatePolicyInput{Name: aws.String("publication-owned"), Description: aws.String("publication"), Type: orgtypes.PolicyTypeTagPolicy, Content: aws.String(effectivePolicyDocument("stackd-publication-owned", "one"))})
			if err != nil {
				t.Fatal(err)
			}
			replacer := strings.NewReplacer("r-example", f.rootID, "222222222222", member, "POLICY_ID", *created.Policy.PolicySummary.Id)
			var previous *orgtypes.EffectivePolicy
			read := func(t *testing.T, want publicationObservation) *orgtypes.EffectivePolicy {
				t.Helper()
				out, err := f.org.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy, TargetId: &member})
				if want.Code != "Success" {
					assertAPIError(t, err, want.Code)
					return nil
				}
				if err != nil {
					t.Fatal(err)
				}
				var content map[string]any
				if err := json.Unmarshal([]byte(*out.EffectivePolicy.PolicyContent), &content); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(content, want.Content) {
					t.Fatalf("got %s; want %v", *out.EffectivePolicy.PolicyContent, want.Content)
				}
				return out.EffectivePolicy
			}
			for _, row := range capture.Transitions {
				t.Run(row.Case, func(t *testing.T) {
					for _, mutation := range row.Mutations {
						input := []byte(replacer.Replace(string(mutation.Input)))
						switch mutation.Action {
						case "EnablePolicyType":
							var in organizations.EnablePolicyTypeInput
							if err := json.Unmarshal(input, &in); err != nil {
								t.Fatal(err)
							}
							_, err = f.org.EnablePolicyType(t.Context(), &in)
						case "DisablePolicyType":
							var in organizations.DisablePolicyTypeInput
							if err := json.Unmarshal(input, &in); err != nil {
								t.Fatal(err)
							}
							_, err = f.org.DisablePolicyType(t.Context(), &in)
						case "AttachPolicy":
							var in organizations.AttachPolicyInput
							if err := json.Unmarshal(input, &in); err != nil {
								t.Fatal(err)
							}
							_, err = f.org.AttachPolicy(t.Context(), &in)
						case "DetachPolicy":
							var in organizations.DetachPolicyInput
							if err := json.Unmarshal(input, &in); err != nil {
								t.Fatal(err)
							}
							_, err = f.org.DetachPolicy(t.Context(), &in)
						case "UpdatePolicy":
							var in organizations.UpdatePolicyInput
							if err := json.Unmarshal(input, &in); err != nil {
								t.Fatal(err)
							}
							_, err = f.org.UpdatePolicy(t.Context(), &in)
						default:
							t.Fatal("unhandled native mutation", mutation.Action)
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					if row.Case != "enable" {
						old := read(t, row.Observations[0])
						if old != nil && !old.LastUpdatedTimestamp.Equal(*previous.LastUpdatedTimestamp) {
							t.Fatal("mutation replaced the published timestamp")
						}
					}
					if row.Case == "update" {
						closeCloud()
						closeDB()
						open()
						cloud, c, closeCloud = creationEventCloud(suite, backends, source)
						f.cloud, f.org = c, c.organizations("test", "test")
						old := read(t, row.Observations[0])
						if !old.LastUpdatedTimestamp.Equal(*previous.LastUpdatedTimestamp) {
							t.Fatal("restart changed prior publication")
						}
					}
					// Keep disable/re-enable in the same instant to exercise the native
					// retained cache. Disabled reads stay gated while its job is pending.
					if row.Case == "disable" || row.Case == "disable-again" {
						return
					}
					events := lifecycleEvents(t, backends.Journal)
					var scheduled journal.Event
					for _, e := range events {
						if e.EffectivePolicyChanged.TargetAccountID == member && e.EffectivePolicyChanged.State == journal.EffectivePolicyScheduled {
							scheduled = e
						}
					}
					source.Advance(500 * time.Millisecond)
					if _, err := cloud.RunDueJobs(t.Context(), 100); err != nil {
						t.Fatal(err)
					}
					if row.Case != "enable" {
						read(t, row.Observations[0])
					}
					source.Advance(500 * time.Millisecond)
					if _, err := cloud.RunDueJobs(t.Context(), 100); err != nil {
						t.Fatal(err)
					}
					previous = read(t, row.Observations[len(row.Observations)-1])
					if !previous.LastUpdatedTimestamp.Equal(source.Now()) {
						t.Fatal("publication did not use service time")
					}
					events = lifecycleEvents(t, backends.Journal)
					var published journal.Event
					for _, e := range events {
						if e.EffectivePolicyChanged.TargetAccountID == member && e.EffectivePolicyChanged.State == journal.EffectivePolicyPublished {
							published = e
						}
					}
					if published.RequestID == "" || published.RequestID != scheduled.RequestID || published.ActorARN != scheduled.ActorARN || published.AccountID != scheduled.AccountID || published.Region != scheduled.Region || published.Partition != scheduled.Partition || !published.At.Equal(source.Now()) || published.Sequence <= scheduled.Sequence {
						t.Fatal("publication lost request origin", scheduled, published)
					}
				})
				if t.Failed() {
					break
				}
			}
			closeCloud()
			closeDB()
		})
	}
}

func TestOrganizationsPolicyPublicationMembership(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "membership.sqlite"))
			}
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			cloud, c, _ := creationEventCloud(t, backends, source)
			f := organizationFixture(t, c, source)
			if _, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeTagPolicy}); err != nil {
				t.Fatal(err)
			}
			policy := createTagPolicy(t, f, "membership-publication", effectivePolicyDocument("cost", "inherited"), f.rootID)
			member := f.account(t, f.rootID, "publication-member")
			settleEffectivePolicies(t, cloud, source)
			read := func(want string) {
				t.Helper()
				out, err := c.organizations(member, "test").DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy})
				if err != nil || !strings.Contains(*out.EffectivePolicy.PolicyContent, `"`+want+`"`) {
					t.Fatal("member did not inherit published policy", out, err)
				}
			}
			read("inherited")
			if _, err := f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &policy, Content: aws.String(effectivePolicyDocument("cost", "rejoined"))}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.org.RemoveAccountFromOrganization(t.Context(), &organizations.RemoveAccountFromOrganizationInput{AccountId: &member}); err != nil {
				t.Fatal(err)
			}
			settleEffectivePolicies(t, cloud, source)
			_, err := f.org.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy, TargetId: &member})
			assertAPIError(t, err, "TargetNotFoundException")
			stored, _, err := backends.Organizations.Load(t.Context(), "aws")
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range stored.Organizations[0].EffectivePolicies {
				if p.AccountID == member {
					t.Fatal("removed member retained publication work")
				}
			}
			invited, err := f.org.InviteAccountToOrganization(t.Context(), &organizations.InviteAccountToOrganizationInput{Target: &orgtypes.HandshakeParty{Type: orgtypes.HandshakePartyTypeAccount, Id: &member}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.organizations(member, "test").AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: invited.Handshake.Id}); err != nil {
				t.Fatal(err)
			}
			settleEffectivePolicies(t, cloud, source)
			read("rejoined")
			if _, err := f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &policy, Content: aws.String(effectivePolicyDocument("cost", "deleted"))}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.org.RemoveAccountFromOrganization(t.Context(), &organizations.RemoveAccountFromOrganizationInput{AccountId: &member}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.org.DeleteOrganization(t.Context(), &organizations.DeleteOrganizationInput{}); err != nil {
				t.Fatal(err)
			}
			settleEffectivePolicies(t, cloud, source)
			stored, _, err = backends.Organizations.Load(t.Context(), "aws")
			if err != nil || len(stored.Organizations) != 0 {
				t.Fatal("publication resurrected a deleted organization", stored, err)
			}
			removed := 0
			for _, e := range lifecycleEvents(t, backends.Journal) {
				if e.EffectivePolicyChanged.State == journal.EffectivePolicyRemoved {
					removed++
				}
			}
			if removed != 3 {
				t.Fatal("missing member/organization removal events", removed)
			}
		})
	}
}
