package stackd_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/journal"
	"stackd/storage"
)

func TestOrganizationsEffectivePolicyRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "rollback.sqlite"))
			}
			fault := &creationCommitFailure{Storage: backends.Organizations}
			backends.Organizations = fault
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			cloud, c, _ := creationEventCloud(t, backends, source)
			f := organizationFixture(t, c, source)
			_, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeTagPolicy})
			if err != nil {
				t.Fatal(err)
			}
			policy := createTagPolicy(t, f, "original-tags", effectivePolicyDocument("cost", "before"), f.rootID)
			read := func() *orgtypes.EffectivePolicy {
				t.Helper()
				out, err := f.org.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy})
				if err != nil {
					t.Fatal(err)
				}
				return out.EffectivePolicy
			}
			settleEffectivePolicies(t, cloud, source)
			before := read()
			for _, mode := range []int32{1, 2} {
				fault.mode.Store(mode)
				f.clock.Advance(time.Second)
				_, err = f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &policy, Content: aws.String(effectivePolicyDocument("cost", "after"))})
				assertAPIError(t, err, "ServiceException")
				after := read()
				if *after.PolicyContent != *before.PolicyContent || !after.LastUpdatedTimestamp.Equal(*before.LastUpdatedTimestamp) {
					t.Fatal("failed write published content or generation")
				}
				_, err = f.org.DetachPolicy(t.Context(), &organizations.DetachPolicyInput{PolicyId: &policy, TargetId: &f.rootID})
				assertAPIError(t, err, "ServiceException")
				after = read()
				if *after.PolicyContent != *before.PolicyContent || !after.LastUpdatedTimestamp.Equal(*before.LastUpdatedTimestamp) {
					t.Fatal("failed detach changed effective state")
				}
			}
		})
	}
}

func TestOrganizationsEffectivePolicyUpgradeRetainsAttachments(t *testing.T) {
	for _, version := range []int{15, 16} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "upgrade.sqlite")
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			backends, closeDB := openSQLiteBackends(t, path)
			cloud, c, closeCloud := creationEventCloud(t, backends, source)
			f := organizationFixture(t, c, source)
			if _, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeTagPolicy}); err != nil {
				t.Fatal(err)
			}
			createTagPolicy(t, f, "first-tags", effectivePolicyDocument("cost", "first"), f.rootID)
			createTagPolicy(t, f, "second-tags", effectivePolicyDocument("cost", "second"), f.rootID)
			settleEffectivePolicies(t, cloud, source)
			before, err := f.org.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy})
			if err != nil {
				t.Fatal(err)
			}
			closeCloud()
			current := path
			path = filepath.Join(t.TempDir(), "historical.sqlite")
			db := awstest.HistoricalSQLite(t, path, "../storage/sqlite/schema", version, current, map[string]string{
				"org_effective_policy_generations": "SELECT * FROM fixture.org_effective_policies",
				"kernel_events": `SELECT * FROM fixture.kernel_events WHERE event_type IN
					('sts.session.issued.v1','iam.access_key.changed.v1','organizations.account_creation.changed.v1','organizations.handshake.changed.v1')`,
			})
			closeDB()
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			source.Advance(time.Hour)
			backends, _ = openSQLiteBackends(t, path)
			cloud, c, _ = creationEventCloud(t, backends, source)
			// The ordinary worker regenerates legacy views at current service time.
			// No historical timestamp or request origin is fabricated by migration.
			if _, err := cloud.RunDueJobs(t.Context(), 100); err != nil {
				t.Fatal(err)
			}
			after, err := c.organizations("test", "test").DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeTagPolicy})
			if err != nil || *after.EffectivePolicy.PolicyContent != *before.EffectivePolicy.PolicyContent {
				t.Fatal("upgrade lost retained attachment order", after, err)
			}
			if after.EffectivePolicy.LastUpdatedTimestamp == nil || !after.EffectivePolicy.LastUpdatedTimestamp.Equal(source.Now()) {
				t.Fatal("recovery publication time missing", after)
			}
			var last journal.Event
			for _, event := range lifecycleEvents(t, backends.Journal) {
				if event.EffectivePolicyChanged.State != "" {
					last = event
				}
			}
			if last.EffectivePolicyChanged.State != "PUBLISHED" || last.RequestID != "" || last.ActorARN != "" || !last.At.Equal(source.Now()) {
				t.Fatal("wrong recovered event", last)
			}
		})
	}
}
