package stackd_test

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

func TestOrganizationsPolicyValidationRecoveryAndRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "validation.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			state := &creationCommitFailure{Storage: backends.Organizations}
			history := &publicationAppendFailure{Storage: backends.Journal}
			backends.Organizations, backends.Journal = state, history
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			cloud, clients, closeCloud := creationEventCloud(t, backends, source)
			f := organizationFixture(t, clients, source)
			member := f.account(t, f.rootID, "validation-recovery")
			unit := f.unit(t, f.rootID, "validation-destination")
			_, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeBackupPolicy})
			if err != nil {
				t.Fatal(err)
			}
			valid := `{"plans":{"daily":{"regions":{"@@assign":["us-east-1"]},"rules":{"daily":{"target_backup_vault_name":{"@@assign":"Vault"}}},"selections":{"tags":{"cost":{"iam_role_arn":{"@@assign":"arn:aws:iam::$account:role/Backup"},"tag_key":{"@@assign":"cost"},"tag_value":{"@@assign":["one"]}}}}}}}`
			invalid := `{"plans":{"daily":{"regions":{"@@assign":["us-east-1"]},"rules":{"daily":{"target_backup_vault_name":{"@@assign":"Vault"}}}}}}`
			created, err := f.org.CreatePolicy(t.Context(), &organizations.CreatePolicyInput{Name: aws.String("validation-recovery"), Description: aws.String("Validation recovery"), Type: orgtypes.PolicyTypeBackupPolicy, Content: &valid})
			if err != nil {
				t.Fatal(err)
			}
			id := created.Policy.PolicySummary.Id
			if _, err := f.org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: id, TargetId: &member}); err != nil {
				t.Fatal(err)
			}
			settleEffectivePolicies(t, cloud, source)
			read := func() (*organizations.ListEffectivePolicyValidationErrorsOutput, *orgtypes.EffectivePolicy) {
				t.Helper()
				report, err := f.org.ListEffectivePolicyValidationErrors(t.Context(), &organizations.ListEffectivePolicyValidationErrorsInput{AccountId: &member, PolicyType: orgtypes.EffectivePolicyTypeBackupPolicy})
				if err != nil {
					t.Fatal(err)
				}
				document, err := f.org.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{TargetId: &member, PolicyType: orgtypes.EffectivePolicyTypeBackupPolicy})
				if err != nil {
					t.Fatal(err)
				}
				return report, document.EffectivePolicy
			}
			_, original := read()
			if _, err := f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: id, Content: &invalid}); err != nil {
				t.Fatal(err)
			}
			settleEffectivePolicies(t, cloud, source)
			report, retained := read()
			if len(report.EffectivePolicyValidationErrors) != 1 || *retained.PolicyContent != *original.PolicyContent || !retained.LastUpdatedTimestamp.After(*original.LastUpdatedTimestamp) {
				t.Fatal("invalid generation did not retain the last valid document", report, retained)
			}
			for _, kind := range []orgtypes.EffectivePolicyType{orgtypes.EffectivePolicyTypeBackupPolicy, orgtypes.EffectivePolicyTypeTagPolicy} {
				_, err := clients.organizations(member, "test").ListEffectivePolicyValidationErrors(t.Context(), &organizations.ListEffectivePolicyValidationErrorsInput{AccountId: &member, PolicyType: kind})
				assertAPIError(t, err, "AccessDeniedException")
			}
			if _, err := f.org.MoveAccount(t.Context(), &organizations.MoveAccountInput{AccountId: &member, SourceParentId: &f.rootID, DestinationParentId: &unit}); err != nil {
				t.Fatal(err)
			}
			restart := func() {
				t.Helper()
				if backend != "sqlite" {
					return
				}
				closeCloud()
				closeDB()
				backends, closeDB = openSQLiteBackends(t, path)
				state = &creationCommitFailure{Storage: backends.Organizations}
				history = &publicationAppendFailure{Storage: backends.Journal}
				backends.Organizations, backends.Journal = state, history
				cloud, clients, closeCloud = creationEventCloud(t, backends, source)
				f.org = clients.organizations("test", "test")
			}
			restart()
			before, revision, err := backends.Organizations.Load(t.Context(), "aws")
			if err != nil {
				t.Fatal(err)
			}
			events := lifecycleEvents(t, backends.Journal)
			for _, mode := range []string{"append", "commit", "cancel"} {
				switch mode {
				case "append":
					history.fail.Store(true)
				case "commit":
					state.mode.Store(1)
				case "cancel":
					state.mode.Store(2)
				}
				source.Advance(time.Second)
				if _, err := cloud.RunDueJobs(t.Context(), 100); err == nil {
					t.Fatal("failed publication succeeded", mode)
				}
				after, nextRevision, err := backends.Organizations.Load(t.Context(), "aws")
				if err != nil || revision != nextRevision || !reflect.DeepEqual(before, after) {
					t.Fatal("failed publication changed stored diagnostics", mode, err)
				}
				if !reflect.DeepEqual(events, lifecycleEvents(t, backends.Journal)) {
					t.Fatal("failed publication retained an event", mode)
				}
				pending, doc := read()
				assertPolicyDiagnostics(t, pending.EffectivePolicyValidationErrors, report.EffectivePolicyValidationErrors)
				if *pending.Path != *report.Path || !pending.EvaluationTimestamp.Equal(*report.EvaluationTimestamp) || !reflect.DeepEqual(doc, retained) {
					t.Fatal("pending read changed the published report or document")
				}
				history.fail.Store(false)
				state.mode.Store(0)
			}
			settleEffectivePolicies(t, cloud, source)
			moved, _ := read()
			if aws.ToString(moved.Path) != f.rootPath+"/"+unit+"/"+member+"/" {
				t.Fatal("validation path did not follow the published hierarchy", moved)
			}
			if _, err := f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: id, Content: &valid}); err != nil {
				t.Fatal(err)
			}
			restart()
			pending, _ := read()
			assertPolicyDiagnostics(t, pending.EffectivePolicyValidationErrors, moved.EffectivePolicyValidationErrors)
			settleEffectivePolicies(t, cloud, source)
			cleared, doc := read()
			if len(cleared.EffectivePolicyValidationErrors) != 0 || cleared.Path != nil || cleared.EvaluationTimestamp != nil || *doc.PolicyContent != *original.PolicyContent {
				t.Fatal("repair retained invalid diagnostics", cleared, doc)
			}
		})
	}
}

func TestOrganizationsPolicyValidationUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.sqlite")
	backends, closeDB := openSQLiteBackends(t, path)
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	cloud, clients, closeCloud := creationEventCloud(t, backends, source)
	f := organizationFixture(t, clients, source)
	if _, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeBackupPolicy}); err != nil {
		t.Fatal(err)
	}
	created, err := f.org.CreatePolicy(t.Context(), &organizations.CreatePolicyInput{Name: aws.String("legacy-backup"), Description: aws.String("Legacy invalid policy"), Type: orgtypes.PolicyTypeBackupPolicy, Content: aws.String(`{"plans":{"daily":{"regions":{"@@assign":["us-east-1"]}}}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: created.Policy.PolicySummary.Id, TargetId: &f.rootID}); err != nil {
		t.Fatal(err)
	}
	settleEffectivePolicies(t, cloud, source)
	closeCloud()
	current := path
	path = filepath.Join(t.TempDir(), "version18.sqlite")
	db := awstest.HistoricalSQLite(t, path, "../storage/sqlite/schema", 18, current, map[string]string{
		"kernel_events": `SELECT * FROM fixture.kernel_events WHERE event_type IN
			('sts.session.issued.v1','iam.access_key.changed.v1','organizations.account_creation.changed.v1','organizations.handshake.changed.v1','organizations.effective_policy.changed.v1')`,
	})
	// Schema 18 published unresolved backup fragments without validation.
	if _, err := db.ExecContext(t.Context(), `UPDATE org_effective_policies SET content='{"plans":{"daily":{"regions":["us-east-1"]}}}', due=NULL WHERE policy_type='BACKUP_POLICY'`); err != nil {
		t.Fatal(err)
	}
	closeDB()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	backends, _ = openSQLiteBackends(t, path)
	cloud, clients, _ = creationEventCloud(t, backends, source)
	settleEffectivePolicies(t, cloud, source)
	client := clients.organizations("test", "test")
	org, err := client.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := client.ListEffectivePolicyValidationErrors(t.Context(), &organizations.ListEffectivePolicyValidationErrorsInput{AccountId: org.Organization.MasterAccountId, PolicyType: orgtypes.EffectivePolicyTypeBackupPolicy})
	if err != nil || len(report.EffectivePolicyValidationErrors) != 2 {
		t.Fatal("legacy policy was not validated", report, err)
	}
	doc, err := client.DescribeEffectivePolicy(t.Context(), &organizations.DescribeEffectivePolicyInput{PolicyType: orgtypes.EffectivePolicyTypeBackupPolicy})
	if err != nil || aws.ToString(doc.EffectivePolicy.PolicyContent) != "{}" {
		t.Fatal("unvalidated legacy content became the last valid document", doc, err)
	}
}
