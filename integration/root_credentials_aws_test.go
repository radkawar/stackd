package stackd_test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd/storage"
	iamstore "stackd/storage/iam"
)

func TestRootCredentialRecoveryAWSReplay(t *testing.T) {
	rows := rootAWSCapture(t)
	backends := storage.NewMemory()
	repository := &accountMetadataRepository{Repository: backends.IAM, reports: make(chan iamstore.Scope, 1)}
	backends.IAM = repository
	f := newOrganizationReportFixture(t, backends)
	member := f.account(t, f.rootID, "root-credentials-native")
	if _, err := f.org.EnableAWSServiceAccess(t.Context(), &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.iam.EnableOrganizationsRootCredentialsManagement(t.Context(), &iam.EnableOrganizationsRootCredentialsManagementInput{}); err != nil {
		t.Fatal(err)
	}
	_, key, secret := f.cloud.user(t, "test", "root-native-operator")
	putUserPolicy(t, f.iam, "root-native-operator", fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRoot","Resource":"arn:aws:iam::%s:root"}}`, member))
	caller := f.cloud.sts(key, secret, "")
	assume := func(task string) *iam.Client {
		t.Helper()
		out, err := caller.AssumeRoot(t.Context(), &sts.AssumeRootInput{TargetPrincipal: &member, TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String("arn:aws:iam::aws:policy/root-task/" + task)}})
		if err != nil {
			t.Fatal(err)
		}
		c := out.Credentials
		return f.cloud.iam(*c.AccessKeyId, *c.SecretAccessKey, *c.SessionToken)
	}
	audit := assume("IAMAuditRootUserCredentials")
	creator := assume("IAMCreateRootUserPassword")
	deleter := assume("IAMDeleteRootUserCredentials")
	user, err := audit.GetUser(t.Context(), &iam.GetUserInput{})
	var nativeUser iam.GetUserOutput
	if err := json.Unmarshal(rootAWSResult(t, rows, "audit_get-user", err), &nativeUser); err != nil {
		t.Fatal(err)
	}
	if user.User.UserName != nativeUser.User.UserName || user.User.Path != nativeUser.User.Path || aws.ToString(user.User.UserId) != member || aws.ToString(user.User.Arn) != "arn:aws:iam::"+member+":root" || user.User.CreateDate == nil {
		t.Fatalf("root GetUser fields: %+v", user.User)
	}
	_, err = audit.GetLoginProfile(t.Context(), &iam.GetLoginProfileInput{})
	rootAWSResult(t, rows, "profile_before", err)
	checkSummary := func(label string) {
		t.Helper()
		out, err := audit.GetAccountSummary(t.Context(), &iam.GetAccountSummaryInput{})
		var native iam.GetAccountSummaryOutput
		if err := json.Unmarshal(rootAWSResult(t, rows, label, err), &native); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"AccountPasswordPresent", "AccountAccessKeysPresent", "AccountSigningCertificatesPresent", "AccountMFAEnabled"} {
			if out.SummaryMap[key] != native.SummaryMap[key] {
				t.Fatalf("%s %s: %d, AWS %d", label, key, out.SummaryMap[key], native.SummaryMap[key])
			}
		}
	}
	checkSummary("summary_before")
	createdAt := f.clock.Now()
	profile, err := creator.CreateLoginProfile(t.Context(), &iam.CreateLoginProfileInput{})
	var nativeProfile iam.CreateLoginProfileOutput
	if err := json.Unmarshal(rootAWSResult(t, rows, "create_profile", err), &nativeProfile); err != nil {
		t.Fatal(err)
	}
	if profile.LoginProfile.UserName != nativeProfile.LoginProfile.UserName || profile.LoginProfile.PasswordResetRequired != nativeProfile.LoginProfile.PasswordResetRequired || !profile.LoginProfile.CreateDate.Equal(createdAt) {
		t.Fatalf("root CreateLoginProfile fields: %+v", profile.LoginProfile)
	}
	_, err = creator.CreateLoginProfile(t.Context(), &iam.CreateLoginProfileInput{})
	rootAWSResult(t, rows, "create_profile_duplicate", err)
	got, err := audit.GetLoginProfile(t.Context(), &iam.GetLoginProfileInput{})
	rootAWSResult(t, rows, "profile_after_create", err)
	if got.LoginProfile.UserName != nil || got.LoginProfile.PasswordResetRequired || !got.LoginProfile.CreateDate.Equal(createdAt) {
		t.Fatalf("stored recovery profile changed: %+v", got.LoginProfile)
	}
	checkSummary("summary_after_create")
	memberIAM := f.cloud.iam(member, "test", "")
	_, err = memberIAM.GenerateCredentialReport(t.Context(), &iam.GenerateCredentialReportInput{})
	rootAWSResult(t, rows, "generate_report", err)
	select {
	case <-repository.reports:
	case <-time.After(5 * time.Second):
		t.Fatal("root credential report did not complete")
	}
	report, err := memberIAM.GetCredentialReport(t.Context(), &iam.GetCredentialReportInput{})
	var nativeReport struct {
		GeneratedTime time.Time
		RootRow       map[string]string
	}
	if err := json.Unmarshal(rootAWSResult(t, rows, "report_after_create", err), &nativeReport); err != nil {
		t.Fatal(err)
	}
	if nativeReport.GeneratedTime.Before(*nativeProfile.LoginProfile.CreateDate) {
		t.Fatal("native report predates the recovery profile; it cannot establish this transition")
	}
	csvRows, err := csv.NewReader(bytes.NewReader(report.Content)).ReadAll()
	if err != nil || len(csvRows) != 2 {
		t.Fatalf("root report rows: %v %v", csvRows, err)
	}
	actual := make(map[string]string)
	for i, field := range csvRows[0] {
		actual[field] = csvRows[1][i]
	}
	nativeReport.RootRow["arn"] = aws.ToString(user.User.Arn)
	nativeReport.RootRow["user_creation_time"] = user.User.CreateDate.UTC().Format(time.RFC3339)
	nativeReport.RootRow["password_last_changed"] = createdAt.UTC().Format(time.RFC3339)
	if !maps.Equal(actual, nativeReport.RootRow) {
		t.Fatalf("root credential report: %v; AWS %v", actual, nativeReport.RootRow)
	}
	_, err = deleter.DeleteLoginProfile(t.Context(), &iam.DeleteLoginProfileInput{})
	rootAWSResult(t, rows, "delete_owned_profile", err)
	_, err = audit.GetLoginProfile(t.Context(), &iam.GetLoginProfileInput{})
	rootAWSResult(t, rows, "profile_after_delete", err)
	checkSummary("summary_after_delete")
}
