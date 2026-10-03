package stackd_test

import (
	"encoding/base32"
	"encoding/csv"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/storage"
)

func TestSQLiteIAMRecoversPendingReportsAndActivity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports.sqlite")
	start := time.Date(2031, 2, 3, 4, 5, 0, 123456789, time.UTC)
	source := clock.NewManual(start)
	backends := &storage.Backends{}
	c, close := openSQLiteCloud(t, path, backends, source)
	root := c.iam("test", "test", "")
	arn, key, secret := c.user(t, "test", "report-subject")
	putUserPolicy(t, root, "report-subject", `{"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/missing":"yes"}}}}`)
	_, err := c.iam(key, secret, "").GetUser(t.Context(), &iam.GetUserInput{})
	assertAPIError(t, err, "AccessDenied")
	job, err := root.GenerateServiceLastAccessedDetails(t.Context(), &iam.GenerateServiceLastAccessedDetailsInput{Arn: &arn, Granularity: iamtypes.AccessAdvisorUsageGranularityTypeActionLevel})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.GenerateCredentialReport(t.Context(), &iam.GenerateCredentialReportInput{}); err != nil {
		t.Fatal(err)
	}
	close()
	advanceClock(t, source, time.Second)
	c, close = openSQLiteCloud(t, path, backends, source)
	root = c.iam("test", "test", "")
	deadline := time.Now().Add(5 * time.Second)
	var report *iam.GetServiceLastAccessedDetailsOutput
	for {
		report, err = root.GetServiceLastAccessedDetails(t.Context(), &iam.GetServiceLastAccessedDetailsInput{JobId: job.JobId})
		if err != nil {
			t.Fatal(err)
		}
		if report.JobStatus != iamtypes.JobStatusTypeInProgress {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("access report worker did not recover")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if report.JobStatus != iamtypes.JobStatusTypeCompleted || len(report.ServicesLastAccessed) != 1 {
		t.Fatal("frozen report not recovered")
	}
	usage := report.ServicesLastAccessed[0]
	if aws.ToString(usage.ServiceNamespace) != "iam" || aws.ToString(usage.LastAuthenticatedEntity) != arn || usage.LastAuthenticated == nil || !usage.LastAuthenticated.Equal(start) || len(usage.TrackedActionsLastAccessed) != 1 || aws.ToString(usage.TrackedActionsLastAccessed[0].ActionName) != "GetUser" {
		t.Fatal("denied activity or action snapshot lost")
	}
	entities, err := root.GetServiceLastAccessedDetailsWithEntities(t.Context(), &iam.GetServiceLastAccessedDetailsWithEntitiesInput{JobId: job.JobId, ServiceNamespace: aws.String("iam")})
	if err != nil || len(entities.EntityDetailsList) != 1 || entities.EntityDetailsList[0].LastAuthenticated == nil {
		t.Fatal("report entity snapshot lost", err)
	}
	var credentialReport *iam.GetCredentialReportOutput
	for {
		credentialReport, err = root.GetCredentialReport(t.Context(), &iam.GetCredentialReportInput{})
		if err == nil {
			break
		}
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "ReportInProgress" {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("credential report worker did not recover")
		}
		time.Sleep(10 * time.Millisecond)
	}
	rows, err := csv.NewReader(strings.NewReader(string(credentialReport.Content))).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatal("credential report content lost", err)
	}
	if !strings.Contains(string(credentialReport.Content), "report-subject") {
		t.Fatal("credential report omitted its principal")
	}
	putUserPolicy(t, root, "report-subject", allow(`"sqs:*"`, "*"))
	close()
	c, _ = openSQLiteCloud(t, path, backends, source)
	retained, err := c.iam("test", "test", "").GetCredentialReport(t.Context(), &iam.GetCredentialReportInput{})
	if err != nil || string(retained.Content) != string(credentialReport.Content) {
		t.Fatal("completed report was regenerated after restart", err)
	}
	frozen, err := c.iam("test", "test", "").GetServiceLastAccessedDetails(t.Context(), &iam.GetServiceLastAccessedDetailsInput{JobId: job.JobId})
	if err != nil || len(frozen.ServicesLastAccessed) != 1 || aws.ToString(frozen.ServicesLastAccessed[0].ServiceNamespace) != "iam" {
		t.Fatal("later policies changed the recovered access snapshot", err)
	}
}

func TestSQLiteIAMRetainsMFAPropagationCodesAndAuthenticationAge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mfa.sqlite")
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	backends := &storage.Backends{}
	c, close := openSQLiteCloud(t, path, backends, source)
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "mfa-user")
	putUserPolicy(t, root, "mfa-user", `{"Statement":{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"},"NumericLessThanEquals":{"aws:MultiFactorAuthAge":"60"}}}}`)
	device, err := root.CreateVirtualMFADevice(t.Context(), &iam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("durable")})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(device.VirtualMFADevice.Base32StringSeed))
	if err != nil {
		t.Fatal(err)
	}
	step := source.Now().Unix() / 30
	if _, err := root.EnableMFADevice(t.Context(), &iam.EnableMFADeviceInput{UserName: aws.String("mfa-user"), SerialNumber: device.VirtualMFADevice.SerialNumber, AuthenticationCode1: aws.String(otpForTest(seed, step-1)), AuthenticationCode2: aws.String(otpForTest(seed, step))}); err != nil {
		t.Fatal(err)
	}
	close()
	advanceClock(t, source, 10*time.Second)
	c, close = openSQLiteCloud(t, path, backends, source)
	input := &sts.GetSessionTokenInput{SerialNumber: device.VirtualMFADevice.SerialNumber, TokenCode: aws.String(otpForTest(seed, step+1))}
	issued, err := c.sts(key, secret, "").GetSessionToken(t.Context(), input)
	if err != nil {
		t.Fatal("MFA binding or seed lost", err)
	}
	close()
	c, _ = openSQLiteCloud(t, path, backends, source)
	_, err = c.sts(key, secret, "").GetSessionToken(t.Context(), input)
	assertAPIError(t, err, "AccessDenied")
	credentials := issued.Credentials
	authenticated := c.iam(aws.ToString(credentials.AccessKeyId), aws.ToString(credentials.SecretAccessKey), aws.ToString(credentials.SessionToken))
	if _, err := authenticated.ListUsers(t.Context(), &iam.ListUsersInput{}); err != nil {
		t.Fatal("authenticated MFA context lost", err)
	}
	advanceClock(t, source, 61*time.Second)
	_, err = authenticated.ListUsers(t.Context(), &iam.ListUsersInput{})
	assertAPIError(t, err, "AccessDenied")
}
