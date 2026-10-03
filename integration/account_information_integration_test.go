package stackd_test

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

func TestAccountInformationAndNamesMatchAWS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/account/information.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Code string
			Input      account.PutAccountNameInput
			Output     struct{ AccountName, AccountState string }
			Error      struct{ Message string }
		}
		SDKBlankError struct {
			Code, Message   string
			Status          int
			ErrorTypeHeader string `json:"error_type_header"`
		} `json:"sdk_blank_error"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	f := newOrganizationReportFixture(t, storage.NewMemory())
	advanceClock(t, f.clock, 889*time.Millisecond)
	member := f.account(t, f.rootID, "account-info-member")
	client := f.cloud.account(member, "test", "")
	initial, err := client.GetAccountInformation(t.Context(), &account.GetAccountInformationInput{})
	if err != nil {
		t.Fatal(err)
	}
	org, err := f.org.DescribeAccount(t.Context(), &organizations.DescribeAccountInput{AccountId: &member})
	if err != nil || !initial.AccountCreatedDate.Equal(org.Account.JoinedTimestamp.Truncate(time.Second)) {
		t.Fatalf("account creation date: %+v %v", initial, err)
	}
	contact := primaryContact()
	if _, err := client.PutContactInformation(t.Context(), &account.PutContactInformationInput{ContactInformation: contact}); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Observations {
		t.Run(row.Case, func(t *testing.T) {
			_, err := client.PutAccountName(t.Context(), &row.Input)
			if row.Code == "Success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if row.Case == "blank" {
				assertAPIError(t, err, fixture.SDKBlankError.Code)
				var apiErr smithy.APIError
				var response *smithyhttp.ResponseError
				if !errors.As(err, &apiErr) || apiErr.ErrorMessage() != fixture.SDKBlankError.Message || !errors.As(err, &response) || response.HTTPStatusCode() != fixture.SDKBlankError.Status || response.Response.Header.Get("X-Amzn-Errortype") != fixture.SDKBlankError.ErrorTypeHeader {
					t.Fatalf("native SDK error differs: %v", err)
				}
			} else {
				assertAPIError(t, err, row.Code)
			}
			info, err := client.GetAccountInformation(t.Context(), &account.GetAccountInformationInput{})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(info.AccountId) != member || aws.ToString(info.AccountName) != row.Output.AccountName || string(info.AccountState) != row.Output.AccountState || !info.AccountCreatedDate.Equal(*initial.AccountCreatedDate) {
				t.Fatalf("native account information differs: %+v", info)
			}
			org, err := f.org.DescribeAccount(t.Context(), &organizations.DescribeAccountInput{AccountId: &member})
			if err != nil || aws.ToString(org.Account.Name) != row.Output.AccountName {
				t.Fatalf("Organizations name did not follow replacement: %+v %v", org, err)
			}
			current, err := client.GetContactInformation(t.Context(), &account.GetContactInformationInput{})
			if err != nil || !reflect.DeepEqual(current.ContactInformation, contact) {
				t.Fatal("account name changed primary contact", err)
			}
		})
	}
	advanceClock(t, f.clock, time.Hour)
	root, err := f.cloud.iam(member, "test", "").GetUser(t.Context(), &iam.GetUserInput{})
	if err != nil || !root.User.CreateDate.Equal(*org.Account.JoinedTimestamp) {
		t.Fatalf("first IAM response reset the provisioned date: %+v %v", root, err)
	}
}

func TestAccountNameFeedsOrganizationCreationAndIAMPasswordRules(t *testing.T) {
	source := clock.NewManual(time.Unix(100, 900_000_000).UTC())
	c := clockCloud(t, stackd.Config{Clock: source})
	client, identity := c.account("test", "test", ""), c.iam("test", "test", "")
	initial, err := client.GetAccountInformation(t.Context(), &account.GetAccountInformationInput{})
	if err != nil || aws.ToString(initial.AccountName) != "Management" || !initial.AccountCreatedDate.Equal(time.Unix(100, 0)) {
		t.Fatalf("bootstrap information: %+v %v", initial, err)
	}
	name := "NewAccountName1"
	if _, err := client.PutAccountName(t.Context(), &account.PutAccountNameInput{AccountName: &name}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, time.Hour)
	if _, err := identity.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("editor")}); err != nil {
		t.Fatal(err)
	}
	_, err = identity.CreateLoginProfile(t.Context(), &iam.CreateLoginProfileInput{UserName: aws.String("editor"), Password: &name})
	assertAPIError(t, err, "PasswordPolicyViolation")
	root, err := identity.GetUser(t.Context(), &iam.GetUserInput{})
	if err != nil || !root.User.CreateDate.Equal(time.Unix(100, 900_000_000)) {
		t.Fatalf("Account changed IAM's canonical date: %+v %v", root, err)
	}
	org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	if _, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll}); err != nil {
		t.Fatal(err)
	}
	member, err := org.DescribeAccount(t.Context(), &organizations.DescribeAccountInput{AccountId: aws.String("000000000000")})
	if err != nil || aws.ToString(member.Account.Name) != name {
		t.Fatalf("organization creation reset account name: %+v %v", member, err)
	}
	current, err := client.GetAccountInformation(t.Context(), &account.GetAccountInformationInput{})
	if err != nil || !current.AccountCreatedDate.Equal(*initial.AccountCreatedDate) {
		t.Fatal("joining an organization reset account creation time", err)
	}
}

func TestAccountInformationOrganizationAccessAndNamePermissions(t *testing.T) {
	f := newOrganizationReportFixture(t, storage.NewMemory())
	member := f.account(t, f.rootID, "information-permissions")
	_, key, secret := f.cloud.user(t, "test", "account-reader")
	putUserPolicy(t, f.iam, "account-reader", `{"Statement":{"Effect":"Allow","Action":"account:GetAccountInformation","Resource":"*"}}`)
	reader := f.cloud.account(key, secret, "")
	_, err := reader.GetAccountInformation(t.Context(), &account.GetAccountInformationInput{AccountId: &member})
	assertAPIError(t, err, "AccessDeniedException")
	if _, err := f.org.EnableAWSServiceAccess(t.Context(), &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("account.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	info, err := reader.GetAccountInformation(t.Context(), &account.GetAccountInformationInput{AccountId: &member})
	if err != nil || aws.ToString(info.AccountName) != "information-permissions" {
		t.Fatal("trusted account information unavailable", err)
	}
	_, err = reader.PutAccountName(t.Context(), &account.PutAccountNameInput{AccountId: &member, AccountName: aws.String("Denied Name")})
	assertAPIError(t, err, "AccessDeniedException")
	memberRoot := f.cloud.account(member, "test", "")
	_, err = memberRoot.GetAccountInformation(t.Context(), &account.GetAccountInformationInput{AccountId: &member})
	assertAPIError(t, err, "AccessDeniedException")
	self, err := memberRoot.GetAccountInformation(t.Context(), &account.GetAccountInformationInput{})
	if err != nil || aws.ToString(self.AccountName) != "information-permissions" {
		t.Fatal("denied rename changed the member", err)
	}
	if _, err := f.org.CloseAccount(t.Context(), &organizations.CloseAccountInput{AccountId: &member}); err != nil {
		t.Fatal(err)
	}
	// The Account read must expose the state stored by Organizations rather
	// than reject the target solely because it is no longer active. Native
	// transition timing and Account access during closure remain an audit gap.
	closed, err := reader.GetAccountInformation(t.Context(), &account.GetAccountInformationInput{AccountId: &member})
	if err != nil || closed.AccountState != "CLOSED" {
		t.Fatalf("closed account information unavailable: %+v %v", closed, err)
	}
}
