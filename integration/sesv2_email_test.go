package stackd_test

import (
	"bytes"
	"errors"
	"io"
	"mime/quotedprintable"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	ses "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"stackd"
)

func capturedMail(t *testing.T, root, subject string) string {
	t.Helper()
	var found string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".eml") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		m, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		if m.Header.Get("Subject") == subject {
			var reader io.Reader = m.Body
			if strings.EqualFold(m.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
				reader = quotedprintable.NewReader(reader)
			}
			body, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			found = string(body)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == "" {
		t.Fatalf("missing MIME subject %s", subject)
	}
	return found
}
func TestSESv2CognitoCapturedWorkflow(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			account := "123456789012"
			cloud, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, SESEmailDirectory: dir}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			clients := func() (*sesv2.Client, *cognitoidentityprovider.Client) {
				cred := credentials.NewStaticCredentialsProvider(account, "test", "")
				return sesv2.New(sesv2.Options{Region: "us-east-1", BaseEndpoint: aws.String(cloud.server.URL), Credentials: cred, HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1}), cognitoidentityprovider.New(cognitoidentityprovider.Options{Region: "us-east-1", BaseEndpoint: aws.String(cloud.server.URL), Credentials: cred, HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1})
			}
			_, users := clients()
			pool, err := users.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("mail-workflow"), AutoVerifiedAttributes: []cognito.VerifiedAttributeType{cognito.VerifiedAttributeTypeEmail}})
			if err != nil {
				t.Fatal(err)
			}
			client, err := users.CreateUserPoolClient(t.Context(), &cognitoidentityprovider.CreateUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientName: aws.String("application"), ExplicitAuthFlows: []cognito.ExplicitAuthFlowsType{cognito.ExplicitAuthFlowsTypeAllowUserPasswordAuth, cognito.ExplicitAuthFlowsTypeAllowRefreshTokenAuth}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = users.SignUp(t.Context(), &cognitoidentityprovider.SignUpInput{ClientId: client.UserPoolClient.ClientId, Username: aws.String("alice"), Password: aws.String("FirstPassword1!"), UserAttributes: []cognito.AttributeType{{Name: aws.String("email"), Value: aws.String("alice@example.invalid")}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = cloud.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 100); err != nil {
				t.Fatal(err)
			}
			code := regexp.MustCompile(`[0-9]{6}`).FindString(capturedMail(t, dir, "Your verification code"))
			if code == "" {
				t.Fatal("missing code")
			}
			_, err = users.ConfirmSignUp(t.Context(), &cognitoidentityprovider.ConfirmSignUpInput{ClientId: client.UserPoolClient.ClientId, Username: aws.String("alice"), ConfirmationCode: aws.String("not-the-code")})
			if err == nil {
				t.Fatal("wrong verification code accepted")
			}
			cloud = reopen()
			mailer, users := clients()
			// Confirmation belongs to the user, not the app client that requested it.
			_, err = users.DeleteUserPoolClient(t.Context(), &cognitoidentityprovider.DeleteUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientId: client.UserPoolClient.ClientId})
			if err != nil {
				t.Fatal(err)
			}
			client, err = users.CreateUserPoolClient(t.Context(), &cognitoidentityprovider.CreateUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientName: aws.String("replacement"), ExplicitAuthFlows: []cognito.ExplicitAuthFlowsType{cognito.ExplicitAuthFlowsTypeAllowUserPasswordAuth, cognito.ExplicitAuthFlowsTypeAllowRefreshTokenAuth}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = users.ConfirmSignUp(t.Context(), &cognitoidentityprovider.ConfirmSignUpInput{ClientId: client.UserPoolClient.ClientId, Username: aws.String("alice"), ConfirmationCode: aws.String(code)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = users.DeleteUserPoolClient(t.Context(), &cognitoidentityprovider.DeleteUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientId: client.UserPoolClient.ClientId})
			if err != nil {
				t.Fatal(err)
			}
			_, err = users.AdminResetUserPassword(t.Context(), &cognitoidentityprovider.AdminResetUserPasswordInput{UserPoolId: pool.UserPool.Id, Username: aws.String("alice")})
			if err != nil {
				t.Fatal(err)
			}
			client, err = users.CreateUserPoolClient(t.Context(), &cognitoidentityprovider.CreateUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientName: aws.String("after-reset"), ExplicitAuthFlows: []cognito.ExplicitAuthFlowsType{cognito.ExplicitAuthFlowsTypeAllowUserPasswordAuth, cognito.ExplicitAuthFlowsTypeAllowRefreshTokenAuth}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = cloud.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 100); err != nil {
				t.Fatal(err)
			}
			reset := regexp.MustCompile(`[0-9]{6}`).FindString(capturedMail(t, dir, "Your password reset code"))
			_, err = users.ConfirmForgotPassword(t.Context(), &cognitoidentityprovider.ConfirmForgotPasswordInput{ClientId: client.UserPoolClient.ClientId, Username: aws.String("alice"), ConfirmationCode: aws.String(reset), Password: aws.String("SecondPassword2!")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = users.InitiateAuth(t.Context(), &cognitoidentityprovider.InitiateAuthInput{ClientId: client.UserPoolClient.ClientId, AuthFlow: cognito.AuthFlowTypeUserPasswordAuth, AuthParameters: map[string]string{"USERNAME": "alice", "PASSWORD": "SecondPassword2!"}})
			if err != nil {
				t.Fatal(err)
			}
			// Managed Cognito capture must not grant public SES sending authority.
			_, err = mailer.SendEmail(t.Context(), &sesv2.SendEmailInput{FromEmailAddress: aws.String("no-reply@verificationemail.com"), Destination: &ses.Destination{ToAddresses: []string{"success@simulator.amazonses.com"}}, Content: &ses.EmailContent{Simple: &ses.Message{Subject: &ses.Content{Data: aws.String("denied")}, Body: &ses.Body{Text: &ses.Content{Data: aws.String("denied")}}}}})
			if err == nil {
				t.Fatal("managed Cognito authority leaked into public SES")
			}
			// Pool dependencies and role removal share one writable domain; a
			// read-only usage callback would leave ordinary IAM deletion stuck.
			_, err = mailer.CreateEmailIdentity(t.Context(), &sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String("sender@example.invalid")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = cloud.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 100); err != nil {
				t.Fatal(err)
			}
			link := regexp.MustCompile(`/_stackd/ses/verify-email-identity\?token=[0-9a-f]{48}`).FindString(capturedMail(t, dir, "Amazon SES Email Address Verification Request"))
			if link == "" {
				t.Fatal("captured identity verification link missing")
			}
			response, err := cloud.server.Client().Get(cloud.server.URL + link)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("verification HTTP %d", response.StatusCode)
			}
			developer, err := users.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("developer-mail"), EmailConfiguration: &cognito.EmailConfigurationType{EmailSendingAccount: cognito.EmailSendingAccountTypeDeveloper, SourceArn: aws.String("arn:aws:ses:us-east-1:" + account + ":identity/sender@example.invalid")}})
			if err != nil {
				t.Fatal(err)
			}
			identity := iam.New(iam.Options{Region: "us-east-1", BaseEndpoint: aws.String(cloud.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1})
			role := aws.String("AWSServiceRoleForAmazonCognitoIdpEmailService")
			task, err := identity.DeleteServiceLinkedRole(t.Context(), &iam.DeleteServiceLinkedRoleInput{RoleName: role})
			if err != nil {
				t.Fatal(err)
			}
			status := waitOrganizationRoleDeletion(t, identity, task.DeletionTaskId)
			if status.Status != iamtypes.DeletionTaskStatusTypeFailed || status.Reason == nil || len(status.Reason.RoleUsageList) != 1 || len(status.Reason.RoleUsageList[0].Resources) != 1 || status.Reason.RoleUsageList[0].Resources[0] != aws.ToString(developer.UserPool.Arn) {
				t.Fatalf("developer role dependency lost: %+v", status)
			}
			_, err = users.DeleteUserPool(t.Context(), &cognitoidentityprovider.DeleteUserPoolInput{UserPoolId: developer.UserPool.Id})
			if err != nil {
				t.Fatal(err)
			}
			task, err = identity.DeleteServiceLinkedRole(t.Context(), &iam.DeleteServiceLinkedRoleInput{RoleName: role})
			if err != nil {
				t.Fatal(err)
			}
			if status = waitOrganizationRoleDeletion(t, identity, task.DeletionTaskId); status.Status != iamtypes.DeletionTaskStatusTypeSucceeded {
				t.Fatalf("released email role was not removed: %+v", status)
			}
			_, err = identity.GetRole(t.Context(), &iam.GetRoleInput{RoleName: role})
			var missing *iamtypes.NoSuchEntityException
			if !errors.As(err, &missing) {
				t.Fatalf("deleted email role still exists: %v", err)
			}
		})
	}
}
