package iam_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

var serviceCredentialCases = []struct {
	service string
	prefix  string
}{
	{"codecommit.amazonaws.com", ""}, {"cassandra.amazonaws.com", ""},
	{"bedrock.amazonaws.com", "ABSK"}, {"logs.amazonaws.com", "ACWL"},
	{"cloudwatch.amazonaws.com", "APIAACWM"}, {"aws-external-anthropic.amazonaws.com", "AEAA"},
}

func serviceCredentialMaterial(c *types.ServiceSpecificCredential) (identifier, secret string) {
	if c.ServiceCredentialAlias != nil {
		return aws.ToString(c.ServiceCredentialAlias), aws.ToString(c.ServiceCredentialSecret)
	}
	return aws.ToString(c.ServiceUserName), aws.ToString(c.ServicePassword)
}

func TestIAMServiceCredentialsLifecycle(t *testing.T) {
	for _, test := range serviceCredentialCases {
		t.Run(test.service, func(t *testing.T) {
			service := iam.New()
			root := clientFor(t, service, "123456789012", "us-east-1")
			ctx := context.Background()
			u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("credential-user"), Path: aws.String("/services/")})
			if err != nil {
				t.Fatal(err)
			}
			input := &sdkiam.CreateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceName: aws.String(strings.ToUpper(test.service)), CredentialAgeDays: aws.Int32(1)}
			created, err := root.CreateServiceSpecificCredential(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			credential := created.ServiceSpecificCredential
			identifier, firstSecret := serviceCredentialMaterial(credential)
			if aws.ToString(credential.ServiceName) != test.service || credential.Status != types.StatusTypeActive || len(aws.ToString(credential.ServiceSpecificCredentialId)) != 21 || identifier != "credential-user-at-123456789012" {
				t.Fatal("created credential metadata does not match AWS")
			}
			if credential.CreateDate == nil || credential.ExpirationDate == nil || credential.ExpirationDate.Sub(*credential.CreateDate) != 24*time.Hour {
				t.Fatal("credential expiry must be one day after creation for every supported service")
			}
			if test.prefix == "" {
				if credential.ServiceCredentialAlias != nil || credential.ServiceCredentialSecret != nil || len(firstSecret) != 60 {
					t.Fatal("legacy credentials must contain a service username and generated password")
				}
			} else {
				if credential.ServiceUserName != nil || credential.ServicePassword != nil || !strings.HasPrefix(firstSecret, test.prefix) {
					t.Fatal("API-key credential has wrong fields or public prefix")
				}
				payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(firstSecret, test.prefix))
				if err != nil || !strings.HasPrefix(string(payload), identifier+":") || len(payload)-len(identifier)-1 != 60 {
					t.Fatal("API-key credential has wrong public envelope")
				}
			}
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			verify := func(secret string, valid bool) {
				t.Helper()
				principal, err := service.VerifyServiceCredential(ctx, scope, test.service, identifier, secret)
				if valid {
					if err != nil || principal.ID != aws.ToString(u.User.UserId) || principal.ARN != aws.ToString(u.User.Arn) {
						t.Fatalf("credential did not authenticate current owner: %v", err)
					}
				} else if !errors.Is(err, iam.ErrInvalidServiceCredential) {
					t.Fatalf("invalid credential was accepted: %v", err)
				}
			}
			verify(firstSecret, true)
			verify(firstSecret+"wrong", false)
			if test.prefix != "" {
				if _, err := service.VerifyServiceCredential(ctx, scope, test.service, "", firstSecret); err != nil {
					t.Fatalf("bearer-token verification: %v", err)
				}
			}
			for _, wrong := range []iam.Scope{{Partition: "aws-cn", AccountID: scope.AccountID}, {Partition: scope.Partition, AccountID: "999999999999"}} {
				_, err := service.VerifyServiceCredential(ctx, wrong, test.service, identifier, firstSecret)
				if !errors.Is(err, iam.ErrInvalidServiceCredential) {
					t.Fatal("credential crossed account or partition scope")
				}
			}
			_, err = service.VerifyServiceCredential(ctx, scope, "other.amazonaws.com", identifier, firstSecret)
			if !errors.Is(err, iam.ErrInvalidServiceCredential) {
				t.Fatal("credential authenticated a different service")
			}
			_, err = root.UpdateServiceSpecificCredential(ctx, &sdkiam.UpdateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId, Status: types.StatusTypeInactive})
			if err != nil {
				t.Fatal(err)
			}
			verify(firstSecret, false)
			reset, err := root.ResetServiceSpecificCredential(ctx, &sdkiam.ResetServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId})
			if err != nil {
				t.Fatal(err)
			}
			resetID, secondSecret := serviceCredentialMaterial(reset.ServiceSpecificCredential)
			if secondSecret == firstSecret || resetID != identifier || reset.ServiceSpecificCredential.Status != types.StatusTypeInactive || !reset.ServiceSpecificCredential.CreateDate.Equal(*credential.CreateDate) || !reset.ServiceSpecificCredential.ExpirationDate.Equal(*credential.ExpirationDate) {
				t.Fatal("reset must rotate only the secret and preserve identity, dates, and inactive status")
			}
			verify(secondSecret, false)
			_, err = root.UpdateServiceSpecificCredential(ctx, &sdkiam.UpdateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId, Status: types.StatusTypeActive})
			if err != nil {
				t.Fatal(err)
			}
			verify(firstSecret, false)
			verify(secondSecret, true)
			_, err = root.UpdateServiceSpecificCredential(ctx, &sdkiam.UpdateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId, Status: types.StatusTypeExpired})
			requireCode(t, err, "InvalidInput")
			verify(secondSecret, true)
			_, err = root.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: u.User.UserName})
			requireCode(t, err, "DeleteConflict")
			_, err = root.DeleteServiceSpecificCredential(ctx, &sdkiam.DeleteServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId})
			if err != nil {
				t.Fatal(err)
			}
			verify(secondSecret, false)
			_, err = root.DeleteServiceSpecificCredential(ctx, &sdkiam.DeleteServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId})
			requireCode(t, err, "NoSuchEntity")
			listed, err := root.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: u.User.UserName})
			if err != nil || len(listed.ServiceSpecificCredentials) != 0 || listed.IsTruncated {
				t.Fatalf("credential deletion listing: %+v %v", listed, err)
			}
		})
	}
}

func TestIAMServiceCredentialsQuotaPaginationAndRename(t *testing.T) {
	service := iam.New()
	root := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("original")})
	if err != nil {
		t.Fatal(err)
	}
	create := func(serviceName string) *types.ServiceSpecificCredential {
		t.Helper()
		result, err := root.CreateServiceSpecificCredential(ctx, &sdkiam.CreateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceName: aws.String(serviceName)})
		if err != nil {
			t.Fatal(err)
		}
		return result.ServiceSpecificCredential
	}
	first := create("codecommit.amazonaws.com")
	second := create("codecommit.amazonaws.com")
	if aws.ToString(second.ServiceUserName) != "original+1-at-123456789012" || second.ExpirationDate != nil {
		t.Fatal("second credential must have a unique alias and no default expiration")
	}
	_, err = root.UpdateServiceSpecificCredential(ctx, &sdkiam.UpdateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceSpecificCredentialId: first.ServiceSpecificCredentialId, Status: types.StatusTypeInactive})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.CreateServiceSpecificCredential(ctx, &sdkiam.CreateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceName: aws.String("codecommit.amazonaws.com")})
	requireCode(t, err, "LimitExceeded")
	create("bedrock.amazonaws.com")
	request := &sdkiam.ListServiceSpecificCredentialsInput{UserName: u.User.UserName, MaxItems: aws.Int32(1)}
	seen := map[string]bool{}
	for {
		page, err := root.ListServiceSpecificCredentials(ctx, request)
		if err != nil || len(page.ServiceSpecificCredentials) != 1 {
			t.Fatalf("single-item page: %+v %v", page, err)
		}
		id := aws.ToString(page.ServiceSpecificCredentials[0].ServiceSpecificCredentialId)
		if seen[id] {
			t.Fatal("credential pagination repeated an item")
		}
		seen[id] = true
		if !page.IsTruncated {
			break
		}
		if request.Marker == nil {
			_, err := root.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: u.User.UserName, Marker: page.Marker, ServiceName: aws.String("bedrock.amazonaws.com")})
			requireCode(t, err, "InvalidInput")
		}
		request.Marker = page.Marker
	}
	if len(seen) != 3 {
		t.Fatal("credential pagination lost a credential")
	}
	_, err = root.UpdateUser(ctx, &sdkiam.UpdateUserInput{UserName: u.User.UserName, NewUserName: aws.String("renamed"), NewPath: aws.String("/new/")})
	if err != nil {
		t.Fatal(err)
	}
	identifier, secret := serviceCredentialMaterial(second)
	principal, err := service.VerifyServiceCredential(ctx, iam.Scope{Partition: "aws", AccountID: "123456789012"}, "codecommit.amazonaws.com", identifier, secret)
	if err != nil || principal.ID != aws.ToString(u.User.UserId) || principal.UserName != "renamed" || principal.ARN != "arn:aws:iam::123456789012:user/new/renamed" {
		t.Fatalf("renamed credential identity: %+v %v", principal, err)
	}
	listed, err := root.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: aws.String("renamed"), ServiceName: aws.String("codecommit.amazonaws.com")})
	if err != nil || len(listed.ServiceSpecificCredentials) != 2 {
		t.Fatalf("renamed listing: %+v %v", listed, err)
	}
	for _, credential := range listed.ServiceSpecificCredentials {
		if aws.ToString(credential.UserName) != "renamed" || !strings.HasPrefix(aws.ToString(credential.ServiceUserName), "original") {
			t.Fatal("rename changed public service username or retained stale owner name")
		}
	}
	_, err = root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("original")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.ResetServiceSpecificCredential(ctx, &sdkiam.ResetServiceSpecificCredentialInput{UserName: aws.String("original"), ServiceSpecificCredentialId: second.ServiceSpecificCredentialId})
	requireCode(t, err, "ValidationError")
	_, err = root.UpdateServiceSpecificCredential(ctx, &sdkiam.UpdateServiceSpecificCredentialInput{UserName: aws.String("original"), ServiceSpecificCredentialId: second.ServiceSpecificCredentialId, Status: types.StatusTypeInactive})
	requireCode(t, err, "ValidationError")
	_, err = root.DeleteServiceSpecificCredential(ctx, &sdkiam.DeleteServiceSpecificCredentialInput{UserName: aws.String("original"), ServiceSpecificCredentialId: second.ServiceSpecificCredentialId})
	requireCode(t, err, "ValidationError")
}
