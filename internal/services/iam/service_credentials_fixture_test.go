package iam_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
)

func TestIAMServiceCredentialsAWSFixtureReplay(t *testing.T) {
	data, err := os.ReadFile("testdata/service_credentials_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case       string `json:"case"`
			Credential struct {
				Fields      []string `json:"fields"`
				ServiceName string
				Status      string
			} `json:"credential"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	_, root := newServiceCredentialTestService(t)
	ctx := context.Background()
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("fixture-user")})
	if err != nil {
		t.Fatal(err)
	}
	cases := 0
	for _, observation := range fixture.Observations {
		if !strings.HasSuffix(observation.Case, ":create-first") {
			continue
		}
		cases++
		t.Run(observation.Credential.ServiceName, func(t *testing.T) {
			input := &sdkiam.CreateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceName: aws.String(observation.Credential.ServiceName)}
			if slices.Contains(observation.Credential.Fields, "ExpirationDate") {
				input.CredentialAgeDays = aws.Int32(1)
			}
			created, err := root.CreateServiceSpecificCredential(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			value := reflect.ValueOf(*created.ServiceSpecificCredential)
			var present []string
			for index := 0; index < value.NumField(); index++ {
				field := value.Type().Field(index)
				if field.IsExported() && !value.Field(index).IsZero() {
					present = append(present, field.Name)
				}
			}
			slices.Sort(present)
			if !slices.Equal(present, observation.Credential.Fields) || string(created.ServiceSpecificCredential.Status) != observation.Credential.Status {
				t.Fatalf("AWS credential field/status mismatch: fields=%v status=%s", present, created.ServiceSpecificCredential.Status)
			}
		})
	}
	if cases != 6 {
		t.Fatalf("fixture replay covered %d services, want 6", cases)
	}
}

func TestIAMServiceCredentialsValidation(t *testing.T) {
	_, root := newServiceCredentialTestService(t)
	ctx := context.Background()
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("validation-user")})
	if err != nil {
		t.Fatal(err)
	}
	for _, age := range []int32{0, -1, 36601} {
		_, err := root.CreateServiceSpecificCredential(ctx, &sdkiam.CreateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceName: aws.String("bedrock.amazonaws.com"), CredentialAgeDays: aws.Int32(age)})
		requireCode(t, err, "ValidationError")
	}
	for _, service := range []string{"sqs.amazonaws.com", "codecommit.amazonaws.com.cn"} {
		_, err := root.CreateServiceSpecificCredential(ctx, &sdkiam.CreateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceName: aws.String(service)})
		requireCode(t, err, "NoSuchEntity")
	}
	_, err = root.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: u.User.UserName, ServiceName: aws.String(" invalid ")})
	requireCode(t, err, "ValidationError")
	_, err = root.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: u.User.UserName, AllUsers: aws.Bool(true)})
	requireCode(t, err, "InvalidInput")
	_, err = root.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: u.User.UserName, AllUsers: aws.Bool(false), ServiceName: aws.String("")})
	if err != nil {
		t.Fatalf("explicit false AllUsers and empty service filter must be accepted: %v", err)
	}
}
