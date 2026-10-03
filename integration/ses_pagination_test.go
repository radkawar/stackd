package stackd_test

import (
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	classic "github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	v2 "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/smithy-go"
	"stackd"
)

func TestSESPaginationScopeAndRetention(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "123456789012"
			cloud, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, SESEmailDirectory: t.TempDir()}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			clients := func(owner, region string) (*ses.Client, *sesv2.Client) {
				cred := credentials.NewStaticCredentialsProvider(owner, "test", "")
				return ses.New(ses.Options{Region: region, BaseEndpoint: aws.String(cloud.server.URL), Credentials: cred, HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1}), sesv2.New(sesv2.Options{Region: region, BaseEndpoint: aws.String(cloud.server.URL), Credentials: cred, HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1})
			}
			_, mailer := clients(account, "us-east-1")
			for _, name := range []string{"charlie", "alpha", "bravo"} {
				if _, err := mailer.CreateConfigurationSet(t.Context(), &sesv2.CreateConfigurationSetInput{ConfigurationSetName: aws.String(name)}); err != nil {
					t.Fatal(err)
				}
				if _, err := mailer.CreateEmailTemplate(t.Context(), &sesv2.CreateEmailTemplateInput{TemplateName: aws.String(name), TemplateContent: &v2.EmailTemplateContent{Subject: aws.String(name), Text: aws.String("body")}}); err != nil {
					t.Fatal(err)
				}
				if _, err := mailer.CreateEmailIdentity(t.Context(), &sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String(name + "@example.invalid")}); err != nil {
					t.Fatal(err)
				}
			}
			type listing struct {
				name, kind string
				list       func(string, string, *string, int32) ([]string, *string, error)
			}
			lists := []listing{
				{"v2-configurations", "configurations", func(owner, region string, token *string, size int32) ([]string, *string, error) {
					_, c := clients(owner, region)
					o, err := c.ListConfigurationSets(t.Context(), &sesv2.ListConfigurationSetsInput{NextToken: token, PageSize: aws.Int32(size)})
					if err != nil {
						return nil, nil, err
					}
					return o.ConfigurationSets, o.NextToken, nil
				}},
				{"classic-configurations", "configurations", func(owner, region string, token *string, size int32) ([]string, *string, error) {
					c, _ := clients(owner, region)
					o, err := c.ListConfigurationSets(t.Context(), &ses.ListConfigurationSetsInput{NextToken: token, MaxItems: aws.Int32(size)})
					if err != nil {
						return nil, nil, err
					}
					var names []string
					for _, row := range o.ConfigurationSets {
						names = append(names, aws.ToString(row.Name))
					}
					return names, o.NextToken, nil
				}},
				{"v2-templates", "templates", func(owner, region string, token *string, size int32) ([]string, *string, error) {
					_, c := clients(owner, region)
					o, err := c.ListEmailTemplates(t.Context(), &sesv2.ListEmailTemplatesInput{NextToken: token, PageSize: aws.Int32(size)})
					if err != nil {
						return nil, nil, err
					}
					var names []string
					for _, row := range o.TemplatesMetadata {
						names = append(names, aws.ToString(row.TemplateName))
					}
					return names, o.NextToken, nil
				}},
				{"classic-templates", "templates", func(owner, region string, token *string, size int32) ([]string, *string, error) {
					c, _ := clients(owner, region)
					o, err := c.ListTemplates(t.Context(), &ses.ListTemplatesInput{NextToken: token, MaxItems: aws.Int32(size)})
					if err != nil {
						return nil, nil, err
					}
					var names []string
					for _, row := range o.TemplatesMetadata {
						names = append(names, aws.ToString(row.Name))
					}
					return names, o.NextToken, nil
				}},
				{"v2-identities", "v2-identities", func(owner, region string, token *string, size int32) ([]string, *string, error) {
					_, c := clients(owner, region)
					o, err := c.ListEmailIdentities(t.Context(), &sesv2.ListEmailIdentitiesInput{NextToken: token, PageSize: aws.Int32(size)})
					if err != nil {
						return nil, nil, err
					}
					var names []string
					for _, row := range o.EmailIdentities {
						names = append(names, aws.ToString(row.IdentityName))
					}
					return names, o.NextToken, nil
				}},
				{"classic-identities", "classic-identities", func(owner, region string, token *string, size int32) ([]string, *string, error) {
					c, _ := clients(owner, region)
					o, err := c.ListIdentities(t.Context(), &ses.ListIdentitiesInput{NextToken: token, MaxItems: aws.Int32(size)})
					if err != nil {
						return nil, nil, err
					}
					return o.Identities, o.NextToken, nil
				}},
			}
			invalid := func(t *testing.T, err error) {
				t.Helper()
				var apiErr smithy.APIError
				if !errors.As(err, &apiErr) || (apiErr.ErrorCode() != "BadRequestException" && apiErr.ErrorCode() != "InvalidParameterValue") {
					t.Fatalf("expected invalid pagination request, got %v", err)
				}
			}
			tokens := make([]*string, len(lists))
			for i, list := range lists {
				names, token, err := list.list(account, "us-east-1", nil, 1)
				want := "alpha"
				if list.kind == "classic-identities" || list.kind == "v2-identities" {
					want += "@example.invalid"
				}
				if err != nil || !slices.Equal(names, []string{want}) || token == nil {
					t.Fatalf("%s first page: %v %v %v", list.name, names, token, err)
				}
				tokens[i] = token
			}
			cloud = reopen()
			for i, list := range lists {
				t.Run(list.name, func(t *testing.T) {
					names, token, err := list.list(account, "us-east-1", tokens[i], 2)
					want := []string{"bravo", "charlie"}
					if list.kind == "classic-identities" || list.kind == "v2-identities" {
						want = []string{"bravo@example.invalid", "charlie@example.invalid"}
					}
					if err != nil || !slices.Equal(names, want) || token != nil {
						t.Fatalf("retained continuation: %v %v %v", names, token, err)
					}
					for _, scope := range [][2]string{{"234567890123", "us-east-1"}, {account, "us-west-2"}, {account, "cn-north-1"}} {
						_, _, err = list.list(scope[0], scope[1], tokens[i], 1)
						invalid(t, err)
					}
					for j, other := range lists {
						if list.kind == other.kind {
							continue
						}
						_, _, err = list.list(account, "us-east-1", tokens[j], 1)
						invalid(t, err)
					}
					for _, token := range []string{"not-base64!", base64.RawURLEncoding.EncodeToString([]byte("alpha"))} {
						_, _, err = list.list(account, "us-east-1", aws.String(token), 1)
						invalid(t, err)
					}
				})
			}
			c, _ := clients(account, "us-east-1")
			filtered, err := c.ListIdentities(t.Context(), &ses.ListIdentitiesInput{IdentityType: classic.IdentityTypeEmailAddress, MaxItems: aws.Int32(1)})
			if err != nil {
				t.Fatal(err)
			}
			continued, err := c.ListIdentities(t.Context(), &ses.ListIdentitiesInput{IdentityType: classic.IdentityTypeEmailAddress, NextToken: filtered.NextToken, MaxItems: aws.Int32(2)})
			if err != nil || !slices.Equal(continued.Identities, []string{"bravo@example.invalid", "charlie@example.invalid"}) || continued.NextToken != nil {
				t.Fatalf("filtered continuation: %v %v", continued, err)
			}
			for _, filter := range []classic.IdentityType{"", classic.IdentityTypeDomain} {
				_, err = c.ListIdentities(t.Context(), &ses.ListIdentitiesInput{IdentityType: filter, NextToken: filtered.NextToken})
				invalid(t, err)
			}
		})
	}
}
