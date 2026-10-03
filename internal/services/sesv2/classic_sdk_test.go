package sesv2_test

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	classic "github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	v2 "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/smithy-go"
	classicapi "stackd/internal/awsapi/ses"
	api "stackd/internal/awsapi/sesv2"
	"stackd/internal/awscatalog"
	"stackd/internal/gateway"
	service "stackd/internal/services/sesv2"
)

func TestClassicSDKSharedTemplateBothFrontendOrders(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "classic-first"
		if reverse {
			name = "v2-first"
		}
		t.Run(name, func(t *testing.T) {
			owner := service.NewWithConfig(service.Config{})
			defer owner.Close()
			classicModel, _ := awscatalog.LookupService("ses")
			v2Model, _ := awscatalog.LookupService("sesv2")
			frontends := []gateway.Service{
				{Name: "ses", SigningName: "ses", Protocol: gateway.Query, QueryVersion: classicModel.Version, Namespace: classicModel.XMLNamespace, Provider: owner.Classic(), Model: &classicModel, Decode: classicapi.DecodeRequest},
				{Name: "sesv2", SigningName: "ses", Protocol: gateway.RestJSON, Provider: owner, Model: &v2Model, Decode: api.DecodeRequest},
			}
			if reverse {
				frontends[0], frontends[1] = frontends[1], frontends[0]
			}
			registry := &gateway.Registry{}
			for _, frontend := range frontends {
				if e := registry.Register(frontend); e != nil {
					t.Fatal(e)
				}
			}
			handler, e := gateway.New(registry, gateway.Config{})
			if e != nil {
				t.Fatal(e)
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			credential := credentials.NewStaticCredentialsProvider("test", "test", "")
			c := ses.New(ses.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credential, HTTPClient: server.Client(), RetryMaxAttempts: 1})
			c2 := sesv2.New(sesv2.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credential, HTTPClient: server.Client(), RetryMaxAttempts: 1})
			template := aws.String("shared-template")
			if _, e = c.CreateTemplate(t.Context(), &ses.CreateTemplateInput{Template: &classic.Template{TemplateName: template, SubjectPart: aws.String("Classic {{name}}"), TextPart: aws.String("Actual stored body")}}); e != nil {
				t.Fatal(e)
			}
			read, e := c2.GetEmailTemplate(t.Context(), &sesv2.GetEmailTemplateInput{TemplateName: template})
			if e != nil {
				t.Fatal(e)
			}
			if aws.ToString(read.TemplateContent.Subject) != "Classic {{name}}" || aws.ToString(read.TemplateContent.Text) != "Actual stored body" {
				t.Fatalf("v2 did not observe classic bytes: %+v", read.TemplateContent)
			}
			if _, e = c2.UpdateEmailTemplate(t.Context(), &sesv2.UpdateEmailTemplateInput{TemplateName: template, TemplateContent: &v2.EmailTemplateContent{Subject: aws.String("Updated {{name}}"), Text: aws.String("V2 replacement body")}}); e != nil {
				t.Fatal(e)
			}
			updated, e := c.GetTemplate(t.Context(), &ses.GetTemplateInput{TemplateName: template})
			if e != nil {
				t.Fatal(e)
			}
			if aws.ToString(updated.Template.SubjectPart) != "Updated {{name}}" || aws.ToString(updated.Template.TextPart) != "V2 replacement body" {
				t.Fatalf("classic did not observe replacement: %+v", updated.Template)
			}
			if _, e = c.DeleteTemplate(t.Context(), &ses.DeleteTemplateInput{TemplateName: template}); e != nil {
				t.Fatal(e)
			}
			_, e = c2.GetEmailTemplate(t.Context(), &sesv2.GetEmailTemplateInput{TemplateName: template})
			var rejected smithy.APIError
			if !errors.As(e, &rejected) || rejected.ErrorCode() != "NotFoundException" {
				t.Fatalf("deletion not shared: %v", e)
			}
		})
	}
}
