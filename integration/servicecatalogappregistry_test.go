package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroups"
	"github.com/aws/aws-sdk-go-v2/service/servicecatalogappregistry"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

// The native account cannot create AppRegistry applications (new-customer
// maintenance mode). These positive SDK checks exercise documented existing-
// customer contracts, not a successful native capture. See native-contracts.json.
func TestAppRegistryAttributeIdentityAndPagination(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "123456789012"
			source := clock.NewManual(time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC))
			cloud, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			client := func(region string) *servicecatalogappregistry.Client {
				return servicecatalogappregistry.NewFromConfig(aws.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1}, func(o *servicecatalogappregistry.Options) { o.BaseEndpoint = new(cloud.server.URL) })
			}
			appInput := servicecatalogappregistry.CreateApplicationInput{Name: new("attribute-boundaries"), ClientToken: new("application-original-token"), Description: new("original")}
			created, err := client("us-east-1").CreateApplication(t.Context(), &appInput)
			if err != nil {
				t.Fatal(err)
			}
			app := aws.ToString(created.Application.Arn)
			other, err := client("us-east-1").CreateApplication(t.Context(), &servicecatalogappregistry.CreateApplicationInput{Name: new("attribute-other"), ClientToken: new("application-other-token")})
			if err != nil {
				t.Fatal(err)
			}
			changed := appInput
			changed.Description = new("conflicting creation")
			_, err = client("us-east-1").CreateApplication(t.Context(), &changed)
			assertAPIError(t, err, "ConflictException")
			if _, err := client("us-east-1").UpdateApplication(t.Context(), &servicecatalogappregistry.UpdateApplicationInput{Application: &app, Description: new("current")}); err != nil {
				t.Fatal(err)
			}

			const originalAttributes = "{\n  \"owner\": \"original\", \"nested\": {\"revision\": 1}\n}"
			attributeInput := servicecatalogappregistry.CreateAttributeGroupInput{Name: new("attribute-one"), ClientToken: new("attribute-original-token"), Attributes: new(originalAttributes)}
			attribute, err := client("us-east-1").CreateAttributeGroup(t.Context(), &attributeInput)
			if err != nil {
				t.Fatal(err)
			}
			attr := aws.ToString(attribute.AttributeGroup.Arn)
			ids := []string{aws.ToString(attribute.AttributeGroup.Id)}
			for _, name := range []string{"attribute-two", "attribute-three"} {
				out, err := client("us-east-1").CreateAttributeGroup(t.Context(), &servicecatalogappregistry.CreateAttributeGroupInput{Name: new(name), ClientToken: new(name + "-token"), Attributes: new(`{"other":true}`)})
				if err != nil {
					t.Fatal(err)
				}
				ids = append(ids, aws.ToString(out.AttributeGroup.Id))
			}
			for _, id := range ids {
				if _, err := client("us-east-1").AssociateAttributeGroup(t.Context(), &servicecatalogappregistry.AssociateAttributeGroupInput{Application: &app, AttributeGroup: new(id)}); err != nil {
					t.Fatal(err)
				}
			}
			// Invalid attribute documents must not clobber the exact stored document.
			_, err = client("us-east-1").UpdateAttributeGroup(t.Context(), &servicecatalogappregistry.UpdateAttributeGroupInput{AttributeGroup: &attr, Attributes: new(`{"broken":`)})
			assertAPIError(t, err, "ValidationException")
			got, err := client("us-east-1").GetAttributeGroup(t.Context(), &servicecatalogappregistry.GetAttributeGroupInput{AttributeGroup: &attr})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(got.Attributes) != originalAttributes {
				t.Fatalf("failed update changed exact document: %q", aws.ToString(got.Attributes))
			}
			const currentAttributes = `{"owner":"updated","revision":2}`
			if _, err := client("us-east-1").UpdateAttributeGroup(t.Context(), &servicecatalogappregistry.UpdateAttributeGroupInput{AttributeGroup: &attr, Description: new("current attribute"), Attributes: new(currentAttributes)}); err != nil {
				t.Fatal(err)
			}
			if _, err := client("us-east-1").TagResource(t.Context(), &servicecatalogappregistry.TagResourceInput{ResourceArn: &attr, Tags: map[string]string{"revision": "current"}}); err != nil {
				t.Fatal(err)
			}
			changedAttribute := attributeInput
			changedAttribute.Attributes = new(currentAttributes)
			_, err = client("us-east-1").CreateAttributeGroup(t.Context(), &changedAttribute)
			assertAPIError(t, err, "ConflictException")

			page, err := client("us-east-1").ListAssociatedAttributeGroups(t.Context(), &servicecatalogappregistry.ListAssociatedAttributeGroupsInput{Application: &app, MaxResults: new(int32(1))})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.AttributeGroups) != 1 || page.NextToken == nil {
				t.Fatalf("expected first bounded page, got %+v", page)
			}
			_, err = client("us-east-1").ListAssociatedAttributeGroups(t.Context(), &servicecatalogappregistry.ListAssociatedAttributeGroupsInput{Application: other.Application.Arn, NextToken: page.NextToken, MaxResults: new(int32(1))})
			assertAPIError(t, err, "ValidationException")
			_, err = client("us-east-1").ListAttributeGroupsForApplication(t.Context(), &servicecatalogappregistry.ListAttributeGroupsForApplicationInput{Application: &app, NextToken: page.NextToken, MaxResults: new(int32(1))})
			assertAPIError(t, err, "ValidationException")
			_, err = client("us-west-2").GetApplication(t.Context(), &servicecatalogappregistry.GetApplicationInput{Application: &app})
			assertAPIError(t, err, "ResourceNotFoundException")
			_, err = client("us-east-1").DeleteApplication(t.Context(), &servicecatalogappregistry.DeleteApplicationInput{Application: &app})
			assertAPIError(t, err, "ConflictException")

			cloud = reopen()
			// Idempotency is bound to the creation request, not mutable current fields.
			replay, err := client("us-east-1").CreateApplication(t.Context(), &appInput)
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(replay.Application.Arn) != app || aws.ToString(replay.Application.Description) != "current" {
				t.Fatalf("application replay lost immutable request/current state: %+v", replay.Application)
			}
			attrReplay, err := client("us-east-1").CreateAttributeGroup(t.Context(), &attributeInput)
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(attrReplay.AttributeGroup.Arn) != attr || attrReplay.AttributeGroup.Tags["revision"] != "current" {
				t.Fatalf("attribute replay lost identity/current tags: %+v", attrReplay.AttributeGroup)
			}
			got, err = client("us-east-1").GetAttributeGroup(t.Context(), &servicecatalogappregistry.GetAttributeGroupInput{AttributeGroup: &attr})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(got.Attributes) != currentAttributes {
				t.Fatal("replay restored creation document over updated attribute")
			}
			found := slices.Clone(page.AttributeGroups)
			token := page.NextToken
			for pages := 0; token != nil; pages++ {
				if pages >= len(ids) {
					t.Fatal("attribute cursor did not terminate")
				}
				out, err := client("us-east-1").ListAssociatedAttributeGroups(t.Context(), &servicecatalogappregistry.ListAssociatedAttributeGroupsInput{Application: &app, MaxResults: new(int32(1)), NextToken: token})
				if err != nil {
					t.Fatal(err)
				}
				found = append(found, out.AttributeGroups...)
				token = out.NextToken
			}
			slices.Sort(found)
			slices.Sort(ids)
			if !slices.Equal(found, ids) {
				t.Fatalf("cursor lost or repeated retained links: %v, want %v", found, ids)
			}
			for _, id := range ids {
				if _, err := client("us-east-1").DisassociateAttributeGroup(t.Context(), &servicecatalogappregistry.DisassociateAttributeGroupInput{Application: &app, AttributeGroup: new(id)}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := client("us-east-1").DeleteApplication(t.Context(), &servicecatalogappregistry.DeleteApplicationInput{Application: &app}); err != nil {
				t.Fatal(err)
			}
			fresh, err := client("us-east-1").CreateApplication(t.Context(), &servicecatalogappregistry.CreateApplicationInput{Name: appInput.Name, ClientToken: new("new-incarnation-token")})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(fresh.Application.Id) == aws.ToString(created.Application.Id) || fresh.Application.ApplicationTag["awsApplication"] == created.Application.ApplicationTag["awsApplication"] {
				t.Fatal("same-name application inherited prior incarnation")
			}
			_, err = client("us-east-1").GetApplication(t.Context(), &servicecatalogappregistry.GetApplicationInput{Application: created.Application.Id})
			assertAPIError(t, err, "ResourceNotFoundException")
			links, err := client("us-east-1").ListAssociatedAttributeGroups(t.Context(), &servicecatalogappregistry.ListAssociatedAttributeGroupsInput{Application: fresh.Application.Arn})
			if err != nil {
				t.Fatal(err)
			}
			if len(links.AttributeGroups) != 0 {
				t.Fatal("replacement application inherited prior attribute links")
			}
		})
	}
}

func TestAppRegistryParameterIncarnationFencesGrouping(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "123456789012"
			cloud, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			config := func() aws.Config {
				return aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1}
			}
			apps := func() *servicecatalogappregistry.Client {
				return servicecatalogappregistry.NewFromConfig(config(), func(o *servicecatalogappregistry.Options) { o.BaseEndpoint = new(cloud.server.URL) })
			}
			groups := func() *resourcegroups.Client {
				return resourcegroups.NewFromConfig(config(), func(o *resourcegroups.Options) { o.BaseEndpoint = new(cloud.server.URL) })
			}
			parameters := func() *ssm.Client {
				return ssm.NewFromConfig(config(), func(o *ssm.Options) { o.BaseEndpoint = new(cloud.server.URL) })
			}
			app, err := apps().CreateApplication(t.Context(), &servicecatalogappregistry.CreateApplicationInput{Name: new("incarnation-boundary"), ClientToken: new("incarnation-application-token")})
			if err != nil {
				t.Fatal(err)
			}
			group := app.Application.ApplicationTag["awsApplication"]
			const parameter = "/appregistry/incarnation"
			const arn = "arn:aws:ssm:us-east-1:" + account + ":parameter" + parameter
			if _, err := parameters().PutParameter(t.Context(), &ssm.PutParameterInput{Name: new(parameter), Type: "String", Value: new("first")}); err != nil {
				t.Fatal(err)
			}
			out, err := groups().GroupResources(t.Context(), &resourcegroups.GroupResourcesInput{Group: &group, ResourceArns: []string{arn}})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(out.Succeeded, []string{arn}) || len(out.Failed) != 0 || len(out.Pending) != 0 {
				t.Fatalf("actual owner grouping failed: %+v", out)
			}
			if _, err := parameters().PutParameter(t.Context(), &ssm.PutParameterInput{Name: new(parameter), Type: "String", Value: new("updated"), Overwrite: new(true)}); err != nil {
				t.Fatal(err)
			}
			cloud = reopen()
			members, err := groups().ListGroupResources(t.Context(), &resourcegroups.ListGroupResourcesInput{Group: &group})
			if err != nil {
				t.Fatal(err)
			}
			if len(members.Resources) != 1 || members.Resources[0].Identifier == nil || aws.ToString(members.Resources[0].Identifier.ResourceArn) != arn {
				t.Fatalf("ordinary parameter version update changed incarnation: %+v", members)
			}
			status, err := groups().ListGroupingStatuses(t.Context(), &resourcegroups.ListGroupingStatusesInput{Group: &group})
			if err != nil {
				t.Fatal(err)
			}
			if len(status.GroupingStatuses) != 1 || status.GroupingStatuses[0].Status != "SUCCESS" || status.GroupingStatuses[0].Action != "GROUP" {
				t.Fatalf("retained grouping status differs: %+v", status)
			}
			if _, err := parameters().DeleteParameter(t.Context(), &ssm.DeleteParameterInput{Name: new(parameter)}); err != nil {
				t.Fatal(err)
			}
			if _, err := parameters().PutParameter(t.Context(), &ssm.PutParameterInput{Name: new(parameter), Type: "String", Value: new("replacement")}); err != nil {
				t.Fatal(err)
			}
			cloud = reopen()
			members, err = groups().ListGroupResources(t.Context(), &resourcegroups.ListGroupResourcesInput{Group: &group})
			if err != nil {
				t.Fatal(err)
			}
			if len(members.Resources) != 0 {
				t.Fatalf("replacement parameter inherited membership: %+v", members)
			}
			status, err = groups().ListGroupingStatuses(t.Context(), &resourcegroups.ListGroupingStatusesInput{Group: &group})
			if err != nil {
				t.Fatal(err)
			}
			if len(status.GroupingStatuses) != 0 {
				t.Fatalf("replacement parameter inherited old success: %+v", status)
			}
			tags, err := parameters().ListTagsForResource(t.Context(), &ssm.ListTagsForResourceInput{ResourceType: "Parameter", ResourceId: new(parameter)})
			if err != nil {
				t.Fatal(err)
			}
			for _, tag := range tags.TagList {
				if aws.ToString(tag.Key) == "awsApplication" {
					t.Fatal("replacement parameter inherited old application tag")
				}
			}
			out, err = groups().GroupResources(t.Context(), &resourcegroups.GroupResourcesInput{Group: &group, ResourceArns: []string{arn}})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(out.Succeeded, []string{arn}) || len(out.Failed) != 0 {
				t.Fatalf("replacement owner could not be explicitly grouped: %+v", out)
			}
			ungrouped, err := groups().UngroupResources(t.Context(), &resourcegroups.UngroupResourcesInput{Group: &group, ResourceArns: []string{arn}})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ungrouped.Succeeded, []string{arn}) || len(ungrouped.Failed) != 0 {
				t.Fatalf("explicit replacement ungroup failed: %+v", ungrouped)
			}
			status, err = groups().ListGroupingStatuses(t.Context(), &resourcegroups.ListGroupingStatusesInput{Group: &group})
			if err != nil {
				t.Fatal(err)
			}
			if len(status.GroupingStatuses) != 1 || status.GroupingStatuses[0].Action != "UNGROUP" || status.GroupingStatuses[0].Status != "SUCCESS" {
				t.Fatalf("ungroup failed to replace last action: %+v", status)
			}
		})
	}
}

func TestAppRegistryNativeErrorPrecedence(t *testing.T) {
	var fixture struct {
		Region       string
		Identity     struct{ Account string }
		Observations []struct {
			Case, Operation, Code string
			Input                 json.RawMessage
		}
	}
	awsReadFixture(t, "appregistry/native-boundaries.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, _ := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Identity.Account}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			client := servicecatalogappregistry.NewFromConfig(aws.Config{Region: fixture.Region, Credentials: credentials.NewStaticCredentialsProvider(fixture.Identity.Account, "test", ""), HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1}, func(o *servicecatalogappregistry.Options) { o.BaseEndpoint = new(cloud.server.URL) })
			for _, row := range fixture.Observations {
				switch row.Case {
				case "application-missing", "application-invalid-identifier",
					"application-update-long-description", "attribute-update-invalid-json",
					"attribute-update-empty", "associate-missing-RESOURCE_TAG_VALUE":
					t.Run(row.Case, func(t *testing.T) {
						operation := map[string]string{"get_application": "GetApplication", "update_application": "UpdateApplication", "update_attribute_group": "UpdateAttributeGroup", "associate_resource": "AssociateResource"}[row.Operation]
						_, err := awstest.CallSDK(t.Context(), client, operation, row.Input)
						assertAPIError(t, err, row.Code)
					})
				}
			}
		})
	}
}
