package stackd_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"stackd"
	"stackd/internal/awstest"
)

func documentTagMap(tags []ssmtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return out
}

func TestSSMDocumentTaggingNativeReplay(t *testing.T) {
	var fixture struct {
		Account string
		Calls   []struct {
			Label, Operation, Code string
			Input, Output          json.RawMessage
		}
	}
	awsReadFixture(t, "resourcegroupstaggingapi/ssm_documents.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cl, _ := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account})
			client := cl.ssm("us-east-1", fixture.Account, "test")
			for _, row := range fixture.Calls {
				t.Run(row.Label, func(t *testing.T) {
					out, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
					if row.Code != "Success" {
						assertAPIError(t, err, row.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if actual, ok := out.(*ssm.ListTagsForResourceOutput); ok {
						var expected ssm.ListTagsForResourceOutput
						if err := json.Unmarshal(row.Output, &expected); err != nil {
							t.Fatal(err)
						}
						if got, want := documentTagMap(actual.TagList), documentTagMap(expected.TagList); !reflect.DeepEqual(got, want) {
							t.Fatalf("native document tags got %v want %v", got, want)
						}
					}
				})
			}
		})
	}
}

func TestResourceGroupsTaggingSSMDocumentLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			const name = "TaggedDocument"
			const never = "NeverTaggedDocument"
			const arn = "arn:aws:ssm:us-east-1:" + account + ":document/" + name
			const neverARN = "arn:aws:ssm:us-east-1:" + account + ":document/" + never
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			client := cl.ssm("us-east-1", account, "test")
			for _, document := range []string{name, never} {
				input := &ssm.CreateDocumentInput{Name: new(document), Content: new(shellDocument("tagging")), DocumentType: ssmtypes.DocumentTypeCommand}
				if document == name {
					input.Tags = []ssmtypes.Tag{{Key: new("source"), Value: new("native")}}
				}
				if _, err := client.CreateDocument(t.Context(), input); err != nil {
					t.Fatal(err)
				}
			}
			tags := taggingClient(cl, "us-east-1", account, "test")
			query := &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: []string{arn, neverARN}}
			listed, err := tags.GetResources(t.Context(), query)
			if err != nil || !reflect.DeepEqual(taggingMappings(listed.ResourceTagMappingList), map[string]map[string]string{arn: {"source": "native"}}) {
				t.Fatalf("native create discovery: %+v %v", listed, err)
			}
			changed, err := tags.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{arn}, Tags: map[string]string{"source": "rgta", "empty": ""}})
			if err != nil || len(changed.FailedResourcesMap) != 0 {
				t.Fatalf("document owner mutation: %+v %v", changed, err)
			}
			current, err := client.ListTagsForResource(t.Context(), &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new(arn)})
			if err != nil || !reflect.DeepEqual(documentTagMap(current.TagList), map[string]string{"source": "rgta", "empty": ""}) {
				t.Fatalf("native read after RGTA mutation: %+v %v", current, err)
			}
			removed, err := tags.UntagResources(t.Context(), &resourcegroupstaggingapi.UntagResourcesInput{ResourceARNList: []string{arn}, TagKeys: []string{"source"}})
			if err != nil || len(removed.FailedResourcesMap) != 0 {
				t.Fatalf("document owner removal: %+v %v", removed, err)
			}
			current, err = client.ListTagsForResource(t.Context(), &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new(name)})
			if err != nil || !reflect.DeepEqual(documentTagMap(current.TagList), map[string]string{"empty": ""}) {
				t.Fatalf("native read after RGTA removal: %+v %v", current, err)
			}
			for _, isolated := range []*ssm.Client{cl.ssm("us-west-2", account, "test"), cl.ssm("us-east-1", "444455556666", "test")} {
				_, err := isolated.ListTagsForResource(t.Context(), &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new(name)})
				assertAPIError(t, err, "InvalidResourceId")
				_, err = isolated.AddTagsToResource(t.Context(), &ssm.AddTagsToResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new(arn), Tags: []ssmtypes.Tag{{Key: new("foreign"), Value: new("denied")}}})
				assertAPIError(t, err, "InvalidResourceId")
			}
			if _, err := client.RemoveTagsFromResource(t.Context(), &ssm.RemoveTagsFromResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new(name), TagKeys: []string{"empty"}}); err != nil {
				t.Fatal(err)
			}
			// No inventory read intervenes between the last native removal and reopen.
			cl = reopen()
			tags = taggingClient(cl, "us-east-1", account, "test")
			client = cl.ssm("us-east-1", account, "test")
			listed, err = tags.GetResources(t.Context(), query)
			if err != nil || !reflect.DeepEqual(taggingMappings(listed.ResourceTagMappingList), map[string]map[string]string{arn: {}}) {
				t.Fatalf("previously tagged membership after reopen: %+v %v", listed, err)
			}
			if _, err := client.DeleteDocument(t.Context(), &ssm.DeleteDocumentInput{Name: new(name)}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.CreateDocument(t.Context(), &ssm.CreateDocumentInput{Name: new(name), Content: new(shellDocument("new incarnation")), DocumentType: ssmtypes.DocumentTypeCommand}); err != nil {
				t.Fatal(err)
			}
			listed, err = tags.GetResources(t.Context(), query)
			if err != nil || len(listed.ResourceTagMappingList) != 0 {
				t.Fatalf("deleted document membership leaked to untagged incarnation: %+v %v", listed, err)
			}
			// Registering document tag operations must not steal Parameter Store's routes.
			if _, err := client.PutParameter(t.Context(), &ssm.PutParameterInput{Name: new(name), Value: new("parameter"), Type: ssmtypes.ParameterTypeString}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.AddTagsToResource(t.Context(), &ssm.AddTagsToResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingParameter, ResourceId: new(name), Tags: []ssmtypes.Tag{{Key: new("owner"), Value: new("parameter")}}}); err != nil {
				t.Fatal(err)
			}
			parameter, err := client.ListTagsForResource(t.Context(), &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingParameter, ResourceId: new(name)})
			if err != nil || !reflect.DeepEqual(documentTagMap(parameter.TagList), map[string]string{"owner": "parameter"}) {
				t.Fatalf("parameter owner route: %+v %v", parameter, err)
			}
			if _, err := client.RemoveTagsFromResource(t.Context(), &ssm.RemoveTagsFromResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingParameter, ResourceId: new(name), TagKeys: []string{"owner"}}); err != nil {
				t.Fatal(err)
			}
			_, err = client.ListTagsForResource(t.Context(), &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingManagedInstance, ResourceId: new("mi-00000000000000000")})
			assertAPIError(t, err, "UnsupportedOperation")
			_, err = client.AddTagsToResource(t.Context(), &ssm.AddTagsToResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new("AWS-RunShellScript"), Tags: []ssmtypes.Tag{{Key: new("forbidden"), Value: new("managed")}}})
			assertAPIError(t, err, "InvalidResourceId")
			_, err = client.RemoveTagsFromResource(t.Context(), &ssm.RemoveTagsFromResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new("AWS-RunShellScript"), TagKeys: []string{"forbidden"}})
			assertAPIError(t, err, "InvalidResourceId")
		})
	}
}

func TestResourceGroupsTaggingSSMDocumentCurrentAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			const name = "DocumentTagAuthority"
			const arn = "arn:aws:ssm:us-east-1:" + account + ":document/" + name
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			root := cl.ssm("us-east-1", account, "test")
			if _, err := root.CreateDocument(t.Context(), &ssm.CreateDocumentInput{Name: new(name), Content: new(shellDocument("authority")), DocumentType: ssmtypes.DocumentTypeCommand, Tags: []ssmtypes.Tag{{Key: new("team"), Value: new("compute")}}}); err != nil {
				t.Fatal(err)
			}
			_, key, secret := cl.user(t, account, "document-tagger")
			putUserPolicy(t, cl.iam(account, "test", ""), "document-tagger", `{"Statement":{"Effect":"Allow","Action":"tag:*","Resource":"*"}}`)
			caller := taggingClient(cl, "us-east-1", key, secret)
			request := &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{arn}, Tags: map[string]string{"caller": "allowed"}}
			denied, err := caller.TagResources(t.Context(), request)
			if err != nil || len(denied.FailedResourcesMap) != 1 || !strings.Contains(string(denied.FailedResourcesMap[arn].ErrorCode), "AccessDenied") {
				t.Fatalf("missing native authority: %+v %v", denied, err)
			}
			policy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"tag:*","Resource":"*"},{"Effect":"Allow","Action":"ssm:AddTagsToResource","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"compute","aws:RequestTag/caller":"allowed"},"ForAllValues:StringEquals":{"aws:TagKeys":["caller"]}}},{"Effect":"Allow","Action":["ssm:RemoveTagsFromResource","ssm:ListTagsForResource"],"Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"compute"},"ForAllValues:StringEquals":{"aws:TagKeys":["caller"]}}}]}`, arn, arn)
			putUserPolicy(t, cl.iam(account, "test", ""), "document-tagger", policy)
			allowed, err := caller.TagResources(t.Context(), request)
			if err != nil || len(allowed.FailedResourcesMap) != 0 {
				t.Fatalf("conditional native authority: %+v %v", allowed, err)
			}
			native := cl.ssm("us-east-1", key, secret)
			current, err := native.ListTagsForResource(t.Context(), &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new(name)})
			if err != nil || !reflect.DeepEqual(documentTagMap(current.TagList), map[string]string{"team": "compute", "caller": "allowed"}) {
				t.Fatalf("authorized native listing: %+v %v", current, err)
			}
			for _, rejectedTags := range []map[string]string{{"caller": "forbidden"}, {"caller": "allowed", "extra": "forbidden"}} {
				denied, err := caller.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{arn}, Tags: rejectedTags})
				if err != nil || len(denied.FailedResourcesMap) != 1 || !strings.Contains(string(denied.FailedResourcesMap[arn].ErrorCode), "AccessDenied") {
					t.Fatalf("request-tag/key conditions: %+v %v", denied, err)
				}
			}
			_, err = native.RemoveTagsFromResource(t.Context(), &ssm.RemoveTagsFromResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new(name), TagKeys: []string{"team"}})
			assertAPIError(t, err, "AccessDeniedException")
			if _, err := native.RemoveTagsFromResource(t.Context(), &ssm.RemoveTagsFromResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new(name), TagKeys: []string{"caller"}}); err != nil {
				t.Fatal(err)
			}
			if restored, err := caller.TagResources(t.Context(), request); err != nil || len(restored.FailedResourcesMap) != 0 {
				t.Fatalf("restoring allowed tag: %+v %v", restored, err)
			}
			putUserPolicy(t, cl.iam(account, "test", ""), "document-tagger", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":["ssm:AddTagsToResource","ssm:RemoveTagsFromResource","ssm:ListTagsForResource"],"Resource":"*"}]}`)
			cl = reopen()
			caller = taggingClient(cl, "us-east-1", key, secret)
			native = cl.ssm("us-east-1", key, secret)
			request.Tags["caller"] = "forbidden"
			denied, err = caller.TagResources(t.Context(), request)
			if err != nil || len(denied.FailedResourcesMap) != 1 || !strings.Contains(string(denied.FailedResourcesMap[arn].ErrorCode), "AccessDenied") {
				t.Fatalf("current native deny after reopen: %+v %v", denied, err)
			}
			untagged, err := caller.UntagResources(t.Context(), &resourcegroupstaggingapi.UntagResourcesInput{ResourceARNList: []string{arn}, TagKeys: []string{"caller"}})
			if err != nil || len(untagged.FailedResourcesMap) != 1 || !strings.Contains(string(untagged.FailedResourcesMap[arn].ErrorCode), "AccessDenied") {
				t.Fatalf("current native untag deny after reopen: %+v %v", untagged, err)
			}
			_, err = native.ListTagsForResource(t.Context(), &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new(name)})
			assertAPIError(t, err, "AccessDeniedException")
			root = cl.ssm("us-east-1", account, "test")
			current, err = root.ListTagsForResource(t.Context(), &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new(name)})
			if err != nil || !reflect.DeepEqual(documentTagMap(current.TagList), map[string]string{"team": "compute", "caller": "allowed"}) {
				t.Fatalf("denied mutation changed document: %+v %v", current, err)
			}
			trails := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: new(cl.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: cl.server.Client(), RetryMaxAttempts: 1})
			event := auditLatestRecord(t, trails, "ListTagsForResource")
			if event["readOnly"] != true || event["eventSource"] != "ssm.amazonaws.com" {
				t.Fatalf("document tagging read classification: %v", event)
			}
			// This fails generated tag-key validation before the owner executes; the
			// decoded Document input must still reach its owner for native audit.
			badKey := strings.Repeat("x", 129)
			_, err = root.AddTagsToResource(t.Context(), &ssm.AddTagsToResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: new(name), Tags: []ssmtypes.Tag{{Key: new(badKey), Value: new("bad")}}})
			assertAPIError(t, err, "ValidationException")
			event = auditLatestRecord(t, trails, "AddTagsToResource")
			parameters, ok := event["requestParameters"].(map[string]any)
			if !ok || parameters["resourceType"] != "Document" || parameters["resourceId"] != name || event["errorCode"] != "ValidationException" {
				t.Fatalf("decoded document rejection audit lost: %v", event)
			}
		})
	}
}
