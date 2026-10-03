package stackd_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	apptypes "github.com/aws/aws-sdk-go-v2/service/appconfig/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroups"
	rgtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroups/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"

	"stackd"
)

func requireAppConfigNativeTags(t *testing.T, client *appconfig.Client, arns []string, want map[string]string) {
	t.Helper()
	for _, arn := range arns {
		current, err := client.ListTagsForResource(t.Context(), &appconfig.ListTagsForResourceInput{ResourceArn: new(arn)})
		if err != nil {
			t.Fatalf("native tags for %s: %v", arn, err)
		}
		if !reflect.DeepEqual(current.Tags, want) {
			t.Fatalf("native tags for %s: got %v want %v", arn, current.Tags, want)
		}
	}
}

func TestResourceGroupsTaggingAppConfigLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			const prefix = "arn:aws:appconfig:us-east-1:" + account + ":"
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			client := cl.appconfig("us-east-1", account, "test")
			nativeTags := map[string]string{"source": "native"}
			application, err := client.CreateApplication(t.Context(), &appconfig.CreateApplicationInput{Name: new("tagged-application"), Tags: nativeTags})
			if err != nil {
				t.Fatal(err)
			}
			environment, err := client.CreateEnvironment(t.Context(), &appconfig.CreateEnvironmentInput{ApplicationId: application.Id, Name: new("tagged-environment"), Tags: nativeTags})
			if err != nil {
				t.Fatal(err)
			}
			profile, err := client.CreateConfigurationProfile(t.Context(), &appconfig.CreateConfigurationProfileInput{ApplicationId: application.Id, Name: new("tagged-profile"), LocationUri: new("hosted"), Tags: nativeTags})
			if err != nil {
				t.Fatal(err)
			}
			strategy, err := client.CreateDeploymentStrategy(t.Context(), &appconfig.CreateDeploymentStrategyInput{Name: new("tagged-strategy"), DeploymentDurationInMinutes: new(int32(0)), GrowthFactor: new(float32(100)), ReplicateTo: apptypes.ReplicateToNone, Tags: nativeTags})
			if err != nil {
				t.Fatal(err)
			}
			never, err := client.CreateApplication(t.Context(), &appconfig.CreateApplicationInput{Name: new("never-tagged")})
			if err != nil {
				t.Fatal(err)
			}
			applicationARN := prefix + "application/" + aws.ToString(application.Id)
			arns := []string{
				applicationARN,
				applicationARN + "/environment/" + aws.ToString(environment.Id),
				applicationARN + "/configurationprofile/" + aws.ToString(profile.Id),
				prefix + "deploymentstrategy/" + aws.ToString(strategy.Id),
			}
			query := &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: append(append([]string{}, arns...), prefix+"application/"+aws.ToString(never.Id))}
			tags := taggingClient(cl, "us-east-1", account, "test")
			want := make(map[string]map[string]string, len(arns))
			for _, arn := range arns {
				want[arn] = nativeTags
			}
			listed, err := tags.GetResources(t.Context(), query)
			if err != nil {
				t.Fatal(err)
			}
			if got := taggingMappings(listed.ResourceTagMappingList); !reflect.DeepEqual(got, want) {
				t.Fatalf("native create discovery: got %v want %v", got, want)
			}
			// Native AppConfig discovery classifies nested resources under the
			// application's ARN root, not under their final path component.
			for _, filter := range []struct {
				resourceType string
				arns         []string
			}{
				{"appconfig", arns},
				{"appconfig:application", arns[:3]},
				{"appconfig:environment", nil},
				{"appconfig:configurationprofile", nil},
				{"appconfig:deploymentstrategy", arns[3:]},
			} {
				listed, err := tags.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceTypeFilters: []string{filter.resourceType}})
				if err != nil {
					t.Fatal(err)
				}
				expected := map[string]map[string]string{}
				for _, arn := range filter.arns {
					expected[arn] = nativeTags
				}
				if got := taggingMappings(listed.ResourceTagMappingList); !reflect.DeepEqual(got, expected) {
					t.Fatalf("resource type %s: got %v want %v", filter.resourceType, got, expected)
				}
			}
			// Resource Groups uses precise CloudFormation types even though
			// RGTA's application filter also includes nested AppConfig resources.
			groups := resourcegroups.New(resourcegroups.Options{Region: "us-east-1", BaseEndpoint: new(cl.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: cl.server.Client(), RetryMaxAttempts: 1})
			for _, selection := range []struct{ resourceType, arn string }{
				{"AWS::AppConfig::Application", applicationARN},
				{"AWS::AppConfig::ConfigurationProfile", arns[2]},
			} {
				query := fmt.Sprintf(`{"ResourceTypeFilters":[%q],"TagFilters":[{"Key":"source","Values":["native"]}]}`, selection.resourceType)
				found, err := groups.SearchResources(t.Context(), &resourcegroups.SearchResourcesInput{ResourceQuery: &rgtypes.ResourceQuery{Type: rgtypes.QueryTypeTagFilters10, Query: new(query)}})
				if err != nil {
					t.Fatal(err)
				}
				if len(found.ResourceIdentifiers) != 1 || aws.ToString(found.ResourceIdentifiers[0].ResourceArn) != selection.arn || aws.ToString(found.ResourceIdentifiers[0].ResourceType) != selection.resourceType || found.NextToken != nil {
					t.Fatalf("Resource Groups type %s selected wrong resources: %+v", selection.resourceType, found)
				}
			}
			changed, err := tags.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: arns, Tags: map[string]string{"source": "rgta", "empty": ""}})
			if err != nil || len(changed.FailedResourcesMap) != 0 {
				t.Fatalf("owner tag mutation: %+v %v", changed, err)
			}
			requireAppConfigNativeTags(t, client, arns, map[string]string{"source": "rgta", "empty": ""})
			removed, err := tags.UntagResources(t.Context(), &resourcegroupstaggingapi.UntagResourcesInput{ResourceARNList: arns, TagKeys: []string{"source"}})
			if err != nil || len(removed.FailedResourcesMap) != 0 {
				t.Fatalf("owner tag removal: %+v %v", removed, err)
			}
			requireAppConfigNativeTags(t, client, arns, map[string]string{"empty": ""})
			for _, scope := range []struct{ account, region string }{{account, "us-west-2"}, {"444455556666", "us-east-1"}} {
				isolated := taggingClient(cl, scope.region, scope.account, "test")
				listed, err := isolated.GetResources(t.Context(), query)
				if err != nil || len(listed.ResourceTagMappingList) != 0 {
					t.Fatalf("discovery crossed scope %v: %+v %v", scope, listed, err)
				}
				changed, err := isolated.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: arns, Tags: map[string]string{"foreign": "forbidden"}})
				if err != nil || len(changed.FailedResourcesMap) != len(arns) {
					t.Fatalf("mutation crossed scope %v: %+v %v", scope, changed, err)
				}
			}
			requireAppConfigNativeTags(t, client, arns, map[string]string{"empty": ""})
			// This resource is never read by tagging discovery before its tags are
			// removed, so durable membership cannot depend on an inventory read.
			unseen, err := client.CreateApplication(t.Context(), &appconfig.CreateApplicationInput{Name: new("native-only-history"), Tags: map[string]string{"empty": ""}})
			if err != nil {
				t.Fatal(err)
			}
			unseenARN := prefix + "application/" + aws.ToString(unseen.Id)
			arns = append(arns, unseenARN)
			query.ResourceARNList = append(query.ResourceARNList, unseenARN)
			for _, arn := range arns {
				if _, err := client.UntagResource(t.Context(), &appconfig.UntagResourceInput{ResourceArn: new(arn), TagKeys: []string{"empty"}}); err != nil {
					t.Fatal(err)
				}
				want[arn] = map[string]string{}
			}
			// No inventory read intervenes between native removal and reopen.
			cl = reopen()
			client = cl.appconfig("us-east-1", account, "test")
			tags = taggingClient(cl, "us-east-1", account, "test")
			listed, err = tags.GetResources(t.Context(), query)
			if err != nil {
				t.Fatal(err)
			}
			if got := taggingMappings(listed.ResourceTagMappingList); !reflect.DeepEqual(got, want) {
				t.Fatalf("previously tagged membership after reopen: got %v want %v", got, want)
			}
			if _, err := client.DeleteEnvironment(t.Context(), &appconfig.DeleteEnvironmentInput{ApplicationId: application.Id, EnvironmentId: environment.Id}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.DeleteConfigurationProfile(t.Context(), &appconfig.DeleteConfigurationProfileInput{ApplicationId: application.Id, ConfigurationProfileId: profile.Id}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.DeleteDeploymentStrategy(t.Context(), &appconfig.DeleteDeploymentStrategyInput{DeploymentStrategyId: strategy.Id}); err != nil {
				t.Fatal(err)
			}
			listed, err = tags.GetResources(t.Context(), query)
			if err != nil {
				t.Fatal(err)
			}
			if got, expected := taggingMappings(listed.ResourceTagMappingList), map[string]map[string]string{applicationARN: {}, unseenARN: {}}; !reflect.DeepEqual(got, expected) {
				t.Fatalf("child deletion affected surviving applications: got %v want %v", got, expected)
			}
			for _, id := range []*string{application.Id, unseen.Id} {
				if _, err := client.DeleteApplication(t.Context(), &appconfig.DeleteApplicationInput{ApplicationId: id}); err != nil {
					t.Fatal(err)
				}
			}
			listed, err = tags.GetResources(t.Context(), query)
			if err != nil || len(listed.ResourceTagMappingList) != 0 {
				t.Fatalf("deleted resources remained discoverable: %+v %v", listed, err)
			}
		})
	}
}

func TestResourceGroupsTaggingAppConfigCurrentAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			root := cl.appconfig("us-east-1", account, "test")
			var arns []string
			for _, name := range []string{"authorized", "outside-resource-scope"} {
				application, err := root.CreateApplication(t.Context(), &appconfig.CreateApplicationInput{Name: new(name), Tags: map[string]string{"team": "config"}})
				if err != nil {
					t.Fatal(err)
				}
				arns = append(arns, fmt.Sprintf("arn:aws:appconfig:us-east-1:%s:application/%s", account, aws.ToString(application.Id)))
			}
			arn := arns[0]
			_, key, secret := cl.user(t, account, "appconfig-tagger")
			caller := taggingClient(cl, "us-east-1", key, secret)
			putUserPolicy(t, cl.iam(account, "test", ""), "appconfig-tagger", `{"Statement":{"Effect":"Allow","Action":["appconfig:ListApplications","appconfig:ListTagsForResource"],"Resource":"*"}}`)
			requireAppConfigNativeTags(t, cl.appconfig("us-east-1", key, secret), []string{arn}, map[string]string{"team": "config"})
			_, err := caller.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: arns})
			assertAPIError(t, err, "AccessDenied")
			putUserPolicy(t, cl.iam(account, "test", ""), "appconfig-tagger", `{"Statement":{"Effect":"Allow","Action":"tag:*","Resource":"*"}}`)
			listed, err := caller.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: arns})
			if err != nil {
				t.Fatal(err)
			}
			if got, want := taggingMappings(listed.ResourceTagMappingList), map[string]map[string]string{arns[0]: {"team": "config"}, arns[1]: {"team": "config"}}; !reflect.DeepEqual(got, want) {
				t.Fatalf("tag:GetResources required native list authority: got %v want %v", got, want)
			}
			assertTagDenied := func(resource string, values map[string]string) {
				t.Helper()
				out, err := caller.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{resource}, Tags: values})
				if err != nil || len(out.FailedResourcesMap) != 1 || !strings.Contains(string(out.FailedResourcesMap[resource].ErrorCode), "AccessDenied") {
					t.Fatalf("expected native tag authority rejection for %s: %+v %v", resource, out, err)
				}
			}
			assertUntagDenied := func(keys []string) {
				t.Helper()
				out, err := caller.UntagResources(t.Context(), &resourcegroupstaggingapi.UntagResourcesInput{ResourceARNList: []string{arn}, TagKeys: keys})
				if err != nil || len(out.FailedResourcesMap) != 1 || !strings.Contains(string(out.FailedResourcesMap[arn].ErrorCode), "AccessDenied") {
					t.Fatalf("expected native untag authority rejection: %+v %v", out, err)
				}
			}
			allowedTags := map[string]string{"caller": "allowed"}
			assertTagDenied(arn, allowedTags)
			assertUntagDenied([]string{"team"})
			requireAppConfigNativeTags(t, root, arns, map[string]string{"team": "config"})
			policy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"tag:*","Resource":"*"},{"Effect":"Allow","Action":"appconfig:TagResource","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"config","aws:RequestTag/caller":"allowed"},"ForAllValues:StringEquals":{"aws:TagKeys":["caller"]}}},{"Effect":"Allow","Action":"appconfig:UntagResource","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"config"},"ForAllValues:StringEquals":{"aws:TagKeys":["caller"]}}}]}`, arn, arn)
			putUserPolicy(t, cl.iam(account, "test", ""), "appconfig-tagger", policy)
			request := &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{arn}, Tags: allowedTags}
			allowed, err := caller.TagResources(t.Context(), request)
			if err != nil || len(allowed.FailedResourcesMap) != 0 {
				t.Fatalf("conditional native tag authority: %+v %v", allowed, err)
			}
			requireAppConfigNativeTags(t, root, []string{arn}, map[string]string{"team": "config", "caller": "allowed"})
			assertTagDenied(arns[1], allowedTags)
			assertTagDenied(arn, map[string]string{"caller": "forbidden"})
			assertTagDenied(arn, map[string]string{"caller": "allowed", "extra": "forbidden"})
			assertUntagDenied([]string{"team"})
			requireAppConfigNativeTags(t, root, []string{arn}, map[string]string{"team": "config", "caller": "allowed"})
			requireAppConfigNativeTags(t, root, arns[1:], map[string]string{"team": "config"})
			removed, err := caller.UntagResources(t.Context(), &resourcegroupstaggingapi.UntagResourcesInput{ResourceARNList: []string{arn}, TagKeys: []string{"caller"}})
			if err != nil || len(removed.FailedResourcesMap) != 0 {
				t.Fatalf("conditional native untag authority: %+v %v", removed, err)
			}
			requireAppConfigNativeTags(t, root, []string{arn}, map[string]string{"team": "config"})
			if _, err := root.TagResource(t.Context(), &appconfig.TagResourceInput{ResourceArn: new(arn), Tags: map[string]string{"team": "other"}}); err != nil {
				t.Fatal(err)
			}
			assertTagDenied(arn, allowedTags)
			assertUntagDenied([]string{"caller"})
			requireAppConfigNativeTags(t, root, []string{arn}, map[string]string{"team": "other"})
			if _, err := root.TagResource(t.Context(), &appconfig.TagResourceInput{ResourceArn: new(arn), Tags: map[string]string{"team": "config"}}); err != nil {
				t.Fatal(err)
			}
			if restored, err := caller.TagResources(t.Context(), request); err != nil || len(restored.FailedResourcesMap) != 0 {
				t.Fatalf("restoring current resource-tag authority: %+v %v", restored, err)
			}
			putUserPolicy(t, cl.iam(account, "test", ""), "appconfig-tagger", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":["appconfig:TagResource","appconfig:UntagResource","appconfig:ListTagsForResource"],"Resource":"*"}]}`)
			cl = reopen()
			caller = taggingClient(cl, "us-east-1", key, secret)
			assertTagDenied(arn, map[string]string{"caller": "revoked"})
			assertUntagDenied([]string{"caller"})
			_, err = cl.appconfig("us-east-1", key, secret).ListTagsForResource(t.Context(), &appconfig.ListTagsForResourceInput{ResourceArn: new(arn)})
			assertAPIError(t, err, "AccessDenied")
			root = cl.appconfig("us-east-1", account, "test")
			requireAppConfigNativeTags(t, root, []string{arn}, map[string]string{"team": "config", "caller": "allowed"})
		})
	}
}

func TestResourceGroupsTaggingAppConfigExtensionVersions(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			client := cl.appconfig("us-east-1", account, "test")
			application, err := client.CreateApplication(t.Context(), &appconfig.CreateApplicationInput{Name: new("extension-owner")})
			if err != nil {
				t.Fatal(err)
			}
			var versions []*appconfig.CreateExtensionOutput
			for _, version := range []string{"one", "two"} {
				input := &appconfig.CreateExtensionInput{
					Name:    new("versioned-tags"),
					Actions: map[string][]apptypes.Action{"PRE_START_DEPLOYMENT": {{Name: new("never-invoke"), Uri: new("arn:aws:lambda:us-east-1:" + account + ":function:absent")}}},
					Tags:    map[string]string{"version": version},
				}
				if len(versions) != 0 {
					input.LatestVersionNumber = new(versions[0].VersionNumber)
				}
				created, err := client.CreateExtension(t.Context(), input)
				if err != nil {
					t.Fatal(err)
				}
				versions = append(versions, created)
			}
			v1, v2 := aws.ToString(versions[0].Arn), aws.ToString(versions[1].Arn)
			association, err := client.CreateExtensionAssociation(t.Context(), &appconfig.CreateExtensionAssociationInput{
				ExtensionIdentifier:    versions[1].Id,
				ExtensionVersionNumber: new(versions[1].VersionNumber),
				ResourceIdentifier:     new("arn:aws:appconfig:us-east-1:" + account + ":application/" + aws.ToString(application.Id)),
				Tags:                   map[string]string{"owner": "association"},
			})
			if err != nil {
				t.Fatal(err)
			}
			associationARN := aws.ToString(association.Arn)
			unversioned := "arn:aws:appconfig:us-east-1:" + account + ":extension/" + aws.ToString(versions[0].Id)
			tags := taggingClient(cl, "us-east-1", account, "test")
			query := &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: []string{v1, unversioned, v2, associationARN}}
			assertDiscovery := func(want map[string]map[string]string) {
				t.Helper()
				listed, err := tags.GetResources(t.Context(), query)
				if err != nil {
					t.Fatal(err)
				}
				if got := taggingMappings(listed.ResourceTagMappingList); !reflect.DeepEqual(got, want) {
					t.Fatalf("versioned extension discovery: got %v want %v", got, want)
				}
			}
			want := map[string]map[string]string{v1: {"version": "one"}, v2: {"version": "two"}, associationARN: {"owner": "association"}}
			assertDiscovery(want)
			if _, err := client.TagResource(t.Context(), &appconfig.TagResourceInput{ResourceArn: new(v1), Tags: map[string]string{"changed": "native"}}); err != nil {
				t.Fatal(err)
			}
			requireAppConfigNativeTags(t, client, []string{v1}, map[string]string{"version": "one", "changed": "native"})
			requireAppConfigNativeTags(t, client, []string{v2}, map[string]string{"version": "two"})
			changed, err := tags.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{v2, associationARN}, Tags: map[string]string{"changed": "rgta"}})
			if err != nil || len(changed.FailedResourcesMap) != 0 {
				t.Fatalf("versioned owner tag mutation: %+v %v", changed, err)
			}
			requireAppConfigNativeTags(t, client, []string{v1}, map[string]string{"version": "one", "changed": "native"})
			requireAppConfigNativeTags(t, client, []string{v2}, map[string]string{"version": "two", "changed": "rgta"})
			requireAppConfigNativeTags(t, client, []string{associationARN}, map[string]string{"owner": "association", "changed": "rgta"})
			want[v1] = map[string]string{"version": "one", "changed": "native"}
			want[v2] = map[string]string{"version": "two", "changed": "rgta"}
			want[associationARN] = map[string]string{"owner": "association", "changed": "rgta"}
			assertDiscovery(want)
			removed, err := tags.UntagResources(t.Context(), &resourcegroupstaggingapi.UntagResourcesInput{ResourceARNList: []string{v1, associationARN}, TagKeys: []string{"changed"}})
			if err != nil || len(removed.FailedResourcesMap) != 0 {
				t.Fatalf("versioned owner tag removal: %+v %v", removed, err)
			}
			requireAppConfigNativeTags(t, client, []string{v1}, map[string]string{"version": "one"})
			requireAppConfigNativeTags(t, client, []string{v2}, map[string]string{"version": "two", "changed": "rgta"})
			requireAppConfigNativeTags(t, client, []string{associationARN}, map[string]string{"owner": "association"})
			if _, err := client.UntagResource(t.Context(), &appconfig.UntagResourceInput{ResourceArn: new(v2), TagKeys: []string{"changed"}}); err != nil {
				t.Fatal(err)
			}
			_, err = client.ListTagsForResource(t.Context(), &appconfig.ListTagsForResourceInput{ResourceArn: new(unversioned)})
			assertAPIError(t, err, "ResourceNotFoundException")
			_, err = client.TagResource(t.Context(), &appconfig.TagResourceInput{ResourceArn: new(unversioned), Tags: map[string]string{"forbidden": "unversioned"}})
			assertAPIError(t, err, "ResourceNotFoundException")
			_, err = client.UntagResource(t.Context(), &appconfig.UntagResourceInput{ResourceArn: new(unversioned), TagKeys: []string{"version"}})
			assertAPIError(t, err, "ResourceNotFoundException")
			changed, err = tags.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{unversioned}, Tags: map[string]string{"forbidden": "unversioned"}})
			if err != nil || len(changed.FailedResourcesMap) != 1 || string(changed.FailedResourcesMap[unversioned].ErrorCode) != "ResourceNotFoundException" || changed.FailedResourcesMap[unversioned].StatusCode != 404 {
				t.Fatalf("unversioned tag failure: %+v %v", changed, err)
			}
			removed, err = tags.UntagResources(t.Context(), &resourcegroupstaggingapi.UntagResourcesInput{ResourceARNList: []string{unversioned}, TagKeys: []string{"version"}})
			if err != nil || len(removed.FailedResourcesMap) != 1 || string(removed.FailedResourcesMap[unversioned].ErrorCode) != "ResourceNotFoundException" || removed.FailedResourcesMap[unversioned].StatusCode != 404 {
				t.Fatalf("unversioned untag failure: %+v %v", removed, err)
			}
			requireAppConfigNativeTags(t, client, []string{v1}, map[string]string{"version": "one"})
			requireAppConfigNativeTags(t, client, []string{v2}, map[string]string{"version": "two"})
			if _, err := client.UntagResource(t.Context(), &appconfig.UntagResourceInput{ResourceArn: new(v1), TagKeys: []string{"version"}}); err != nil {
				t.Fatal(err)
			}
			// Version-scoped empty membership survives without a discovery read.
			cl = reopen()
			client = cl.appconfig("us-east-1", account, "test")
			tags = taggingClient(cl, "us-east-1", account, "test")
			want = map[string]map[string]string{v1: {}, v2: {"version": "two"}, associationARN: {"owner": "association"}}
			assertDiscovery(want)
			if _, err := client.DeleteExtension(t.Context(), &appconfig.DeleteExtensionInput{ExtensionIdentifier: versions[0].Id, VersionNumber: new(versions[0].VersionNumber)}); err != nil {
				t.Fatal(err)
			}
			delete(want, v1)
			assertDiscovery(want)
			requireAppConfigNativeTags(t, client, []string{v2}, map[string]string{"version": "two"})
			_, err = client.ListTagsForResource(t.Context(), &appconfig.ListTagsForResourceInput{ResourceArn: new(v1)})
			assertAPIError(t, err, "ResourceNotFoundException")
			if _, err := client.DeleteExtensionAssociation(t.Context(), &appconfig.DeleteExtensionAssociationInput{ExtensionAssociationId: association.Id}); err != nil {
				t.Fatal(err)
			}
			delete(want, associationARN)
			assertDiscovery(want)
		})
	}
}
