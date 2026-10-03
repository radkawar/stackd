package stackd_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroups"
	rgtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroups/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"

	"stackd"
)

// Each control is created by its native API, with a real role and a stopped
// recorder. No delivery channel or recording worker is needed for tagging.
type configTagControl struct {
	name        string
	arn         string
	taggingType string
	groupType   string
	put         func(*configservice.Client, []configtypes.Tag) (string, error)
	remove      func(*configservice.Client) error
}

func configTagControls(t *testing.T, c cloudClients, tags []configtypes.Tag) []configTagControl {
	t.Helper()
	ctx := t.Context()
	identity := c.iam("test", "test", "")
	role, err := identity.CreateRole(ctx, &iam.CreateRoleInput{RoleName: new("config-tags"), AssumeRolePolicyDocument: new(`{"Statement":{"Effect":"Allow","Principal":{"Service":"config.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, identity, "config-tags", allow(`"*"`, "*"))
	controls := []configTagControl{
		{
			name: "recorder", taggingType: "config:configuration-recorder", groupType: "AWS::Config::ConfigurationRecorder",
			put: func(client *configservice.Client, tags []configtypes.Tag) (string, error) {
				_, err := client.PutConfigurationRecorder(ctx, &configservice.PutConfigurationRecorderInput{ConfigurationRecorder: &configtypes.ConfigurationRecorder{Name: new("config-tags"), RoleARN: role.Role.Arn}, Tags: tags})
				if err != nil {
					return "", err
				}
				out, err := client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{ConfigurationRecorderNames: []string{"config-tags"}})
				if err != nil {
					return "", err
				}
				if len(out.ConfigurationRecorders) != 1 {
					t.Fatalf("created recorder missing: %+v", out)
				}
				return aws.ToString(out.ConfigurationRecorders[0].Arn), nil
			},
			remove: func(client *configservice.Client) error {
				_, err := client.DeleteConfigurationRecorder(ctx, &configservice.DeleteConfigurationRecorderInput{ConfigurationRecorderName: new("config-tags")})
				return err
			},
		},
		{
			name: "rule", taggingType: "config:config-rule", groupType: "AWS::Config::ConfigRule",
			put: func(client *configservice.Client, tags []configtypes.Tag) (string, error) {
				_, err := client.PutConfigRule(ctx, &configservice.PutConfigRuleInput{ConfigRule: &configtypes.ConfigRule{ConfigRuleName: new("config-tags"), Source: &configtypes.Source{Owner: configtypes.OwnerAws, SourceIdentifier: new("REQUIRED_TAGS")}, InputParameters: new(`{"tag1Key":"owner"}`)}, Tags: tags})
				if err != nil {
					return "", err
				}
				out, err := client.DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{ConfigRuleNames: []string{"config-tags"}})
				if err != nil {
					return "", err
				}
				if len(out.ConfigRules) != 1 {
					t.Fatalf("created rule missing: %+v", out)
				}
				return aws.ToString(out.ConfigRules[0].ConfigRuleArn), nil
			},
			remove: func(client *configservice.Client) error {
				_, err := client.DeleteConfigRule(ctx, &configservice.DeleteConfigRuleInput{ConfigRuleName: new("config-tags")})
				return err
			},
		},
		{
			name: "aggregator", taggingType: "config:config-aggregator", groupType: "AWS::Config::ConfigurationAggregator",
			put: func(client *configservice.Client, tags []configtypes.Tag) (string, error) {
				out, err := client.PutConfigurationAggregator(ctx, &configservice.PutConfigurationAggregatorInput{ConfigurationAggregatorName: new("config-tags"), AccountAggregationSources: []configtypes.AccountAggregationSource{{AccountIds: []string{"123456789012"}, AwsRegions: []string{"us-east-1"}}}, Tags: tags})
				if err != nil {
					return "", err
				}
				return aws.ToString(out.ConfigurationAggregator.ConfigurationAggregatorArn), nil
			},
			remove: func(client *configservice.Client) error {
				_, err := client.DeleteConfigurationAggregator(ctx, &configservice.DeleteConfigurationAggregatorInput{ConfigurationAggregatorName: new("config-tags")})
				return err
			},
		},
		{
			name: "authorization", taggingType: "config:aggregation-authorization", groupType: "AWS::Config::AggregationAuthorization",
			put: func(client *configservice.Client, tags []configtypes.Tag) (string, error) {
				out, err := client.PutAggregationAuthorization(ctx, &configservice.PutAggregationAuthorizationInput{AuthorizedAccountId: new("111111111111"), AuthorizedAwsRegion: new("us-east-1"), Tags: tags})
				if err != nil {
					return "", err
				}
				return aws.ToString(out.AggregationAuthorization.AggregationAuthorizationArn), nil
			},
			remove: func(client *configservice.Client) error {
				_, err := client.DeleteAggregationAuthorization(ctx, &configservice.DeleteAggregationAuthorizationInput{AuthorizedAccountId: new("111111111111"), AuthorizedAwsRegion: new("us-east-1")})
				return err
			},
		},
	}
	root := configClient(c, "us-east-1")
	for i := range controls {
		controls[i].arn, err = controls[i].put(root, tags)
		if err != nil {
			t.Fatalf("create %s: %v", controls[i].name, err)
		}
	}
	return controls
}

func requireConfigTags(t *testing.T, client *configservice.Client, arn string, want map[string]string) {
	t.Helper()
	got := map[string]string{}
	input := &configservice.ListTagsForResourceInput{ResourceArn: new(arn)}
	seen := map[string]bool{}
	for {
		out, err := client.ListTagsForResource(t.Context(), input)
		if err != nil {
			t.Fatalf("list tags for %s: %v", arn, err)
		}
		for _, tag := range out.Tags {
			key := aws.ToString(tag.Key)
			if _, duplicate := got[key]; duplicate {
				t.Fatalf("duplicate tag %q for %s", key, arn)
			}
			got[key] = aws.ToString(tag.Value)
		}
		if aws.ToString(out.NextToken) == "" {
			break
		}
		if seen[*out.NextToken] {
			t.Fatal("ListTagsForResource repeated a page token")
		}
		seen[*out.NextToken] = true
		input.NextToken = out.NextToken
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tags for %s: got %v want %v", arn, got, want)
	}
}

// The four Put API references explicitly say that Tags are create-only:
// https://docs.aws.amazon.com/config/latest/APIReference/API_PutConfigRule.html
// https://docs.aws.amazon.com/config/latest/APIReference/API_PutConfigurationAggregator.html
// https://docs.aws.amazon.com/config/latest/APIReference/API_PutAggregationAuthorization.html
// https://docs.aws.amazon.com/config/latest/APIReference/API_PutConfigurationRecorder.html
func TestConfigTaggingNativeLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012"})
			root := configClient(c, "us-east-1")
			controls := configTagControls(t, c, []configtypes.Tag{{Key: new("owner"), Value: new("native")}})
			for _, control := range controls {
				requireConfigTags(t, root, control.arn, map[string]string{"owner": "native"})
				for _, tags := range [][]configtypes.Tag{nil, {{Key: new("owner"), Value: new("ignored")}, {Key: new("extra"), Value: new("ignored")}}} {
					arn, err := control.put(root, tags)
					if err != nil || arn != control.arn {
						t.Fatalf("update %s changed identity: %q %v", control.name, arn, err)
					}
					requireConfigTags(t, root, control.arn, map[string]string{"owner": "native"})
				}
				if _, err := root.TagResource(t.Context(), &configservice.TagResourceInput{ResourceArn: new(control.arn), Tags: []configtypes.Tag{{Key: new("owner"), Value: new("updated")}, {Key: new("empty"), Value: new("")}}}); err != nil {
					t.Fatal(err)
				}
				if _, err := root.UntagResource(t.Context(), &configservice.UntagResourceInput{ResourceArn: new(control.arn), TagKeys: []string{"owner", "absent"}}); err != nil {
					t.Fatal(err)
				}
				requireConfigTags(t, root, control.arn, map[string]string{"empty": ""})
			}
			status, err := root.DescribeConfigurationRecorderStatus(t.Context(), &configservice.DescribeConfigurationRecorderStatusInput{})
			if err != nil || len(status.ConfigurationRecordersStatus) != 1 || status.ConfigurationRecordersStatus[0].Recording {
				t.Fatalf("tagging changed stopped recorder: %+v %v", status, err)
			}
			c = reopen()
			root = configClient(c, "us-east-1")
			for _, control := range controls {
				requireConfigTags(t, root, control.arn, map[string]string{"empty": ""})
				if err := control.remove(root); err != nil {
					t.Fatal(err)
				}
				_, err := root.ListTagsForResource(t.Context(), &configservice.ListTagsForResourceInput{ResourceArn: new(control.arn)})
				assertAPIError(t, err, "ResourceNotFoundException")
				arn, err := control.put(root, nil)
				if err != nil {
					t.Fatalf("recreate %s: %v", control.name, err)
				}
				requireConfigTags(t, root, arn, map[string]string{})
			}
		})
	}
}

// Config's SAR supports resource tags on native reads and mutations, request
// tags on TagResource/Put*, and TagKeys on TagResource/UntagResource/Put*.
// https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html
func TestConfigTaggingCurrentAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012"})
			root := configClient(c, "us-east-1")
			controls := configTagControls(t, c, []configtypes.Tag{{Key: new("team"), Value: new("config")}})
			_, key, secret := c.user(t, "test", "config-tagger")
			userClient := func() *configservice.Client {
				return configservice.New(configservice.Options{Region: "us-east-1", BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			}
			user := userClient()
			for _, control := range controls {
				policy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":["config:ListTagsForResource","config:DeleteConfigRule","config:DeleteConfigurationAggregator","config:DeleteAggregationAuthorization","config:DeleteConfigurationRecorder","config:StopConfigurationRecorder"],"Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"config"}}},{"Effect":"Allow","Action":"config:TagResource","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"config","aws:RequestTag/caller":"allowed"},"ForAllValues:StringEquals":{"aws:TagKeys":["caller"]}}},{"Effect":"Allow","Action":"config:UntagResource","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"config"},"ForAllValues:StringEquals":{"aws:TagKeys":["caller"]}}}]}`, control.arn, control.arn, control.arn)
				putUserPolicy(t, c.iam("test", "test", ""), "config-tagger", policy)
				requireConfigTags(t, user, control.arn, map[string]string{"team": "config"})
				if control.name == "recorder" {
					if _, err := user.StopConfigurationRecorder(t.Context(), &configservice.StopConfigurationRecorderInput{ConfigurationRecorderName: new("config-tags")}); err != nil {
						t.Fatal(err)
					}
				}
				allowed := &configservice.TagResourceInput{ResourceArn: new(control.arn), Tags: []configtypes.Tag{{Key: new("caller"), Value: new("allowed")}}}
				if _, err := user.TagResource(t.Context(), allowed); err != nil {
					t.Fatal(err)
				}
				for _, denied := range [][]configtypes.Tag{
					{{Key: new("caller"), Value: new("forbidden")}},
					{{Key: new("caller"), Value: new("allowed")}, {Key: new("extra"), Value: new("forbidden")}},
				} {
					_, err := user.TagResource(t.Context(), &configservice.TagResourceInput{ResourceArn: new(control.arn), Tags: denied})
					assertAPIError(t, err, "AccessDeniedException")
				}
				_, err := user.UntagResource(t.Context(), &configservice.UntagResourceInput{ResourceArn: new(control.arn), TagKeys: []string{"caller", "team"}})
				assertAPIError(t, err, "AccessDeniedException")
				requireConfigTags(t, root, control.arn, map[string]string{"team": "config", "caller": "allowed"})
				if _, err := user.UntagResource(t.Context(), &configservice.UntagResourceInput{ResourceArn: new(control.arn), TagKeys: []string{"caller"}}); err != nil {
					t.Fatal(err)
				}
				if _, err := root.TagResource(t.Context(), &configservice.TagResourceInput{ResourceArn: new(control.arn), Tags: []configtypes.Tag{{Key: new("team"), Value: new("other")}}}); err != nil {
					t.Fatal(err)
				}
				_, err = user.TagResource(t.Context(), allowed)
				assertAPIError(t, err, "AccessDeniedException")
				_, err = user.ListTagsForResource(t.Context(), &configservice.ListTagsForResourceInput{ResourceArn: new(control.arn)})
				assertAPIError(t, err, "AccessDeniedException")
				assertAPIError(t, control.remove(user), "AccessDeniedException")
				if control.name == "recorder" {
					_, err := user.StopConfigurationRecorder(t.Context(), &configservice.StopConfigurationRecorderInput{ConfigurationRecorderName: new("config-tags")})
					assertAPIError(t, err, "AccessDeniedException")
				}
				requireConfigTags(t, root, control.arn, map[string]string{"team": "other"})
			}
			c = reopen()
			root, user = configClient(c, "us-east-1"), userClient()
			last := controls[len(controls)-1]
			_, err := user.TagResource(t.Context(), &configservice.TagResourceInput{ResourceArn: new(last.arn), Tags: []configtypes.Tag{{Key: new("caller"), Value: new("allowed")}}})
			assertAPIError(t, err, "AccessDeniedException")
			for _, control := range controls {
				requireConfigTags(t, root, control.arn, map[string]string{"team": "other"})
			}
		})
	}
}

func TestConfigTaggingCreateAuthorityAtomicity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012"})
			root := configClient(c, "us-east-1")
			_, key, secret := c.user(t, "test", "config-create-tags")
			user := configservice.New(configservice.Options{Region: "us-east-1", BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			const resource = "arn:aws:config:us-east-1:123456789012:config-aggregator/*"
			input := &configservice.PutConfigurationAggregatorInput{ConfigurationAggregatorName: new("conditional-create"), AccountAggregationSources: []configtypes.AccountAggregationSource{{AccountIds: []string{"123456789012"}, AwsRegions: []string{"us-east-1"}}}, Tags: []configtypes.Tag{{Key: new("team"), Value: new("config")}}}
			assertAbsent := func() {
				t.Helper()
				out, err := root.DescribeConfigurationAggregators(t.Context(), &configservice.DescribeConfigurationAggregatorsInput{})
				if err != nil || len(out.ConfigurationAggregators) != 0 {
					t.Fatalf("denied create left an aggregator: %+v %v", out, err)
				}
				found, err := taggingClient(c, "us-east-1", "test", "test").GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceTypeFilters: []string{"config:config-aggregator"}})
				if err != nil || len(found.ResourceTagMappingList) != 0 {
					t.Fatalf("denied create leaked discovery membership: %+v %v", found, err)
				}
			}
			// Tagged creation requires the dependent native TagResource permission.
			putUserPolicy(t, c.iam("test", "test", ""), "config-create-tags", allow(`"config:PutConfigurationAggregator"`, resource))
			_, err := user.PutConfigurationAggregator(t.Context(), input)
			assertAPIError(t, err, "AccessDeniedException")
			assertAbsent()
			policy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"config:TagResource","Resource":%q},{"Effect":"Allow","Action":"config:PutConfigurationAggregator","Resource":%q,"Condition":{"StringEquals":{"aws:RequestTag/team":"config"},"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}}]}`, resource, resource)
			putUserPolicy(t, c.iam("test", "test", ""), "config-create-tags", policy)
			for _, tags := range [][]configtypes.Tag{
				{{Key: new("team"), Value: new("other")}},
				{{Key: new("team"), Value: new("config")}, {Key: new("extra"), Value: new("forbidden")}},
			} {
				input.Tags = tags
				_, err := user.PutConfigurationAggregator(t.Context(), input)
				assertAPIError(t, err, "AccessDeniedException")
				assertAbsent()
			}
			input.Tags = []configtypes.Tag{{Key: new("team"), Value: new("config")}}
			made, err := user.PutConfigurationAggregator(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			arn := aws.ToString(made.ConfigurationAggregator.ConfigurationAggregatorArn)
			requireConfigTags(t, root, arn, map[string]string{"team": "config"})
			// Updating a resource with create-only Tags must not bypass current
			// resource-tag authority or partly change its native configuration.
			policy = fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"config:PutConfigurationAggregator","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"config"}}}}`, arn)
			putUserPolicy(t, c.iam("test", "test", ""), "config-create-tags", policy)
			input.Tags = nil
			input.AccountAggregationSources[0].AwsRegions = []string{"us-west-2"}
			if _, err := user.PutConfigurationAggregator(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			if _, err := root.TagResource(t.Context(), &configservice.TagResourceInput{ResourceArn: new(arn), Tags: []configtypes.Tag{{Key: new("team"), Value: new("other")}}}); err != nil {
				t.Fatal(err)
			}
			before, err := root.DescribeConfigurationAggregators(t.Context(), &configservice.DescribeConfigurationAggregatorsInput{})
			if err != nil {
				t.Fatal(err)
			}
			input.Tags = []configtypes.Tag{{Key: new("team"), Value: new("config")}}
			input.AccountAggregationSources[0].AwsRegions = []string{"eu-west-1"}
			_, err = user.PutConfigurationAggregator(t.Context(), input)
			assertAPIError(t, err, "AccessDeniedException")
			after, err := root.DescribeConfigurationAggregators(t.Context(), &configservice.DescribeConfigurationAggregatorsInput{})
			if err != nil || !reflect.DeepEqual(before.ConfigurationAggregators, after.ConfigurationAggregators) {
				t.Fatalf("denied update changed native configuration: %+v %v", after, err)
			}
			requireConfigTags(t, root, arn, map[string]string{"team": "other"})
		})
	}
}

func TestConfigTaggingMergeLimitAndListing(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012"})
			root := configClient(c, "us-east-1")
			tags := make([]configtypes.Tag, 49)
			want := map[string]string{}
			for i := range tags {
				key := fmt.Sprintf("key-%02d", i)
				tags[i] = configtypes.Tag{Key: new(key), Value: new("original")}
				want[key] = "original"
			}
			made, err := root.PutAggregationAuthorization(t.Context(), &configservice.PutAggregationAuthorizationInput{AuthorizedAccountId: new("111111111111"), AuthorizedAwsRegion: new("us-east-1"), Tags: tags})
			if err != nil {
				t.Fatal(err)
			}
			arn := aws.ToString(made.AggregationAuthorization.AggregationAuthorizationArn)
			if _, err := root.TagResource(t.Context(), &configservice.TagResourceInput{ResourceArn: new(arn), Tags: []configtypes.Tag{{Key: new("key-49"), Value: new("last")}, {Key: new("key-00"), Value: new("updated")}}}); err != nil {
				t.Fatal(err)
			}
			want["key-49"], want["key-00"] = "last", "updated"
			requireConfigTags(t, root, arn, want)
			_, err = root.TagResource(t.Context(), &configservice.TagResourceInput{ResourceArn: new(arn), Tags: []configtypes.Tag{{Key: new("key-00"), Value: new("forbidden")}, {Key: new("overflow"), Value: new("forbidden")}}})
			assertAPIError(t, err, "TooManyTagsException")
			requireConfigTags(t, root, arn, want)
			// Native Config returns the full tag set even with Limit=1 and
			// ignores NextToken; it does not issue a pagination token.
			for _, limit := range []int32{1, 100} {
				page, err := root.ListTagsForResource(t.Context(), &configservice.ListTagsForResourceInput{ResourceArn: new(arn), Limit: limit, NextToken: new("not-a-native-token")})
				if err != nil {
					t.Fatal(err)
				}
				got := map[string]string{}
				for _, tag := range page.Tags {
					got[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
				}
				if !reflect.DeepEqual(got, want) || aws.ToString(page.NextToken) != "" {
					t.Fatalf("native nonpaginated tag listing with limit %d: %+v, want %v", limit, page, want)
				}
			}
			_, err = root.ListTagsForResource(t.Context(), &configservice.ListTagsForResourceInput{ResourceArn: new(arn), Limit: 101})
			assertAPIError(t, err, "ValidationException")
			// The native capture covers regional absence. Cross-account calls
			// have no resource-policy grant and fail current IAM authorization.
			for _, scope := range []struct{ account, region, code string }{
				{"123456789012", "us-west-2", "ResourceNotFoundException"},
				{"444455556666", "us-east-1", "AccessDeniedException"},
			} {
				isolated := configservice.New(configservice.Options{Region: scope.region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(scope.account, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
				_, err := isolated.ListTagsForResource(t.Context(), &configservice.ListTagsForResourceInput{ResourceArn: new(arn)})
				assertAPIError(t, err, scope.code)
				_, err = isolated.TagResource(t.Context(), &configservice.TagResourceInput{ResourceArn: new(arn), Tags: []configtypes.Tag{{Key: new("key-00"), Value: new("foreign")}}})
				assertAPIError(t, err, scope.code)
			}
			requireConfigTags(t, root, arn, want)
			if _, err := root.TagResource(t.Context(), &configservice.TagResourceInput{ResourceArn: new(arn), Tags: []configtypes.Tag{{Key: new("key-00"), Value: new("at-capacity")}}}); err != nil {
				t.Fatal(err)
			}
			want["key-00"] = "at-capacity"
			c = reopen()
			requireConfigTags(t, configClient(c, "us-east-1"), arn, want)
		})
	}
}

func TestResourceGroupsTaggingConfigLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "123456789012"
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			root := configClient(c, "us-east-1")
			controls := configTagControls(t, c, []configtypes.Tag{{Key: new("source"), Value: new("native")}})
			never, err := root.PutAggregationAuthorization(t.Context(), &configservice.PutAggregationAuthorizationInput{AuthorizedAccountId: new("222222222222"), AuthorizedAwsRegion: new("us-east-1")})
			if err != nil {
				t.Fatal(err)
			}
			tags := taggingClient(c, "us-east-1", "test", "test")
			arns := []string{}
			want := map[string]map[string]string{}
			for _, control := range controls {
				arns = append(arns, control.arn)
				want[control.arn] = map[string]string{"source": "native"}
				listed, err := tags.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceTypeFilters: []string{control.taggingType}})
				if err != nil {
					t.Fatal(err)
				}
				if got, expected := taggingMappings(listed.ResourceTagMappingList), map[string]map[string]string{control.arn: {"source": "native"}}; !reflect.DeepEqual(got, expected) {
					t.Fatalf("Config discovery type %s: got %v want %v", control.taggingType, got, expected)
				}
			}
			query := &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: append(append([]string{}, arns...), aws.ToString(never.AggregationAuthorization.AggregationAuthorizationArn))}
			listed, err := tags.GetResources(t.Context(), query)
			if err != nil {
				t.Fatal(err)
			}
			if got := taggingMappings(listed.ResourceTagMappingList); !reflect.DeepEqual(got, want) {
				t.Fatalf("native create discovery: got %v want %v", got, want)
			}
			groups := resourcegroups.New(resourcegroups.Options{Region: "us-east-1", BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			for _, control := range controls[1:] {
				query := fmt.Sprintf(`{"ResourceTypeFilters":[%q],"TagFilters":[{"Key":"source","Values":["native"]}]}`, control.groupType)
				found, err := groups.SearchResources(t.Context(), &resourcegroups.SearchResourcesInput{ResourceQuery: &rgtypes.ResourceQuery{Type: rgtypes.QueryTypeTagFilters10, Query: new(query)}})
				if err != nil {
					t.Fatal(err)
				}
				if len(found.ResourceIdentifiers) != 1 || aws.ToString(found.ResourceIdentifiers[0].ResourceArn) != control.arn || aws.ToString(found.ResourceIdentifiers[0].ResourceType) != control.groupType {
					t.Fatalf("Resource Groups Config type %s: %+v", control.groupType, found)
				}
			}
			changed, err := tags.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: arns, Tags: map[string]string{"source": "shared", "empty": ""}})
			if err != nil || len(changed.FailedResourcesMap) != 0 {
				t.Fatalf("shared Config tag mutation: %+v %v", changed, err)
			}
			for _, arn := range arns {
				requireConfigTags(t, root, arn, map[string]string{"source": "shared", "empty": ""})
			}
			removed, err := tags.UntagResources(t.Context(), &resourcegroupstaggingapi.UntagResourcesInput{ResourceARNList: arns, TagKeys: []string{"source"}})
			if err != nil || len(removed.FailedResourcesMap) != 0 {
				t.Fatalf("shared Config untag mutation: %+v %v", removed, err)
			}
			for _, scope := range []struct{ account, region string }{{account, "us-west-2"}, {"444455556666", "us-east-1"}} {
				isolated := taggingClient(c, scope.region, scope.account, "test")
				listed, err := isolated.GetResources(t.Context(), query)
				if err != nil || len(listed.ResourceTagMappingList) != 0 {
					t.Fatalf("Config discovery crossed scope %v: %+v %v", scope, listed, err)
				}
				changed, err := isolated.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: arns, Tags: map[string]string{"foreign": "forbidden"}})
				if err != nil || len(changed.FailedResourcesMap) != len(arns) {
					t.Fatalf("Config mutation crossed scope %v: %+v %v", scope, changed, err)
				}
			}
			for _, arn := range arns {
				requireConfigTags(t, root, arn, map[string]string{"empty": ""})
			}
			// No discovery read observes this resource while it has tags:
			// membership must be committed by the native mutation itself.
			unseen, err := root.PutAggregationAuthorization(t.Context(), &configservice.PutAggregationAuthorizationInput{AuthorizedAccountId: new("333333333333"), AuthorizedAwsRegion: new("us-east-1"), Tags: []configtypes.Tag{{Key: new("empty"), Value: new("")}}})
			if err != nil {
				t.Fatal(err)
			}
			unseenARN := aws.ToString(unseen.AggregationAuthorization.AggregationAuthorizationArn)
			arns = append(arns, unseenARN)
			query.ResourceARNList = append(query.ResourceARNList, unseenARN)
			for _, arn := range arns {
				if _, err := root.UntagResource(t.Context(), &configservice.UntagResourceInput{ResourceArn: new(arn), TagKeys: []string{"empty"}}); err != nil {
					t.Fatal(err)
				}
				want[arn] = map[string]string{}
			}
			c = reopen()
			root, tags = configClient(c, "us-east-1"), taggingClient(c, "us-east-1", "test", "test")
			listed, err = tags.GetResources(t.Context(), query)
			if err != nil {
				t.Fatal(err)
			}
			if got := taggingMappings(listed.ResourceTagMappingList); !reflect.DeepEqual(got, want) {
				t.Fatalf("last-tag membership after reopen: got %v want %v", got, want)
			}
			for _, control := range controls {
				if err := control.remove(root); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := root.DeleteAggregationAuthorization(t.Context(), &configservice.DeleteAggregationAuthorizationInput{AuthorizedAccountId: new("333333333333"), AuthorizedAwsRegion: new("us-east-1")}); err != nil {
				t.Fatal(err)
			}
			// The authorization reuses its ARN, unlike an opaque rule ID.
			// Recreating it untagged must not resurrect historical membership.
			arn, err := controls[len(controls)-1].put(root, nil)
			if err != nil {
				t.Fatal(err)
			}
			requireConfigTags(t, root, arn, map[string]string{})
			c = reopen()
			listed, err = taggingClient(c, "us-east-1", "test", "test").GetResources(t.Context(), query)
			if err != nil || len(listed.ResourceTagMappingList) != 0 {
				t.Fatalf("deleted/recreated Config membership survived: %+v %v", listed, err)
			}
		})
	}
}

func TestResourceGroupsTaggingConfigCurrentAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012"})
			root := configClient(c, "us-east-1")
			controls := configTagControls(t, c, []configtypes.Tag{{Key: new("team"), Value: new("config")}})
			arn, outside := controls[2].arn, controls[3].arn
			_, key, secret := c.user(t, "test", "config-shared-tagger")
			caller := taggingClient(c, "us-east-1", key, secret)
			putUserPolicy(t, c.iam("test", "test", ""), "config-shared-tagger", allow(`"tag:*"`, "*"))
			listed, err := caller.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceARNList: []string{arn, outside}})
			if err != nil {
				t.Fatal(err)
			}
			if got, want := taggingMappings(listed.ResourceTagMappingList), map[string]map[string]string{arn: {"team": "config"}, outside: {"team": "config"}}; !reflect.DeepEqual(got, want) {
				t.Fatalf("shared discovery required native list permission: got %v want %v", got, want)
			}
			assertDenied := func(resource string, values map[string]string) {
				t.Helper()
				out, err := caller.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{resource}, Tags: values})
				if err != nil || len(out.FailedResourcesMap) != 1 || !strings.Contains(string(out.FailedResourcesMap[resource].ErrorCode), "AccessDenied") {
					t.Fatalf("expected native Config authority failure: %+v %v", out, err)
				}
			}
			assertDenied(arn, map[string]string{"caller": "allowed"})
			policy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"tag:*","Resource":"*"},{"Effect":"Allow","Action":"config:TagResource","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"config","aws:RequestTag/caller":"allowed"},"ForAllValues:StringEquals":{"aws:TagKeys":["caller"]}}},{"Effect":"Allow","Action":"config:UntagResource","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"config"},"ForAllValues:StringEquals":{"aws:TagKeys":["caller"]}}}]}`, arn, arn)
			putUserPolicy(t, c.iam("test", "test", ""), "config-shared-tagger", policy)
			out, err := caller.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{arn}, Tags: map[string]string{"caller": "allowed"}})
			if err != nil || len(out.FailedResourcesMap) != 0 {
				t.Fatalf("conditional Config shared mutation: %+v %v", out, err)
			}
			assertDenied(outside, map[string]string{"caller": "allowed"})
			assertDenied(arn, map[string]string{"caller": "forbidden"})
			assertDenied(arn, map[string]string{"caller": "allowed", "extra": "forbidden"})
			removed, err := caller.UntagResources(t.Context(), &resourcegroupstaggingapi.UntagResourcesInput{ResourceARNList: []string{arn}, TagKeys: []string{"caller", "team"}})
			if err != nil || len(removed.FailedResourcesMap) != 1 || !strings.Contains(string(removed.FailedResourcesMap[arn].ErrorCode), "AccessDenied") {
				t.Fatalf("conditional Config untag rejection: %+v %v", removed, err)
			}
			requireConfigTags(t, root, arn, map[string]string{"team": "config", "caller": "allowed"})
			requireConfigTags(t, root, outside, map[string]string{"team": "config"})
			removed, err = caller.UntagResources(t.Context(), &resourcegroupstaggingapi.UntagResourcesInput{ResourceARNList: []string{arn}, TagKeys: []string{"caller"}})
			if err != nil || len(removed.FailedResourcesMap) != 0 {
				t.Fatalf("conditional Config untag: %+v %v", removed, err)
			}
			if _, err := root.TagResource(t.Context(), &configservice.TagResourceInput{ResourceArn: new(arn), Tags: []configtypes.Tag{{Key: new("team"), Value: new("other")}}}); err != nil {
				t.Fatal(err)
			}
			c = reopen()
			root, caller = configClient(c, "us-east-1"), taggingClient(c, "us-east-1", key, secret)
			assertDenied(arn, map[string]string{"caller": "allowed"})
			requireConfigTags(t, root, arn, map[string]string{"team": "other"})
		})
	}
}
