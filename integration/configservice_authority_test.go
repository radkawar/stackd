package stackd_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"stackd"
)

// Resource associations, including the account-wide DescribeConfigRules and
// PutEvaluations exceptions, follow the AWS Config authorization reference:
// https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html
func TestConfigResourceAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012"})
			root := configClient(c, "us-east-1")
			identity := c.iam("test", "test", "")
			_, key, secret := c.user(t, "test", "config-authority")
			user := configservice.New(configservice.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			setPolicy := func(policy string) { putUserPolicy(t, identity, "config-authority", policy) }
			deny := func(arn string) {
				setPolicy(fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"config:*","Resource":"*"},{"Effect":"Deny","Action":"config:*","Resource":%q}]}`, arn))
			}
			role, err := identity.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("config-authority"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Service":"config.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			putRolePolicy(t, identity, "config-authority", allow(`"*"`, "*"))
			if _, err := identity.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: aws.String("config-authority"), PolicyName: aws.String("pass-role"), PolicyDocument: aws.String(allow(`"iam:PassRole"`, aws.ToString(role.Role.Arn)))}); err != nil {
				t.Fatal(err)
			}
			recorderInput := &configservice.PutConfigurationRecorderInput{ConfigurationRecorder: &configtypes.ConfigurationRecorder{Name: aws.String("authority"), RoleARN: role.Role.Arn}}
			if _, err := root.PutConfigurationRecorder(ctx, recorderInput); err != nil {
				t.Fatal(err)
			}
			recorders, err := root.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
			if err != nil {
				t.Fatal(err)
			}
			recorderARN := aws.ToString(recorders.ConfigurationRecorders[0].Arn)
			setPolicy(allow(`"config:*"`, recorderARN))
			if _, err := user.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{ConfigurationRecorderNames: []string{"authority"}}); err != nil {
				t.Fatal(err)
			}
			if _, err := user.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{}); err != nil {
				t.Fatal(err)
			}
			if _, err := user.PutConfigurationRecorder(ctx, recorderInput); err != nil {
				t.Fatal(err)
			}
			if _, err := user.StopConfigurationRecorder(ctx, &configservice.StopConfigurationRecorderInput{ConfigurationRecorderName: aws.String("authority")}); err != nil {
				t.Fatal(err)
			}
			deny(recorderARN)
			_, err = user.DeleteConfigurationRecorder(ctx, &configservice.DeleteConfigurationRecorderInput{ConfigurationRecorderName: aws.String("authority")})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = user.StartConfigurationRecorder(ctx, &configservice.StartConfigurationRecorderInput{ConfigurationRecorderName: aws.String("authority")})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = user.PutConfigurationRecorder(ctx, recorderInput)
			assertAPIError(t, err, "AccessDeniedException")
			after, err := root.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
			if err != nil || !reflect.DeepEqual(recorders.ConfigurationRecorders, after.ConfigurationRecorders) {
				t.Fatalf("denied recorder mutation: %+v %v", after, err)
			}

			ruleInput := &configservice.PutConfigRuleInput{ConfigRule: &configtypes.ConfigRule{ConfigRuleName: aws.String("first"), Source: &configtypes.Source{Owner: configtypes.OwnerAws, SourceIdentifier: aws.String("REQUIRED_TAGS")}, InputParameters: aws.String(`{"tag1Key":"owner"}`)}}
			for _, name := range []string{"first", "second"} {
				ruleInput.ConfigRule.ConfigRuleName = aws.String(name)
				if _, err := root.PutConfigRule(ctx, ruleInput); err != nil {
					t.Fatal(err)
				}
			}
			rules, err := root.DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{})
			if err != nil {
				t.Fatal(err)
			}
			ruleARN := aws.ToString(rules.ConfigRules[0].ConfigRuleArn)
			setPolicy(allow(`"config:*"`, ruleARN))
			if _, err := user.GetComplianceDetailsByConfigRule(ctx, &configservice.GetComplianceDetailsByConfigRuleInput{ConfigRuleName: aws.String("first")}); err != nil {
				t.Fatal(err)
			}
			if _, err := user.DeleteEvaluationResults(ctx, &configservice.DeleteEvaluationResultsInput{ConfigRuleName: aws.String("first")}); err != nil {
				t.Fatal(err)
			}
			ruleInput.ConfigRule.ConfigRuleName = aws.String("first")
			if _, err := user.PutConfigRule(ctx, ruleInput); err != nil {
				t.Fatal(err)
			}
			_, err = user.DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{ConfigRuleNames: []string{"first"}})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = user.PutEvaluations(ctx, &configservice.PutEvaluationsInput{TestMode: true, ResultToken: aws.String("test")})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = user.StartConfigRulesEvaluation(ctx, &configservice.StartConfigRulesEvaluationInput{ConfigRuleNames: []string{"first", "second"}})
			assertAPIError(t, err, "AccessDeniedException")
			// The rejected batch must not consume the first rule's reevaluation slot.
			if _, err := user.StartConfigRulesEvaluation(ctx, &configservice.StartConfigRulesEvaluationInput{ConfigRuleNames: []string{"first"}}); err != nil {
				t.Fatal(err)
			}
			deny(ruleARN)
			ruleInput.ConfigRule.Description = aws.String("forbidden")
			_, err = user.PutConfigRule(ctx, ruleInput)
			assertAPIError(t, err, "AccessDeniedException")
			_, err = user.DeleteConfigRule(ctx, &configservice.DeleteConfigRuleInput{ConfigRuleName: aws.String("first")})
			assertAPIError(t, err, "AccessDeniedException")
			current, err := root.DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{ConfigRuleNames: []string{"first"}})
			if err != nil || aws.ToString(current.ConfigRules[0].Description) != "" || aws.ToString(current.ConfigRules[0].ConfigRuleArn) != ruleARN {
				t.Fatalf("denied rule mutation: %+v %v", current, err)
			}
			if _, err := user.DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{}); err != nil {
				t.Fatal(err)
			}

			aggregatorInput := &configservice.PutConfigurationAggregatorInput{ConfigurationAggregatorName: aws.String("authority"), AccountAggregationSources: []configtypes.AccountAggregationSource{{AccountIds: []string{"123456789012"}, AwsRegions: []string{"us-east-1"}}}}
			made, err := root.PutConfigurationAggregator(ctx, aggregatorInput)
			if err != nil {
				t.Fatal(err)
			}
			aggregatorARN := aws.ToString(made.ConfigurationAggregator.ConfigurationAggregatorArn)
			setPolicy(allow(`"config:*"`, aggregatorARN))
			if _, err := user.GetAggregateDiscoveredResourceCounts(ctx, &configservice.GetAggregateDiscoveredResourceCountsInput{ConfigurationAggregatorName: aggregatorInput.ConfigurationAggregatorName}); err != nil {
				t.Fatal(err)
			}
			if _, err := user.DescribeConfigurationAggregatorSourcesStatus(ctx, &configservice.DescribeConfigurationAggregatorSourcesStatusInput{ConfigurationAggregatorName: aggregatorInput.ConfigurationAggregatorName}); err != nil {
				t.Fatal(err)
			}
			if _, err := user.ListAggregateDiscoveredResources(ctx, &configservice.ListAggregateDiscoveredResourcesInput{ConfigurationAggregatorName: aggregatorInput.ConfigurationAggregatorName, ResourceType: configtypes.ResourceType("AWS::SQS::Queue")}); err != nil {
				t.Fatal(err)
			}
			if _, err := user.DescribeAggregateComplianceByConfigRules(ctx, &configservice.DescribeAggregateComplianceByConfigRulesInput{ConfigurationAggregatorName: aggregatorInput.ConfigurationAggregatorName}); err != nil {
				t.Fatal(err)
			}
			if _, err := user.GetAggregateConfigRuleComplianceSummary(ctx, &configservice.GetAggregateConfigRuleComplianceSummaryInput{ConfigurationAggregatorName: aggregatorInput.ConfigurationAggregatorName}); err != nil {
				t.Fatal(err)
			}
			if _, err := user.PutConfigurationAggregator(ctx, aggregatorInput); err != nil {
				t.Fatal(err)
			}
			before, err := root.DescribeConfigurationAggregators(ctx, &configservice.DescribeConfigurationAggregatorsInput{})
			if err != nil {
				t.Fatal(err)
			}
			deny(aggregatorARN)
			aggregatorInput.AccountAggregationSources[0].AwsRegions = []string{"us-west-2"}
			_, err = user.PutConfigurationAggregator(ctx, aggregatorInput)
			assertAPIError(t, err, "AccessDeniedException")
			_, err = user.DeleteConfigurationAggregator(ctx, &configservice.DeleteConfigurationAggregatorInput{ConfigurationAggregatorName: aggregatorInput.ConfigurationAggregatorName})
			assertAPIError(t, err, "AccessDeniedException")
			retained, err := root.DescribeConfigurationAggregators(ctx, &configservice.DescribeConfigurationAggregatorsInput{})
			if err != nil || !reflect.DeepEqual(before.ConfigurationAggregators, retained.ConfigurationAggregators) {
				t.Fatalf("denied aggregator mutation: %+v %v", retained, err)
			}

			grant := &configservice.PutAggregationAuthorizationInput{AuthorizedAccountId: aws.String("111111111111"), AuthorizedAwsRegion: aws.String("us-east-1")}
			grantARN := "arn:aws:config:us-east-1:123456789012:aggregation-authorization/111111111111/us-east-1"
			setPolicy(allow(`"config:*"`, grantARN))
			if _, err := user.PutAggregationAuthorization(ctx, grant); err != nil {
				t.Fatal(err)
			}
			deny(grantARN)
			_, err = user.PutAggregationAuthorization(ctx, grant)
			assertAPIError(t, err, "AccessDeniedException")
			_, err = user.DeleteAggregationAuthorization(ctx, &configservice.DeleteAggregationAuthorizationInput{AuthorizedAccountId: grant.AuthorizedAccountId, AuthorizedAwsRegion: grant.AuthorizedAwsRegion})
			assertAPIError(t, err, "AccessDeniedException")
			grants, err := root.DescribeAggregationAuthorizations(ctx, &configservice.DescribeAggregationAuthorizationsInput{})
			if err != nil || len(grants.AggregationAuthorizations) != 1 || aws.ToString(grants.AggregationAuthorizations[0].AggregationAuthorizationArn) != grantARN {
				t.Fatalf("denied authorization deletion: %+v %v", grants, err)
			}
			// Opaque IDs do not turn create actions into account-wide permissions.
			setPolicy(allow(`"config:PutConfigRule"`, "arn:aws:config:us-east-1:123456789012:config-rule/*"))
			ruleInput.ConfigRule.ConfigRuleName = aws.String("scoped-create")
			if _, err := user.PutConfigRule(ctx, ruleInput); err != nil {
				t.Fatal(err)
			}
			setPolicy(allow(`"config:PutConfigurationAggregator"`, "arn:aws:config:us-east-1:123456789012:config-aggregator/*"))
			aggregatorInput.ConfigurationAggregatorName = aws.String("scoped-create")
			if _, err := user.PutConfigurationAggregator(ctx, aggregatorInput); err != nil {
				t.Fatal(err)
			}
		})
	}
}
