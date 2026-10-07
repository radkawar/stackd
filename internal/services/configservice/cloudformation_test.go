package configservice

import (
	api "stackd/internal/awsapi/configservice"
	"testing"
)

func TestCloudFormationAggregatorRejectsOtherIncarnation(t *testing.T) {
	scope := Scope{"aws", "111111111111", "us-east-1"}
	ctx := ruleTestContext(scope)
	repo := NewMemoryRepository(nil)
	s := New(Config{Repository: repo})
	defer s.Close()
	owner := WithCloudFormationOwnership(ctx, CloudFormationOwnership{Owner: "stack-resource", Token: "first"})
	input := &api.PutConfigurationAggregatorInput{ConfigurationAggregatorName: new(api.ConfigurationAggregatorName("aggregate")), AccountAggregationSources: api.AccountAggregationSourceList{{AccountIds: api.AccountAggregationSourceAccountList{api.AccountId(scope.AccountID)}, AwsRegions: api.AggregatorRegionList{api.String(scope.Region)}}}, Tags: api.TagsList{{Key: new(api.TagKey("stackd:cloudformation:owner")), Value: new(api.TagValue("stack-resource"))}, {Key: new(api.TagKey("stackd:cloudformation:create-token")), Value: new(api.TagValue("first"))}}}
	first := ruleTestOK[api.PutConfigurationAggregatorOutput](t, s, owner, "PutConfigurationAggregator", input)
	stale := WithCloudFormationOwnership(ctx, CloudFormationOwnership{Owner: "stack-resource", Token: "second"})
	if _, e := ruleTestCommand(t, s, stale, "PutConfigurationAggregator", input); e == nil || e.Code != "ResourceAlreadyExistsException" {
		t.Fatalf("foreign incarnation put: %v", e)
	}
	if _, e := ruleTestCommand(t, s, stale, "DeleteConfigurationAggregator", &api.DeleteConfigurationAggregatorInput{ConfigurationAggregatorName: input.ConfigurationAggregatorName}); e == nil || e.Code != "ResourceAlreadyExistsException" {
		t.Fatalf("foreign incarnation delete: %v", e)
	}
	live := ruleTestOK[api.DescribeConfigurationAggregatorsOutput](t, s, ctx, "DescribeConfigurationAggregators", &api.DescribeConfigurationAggregatorsInput{})
	if len(live.ConfigurationAggregators) != 1 || value(live.ConfigurationAggregators[0].ConfigurationAggregatorArn) != value(first.ConfigurationAggregator.ConfigurationAggregatorArn) {
		t.Fatal("rejected ownership operation changed the live owner")
	}
	// Direct Cloud Control/native owner calls do not require stack ownership.
	ruleTestOK[api.DeleteConfigurationAggregatorOutput](t, s, ctx, "DeleteConfigurationAggregator", &api.DeleteConfigurationAggregatorInput{ConfigurationAggregatorName: input.ConfigurationAggregatorName})
}

func TestCloudFormationDeliveryChannelMetadataDoesNotAdoptNativeControl(t *testing.T) {
	scope := Scope{"aws", "111111111111", "us-east-1"}
	ctx := ruleTestContext(scope)
	repo := NewMemoryRepository(nil)
	ruleTestSeed(t, repo, func(tx Transaction) error {
		return tx.PutChannel(Channel{Scope: scope, Name: "delivery", Bucket: "actual-bucket", Frequency: "TwentyFour_Hours"})
	})
	s := New(Config{Repository: repo})
	defer s.Close()
	owner := WithCloudFormationOwnership(ctx, CloudFormationOwnership{Owner: "stack-resource", Token: "first"})
	if _, e := ruleTestCommand(t, s, owner, "DescribeDeliveryChannels", &api.DescribeDeliveryChannelsInput{DeliveryChannelNames: api.DeliveryChannelNameList{api.ChannelName("delivery")}}); e == nil || e.Code != "ResourceAlreadyExistsException" {
		t.Fatalf("adopted native delivery channel: %v", e)
	}
	native := ruleTestOK[api.DescribeDeliveryChannelsOutput](t, s, ctx, "DescribeDeliveryChannels", &api.DescribeDeliveryChannelsInput{})
	if len(native.DeliveryChannels) != 1 || value(native.DeliveryChannels[0].S3BucketName) != "actual-bucket" {
		t.Fatal("native control changed")
	}
	ruleTestSeed(t, repo, func(tx Transaction) error {
		return tx.PutTags(scope, channelOwnershipARN(scope, "delivery"), map[string]string{"stackd:cloudformation:owner": "stack-resource", "stackd:cloudformation:create-token": "first"})
	})
	if _, e := ruleTestCommand(t, s, owner, "DeleteDeliveryChannel", &api.DeleteDeliveryChannelInput{DeliveryChannelName: new(api.ChannelName("delivery"))}); e == nil || e.Code != "ResourceAlreadyExistsException" {
		t.Fatalf("counterfeit channel tags conferred private authority: %v", e)
	}
	ruleTestOK[api.DeleteDeliveryChannelOutput](t, s, ctx, "DeleteDeliveryChannel", &api.DeleteDeliveryChannelInput{DeliveryChannelName: new(api.ChannelName("delivery"))})
}
