package stackd_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"stackd"
	"stackd/clock"
)

func configClient(c cloudClients, region string) *configservice.Client {
	return configservice.New(configservice.Options{Region: region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}
func TestConfigNativeOwnerHistory(t *testing.T) {
	var fixture struct {
		Calls []struct {
			Parameters struct {
				ResourceType string `json:"resourceType"`
			}
			Output struct {
				Items []struct {
					Configuration string            `json:"configuration"`
					Supplementary map[string]string `json:"supplementaryConfiguration"`
					Tags          map[string]string `json:"tags"`
				} `json:"configurationItems"`
			}
		}
	}
	awsReadFixture(t, "configservice/owned_resource_shapes.json", &fixture)
	var expectedConfiguration, expectedTags map[string]string
	for _, call := range fixture.Calls {
		if call.Parameters.ResourceType == "AWS::SQS::Queue" && len(call.Output.Items) > 0 {
			if err := json.Unmarshal([]byte(call.Output.Items[0].Configuration), &expectedConfiguration); err != nil {
				t.Fatal(err)
			}
			expectedTags = call.Output.Items[0].Tags
			break
		}
	}
	if expectedConfiguration == nil {
		t.Fatal("native SQS item absent")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			start := time.Unix(1790587325, 0).UTC()
			source := clock.NewManual(start)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000", Clock: source})
			region := "us-west-2"
			cfg := configClient(clients, region)
			identity := clients.iam("test", "test", "")
			role, err := identity.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: new("config-native"), AssumeRolePolicyDocument: new(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"config.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := identity.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: new("native"), PolicyDocument: new(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)}); err != nil {
				t.Fatal(err)
			}
			objectClient := s3.New(s3.Options{Region: region, BaseEndpoint: new(clients.server.URL), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			bucket := "config-native-history"
			if _, err := objectClient.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: new(bucket), CreateBucketConfiguration: &s3types.CreateBucketConfiguration{LocationConstraint: s3types.BucketLocationConstraintUsWest2}}); err != nil {
				t.Fatal(err)
			}
			if _, err := cfg.StartConfigurationRecorder(t.Context(), &configservice.StartConfigurationRecorderInput{ConfigurationRecorderName: new("native")}); err == nil {
				t.Fatal("missing recorder accepted")
			} else {
				assertAPIError(t, err, "NoSuchConfigurationRecorderException")
			}
			if _, err := cfg.PutConfigurationRecorder(t.Context(), &configservice.PutConfigurationRecorderInput{ConfigurationRecorder: &configtypes.ConfigurationRecorder{Name: new("native"), RoleARN: role.Role.Arn, RecordingGroup: &configtypes.RecordingGroup{ResourceTypes: []configtypes.ResourceType{configtypes.ResourceType("AWS::SQS::Queue")}}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := cfg.PutDeliveryChannel(t.Context(), &configservice.PutDeliveryChannelInput{DeliveryChannel: &configtypes.DeliveryChannel{Name: new("native"), S3BucketName: new(bucket)}}); err != nil {
				t.Fatal(err)
			}
			if _, err := cfg.StartConfigurationRecorder(t.Context(), &configservice.StartConfigurationRecorderInput{ConfigurationRecorderName: new("native")}); err != nil {
				t.Fatal(err)
			}
			queues := sqs.New(sqs.Options{Region: region, BaseEndpoint: new(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			name := "stackd-next-config-76aa721f4d-resource"
			queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: new(name), Tags: expectedTags, Attributes: map[string]string{"VisibilityTimeout": "37"}})
			if err != nil {
				t.Fatal(err)
			}
			id := "https://sqs.us-west-2.amazonaws.com/000000000000/" + name
			lower := start.Add(-time.Millisecond)
			history, err := cfg.GetResourceConfigHistory(t.Context(), &configservice.GetResourceConfigHistoryInput{ResourceType: configtypes.ResourceType("AWS::SQS::Queue"), ResourceId: new(id), EarlierTime: &lower, LaterTime: &start, ChronologicalOrder: configtypes.ChronologicalOrderForward})
			if err != nil {
				t.Fatal(err)
			}
			if len(history.ConfigurationItems) != 1 {
				t.Fatalf("initial history: %#v", history.ConfigurationItems)
			}
			item := history.ConfigurationItems[0]
			var actual map[string]string
			if err := json.Unmarshal([]byte(aws.ToString(item.Configuration)), &actual); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual, expectedConfiguration) || !reflect.DeepEqual(item.Tags, expectedTags) || aws.ToString(item.AvailabilityZone) != "Not Applicable" || item.ConfigurationItemStatus != configtypes.ConfigurationItemStatusResourceDiscovered {
				t.Fatalf("native item mismatch actual=%+v expected=%+v item=%+v", actual, expectedConfiguration, item)
			}
			var supplementalTags map[string]string
			if err := json.Unmarshal([]byte(item.SupplementaryConfiguration["Tags"]), &supplementalTags); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(supplementalTags, expectedTags) {
				t.Fatalf("supplementary tags %v", supplementalTags)
			}
			if err := source.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"VisibilityTimeout": "51"}}); err != nil {
				t.Fatal(err)
			}
			cutoff := start.Add(time.Second)
			ranged, err := cfg.GetResourceConfigHistory(t.Context(), &configservice.GetResourceConfigHistoryInput{ResourceType: configtypes.ResourceType("AWS::SQS::Queue"), ResourceId: new(id), EarlierTime: &lower, LaterTime: &start})
			if err != nil {
				t.Fatal(err)
			}
			if len(ranged.ConfigurationItems) != 1 || ranged.ConfigurationItems[0].ConfigurationItemStatus != configtypes.ConfigurationItemStatusResourceDiscovered {
				t.Fatal("closed interval included later mutation")
			}
			_, err = cfg.GetResourceConfigHistory(t.Context(), &configservice.GetResourceConfigHistoryInput{ResourceType: configtypes.ResourceType("AWS::SQS::Queue"), ResourceId: new(id), EarlierTime: &cutoff, LaterTime: &start})
			assertAPIError(t, err, "InvalidTimeRangeException")
			empty, err := cfg.GetResourceConfigHistory(t.Context(), &configservice.GetResourceConfigHistoryInput{ResourceType: configtypes.ResourceType("AWS::SQS::Queue"), ResourceId: new(id), EarlierTime: &start, LaterTime: &start})
			if err != nil || len(empty.ConfigurationItems) != 0 {
				t.Fatalf("native zero-width interval: %+v %v", empty, err)
			}
			clients = reopen()
			cfg = configClient(clients, region)
			queues = sqs.New(sqs.Options{Region: region, BaseEndpoint: new(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			recovered, err := cfg.GetResourceConfigHistory(t.Context(), &configservice.GetResourceConfigHistoryInput{ResourceType: configtypes.ResourceType("AWS::SQS::Queue"), ResourceId: new(id)})
			if err != nil {
				t.Fatal(err)
			}
			if len(recovered.ConfigurationItems) != 2 || !strings.Contains(aws.ToString(recovered.ConfigurationItems[0].Configuration), `"VisibilityTimeout":"51"`) {
				t.Fatalf("retained mutation: %+v", recovered)
			}
			other := configClient(clients, "us-east-1")
			_, err = other.GetResourceConfigHistory(t.Context(), &configservice.GetResourceConfigHistoryInput{ResourceType: configtypes.ResourceType("AWS::SQS::Queue"), ResourceId: new(id)})
			assertAPIError(t, err, "ResourceNotDiscoveredException")
			attrs, err := queues.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: queue.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameVisibilityTimeout}})
			if err != nil {
				t.Fatal(err)
			}
			if attrs.Attributes["VisibilityTimeout"] != "51" {
				t.Fatal("source mutation not retained")
			}
		})
	}
}
