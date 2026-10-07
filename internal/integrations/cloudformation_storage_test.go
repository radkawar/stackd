package integrations

import (
	"reflect"
	"testing"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/services/cloudformation"
)

func TestCloudFormationS3LifecycleFilterAndRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		rule  map[string]any
		check func(*testing.T, api.LifecycleRule)
	}{
		{"single tag without prefix", map[string]any{"Status": "Enabled", "ExpirationInDays": "1", "TagFilters": []any{map[string]any{"Key": "expire", "Value": "true"}}},
			func(t *testing.T, rule api.LifecycleRule) {
				if rule.Filter.Tag == nil || rule.Filter.And != nil || rule.Filter.Prefix != nil {
					t.Fatalf("one predicate must not use And: %+v", rule.Filter)
				}
			}},
		{"prefix and tag", map[string]any{"Status": "Enabled", "Prefix": "tmp/", "ExpirationInDays": 1, "TagFilters": []any{map[string]any{"Key": "expire", "Value": "true"}}},
			func(t *testing.T, rule api.LifecycleRule) {
				if rule.Filter.And == nil || string(*rule.Filter.And.Prefix) != "tmp/" || len(rule.Filter.And.Tags) != 1 {
					t.Fatalf("prefix and tag must use And: %+v", rule.Filter)
				}
			}},
		{"legacy glacier and false marker", map[string]any{"Status": "Enabled", "ExpirationInDays": 30, "ExpiredObjectDeleteMarker": false,
			"Transition": map[string]any{"StorageClass": "Glacier", "TransitionInDays": 7}, "NoncurrentVersionExpirationInDays": 3},
			func(t *testing.T, rule api.LifecycleRule) {
				if rule.Expiration.ExpiredObjectDeleteMarker != nil || int32(*rule.Expiration.Days) != 30 {
					t.Fatalf("a false marker must not conflict with days: %+v", rule.Expiration)
				}
				if len(rule.Transitions) != 1 || string(*rule.Transitions[0].StorageClass) != "GLACIER" || int32(*rule.NoncurrentVersionExpiration.NoncurrentDays) != 3 {
					t.Fatalf("legacy singular properties were not translated: %+v", rule)
				}
				if rule.Filter.Prefix == nil || *rule.Filter.Prefix != "" {
					t.Fatalf("an unfiltered rule needs an empty V2 prefix filter: %+v", rule.Filter)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p cfnS3BucketProperties
			if err := cfnMessagingDecode(cloudformation.Properties{"LifecycleConfiguration": map[string]any{"Rules": []any{tc.rule}}}, &p); err != nil {
				t.Fatal(err)
			}
			input, err := p.LifecycleConfiguration.native()
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, input.LifecycleConfiguration.Rules[0])
			read := cfnS3ReadLifecycle(&api.GetBucketLifecycleConfigurationOutput{Rules: input.LifecycleConfiguration.Rules})
			var again cfnS3BucketProperties
			if err := cfnMessagingDecode(cloudformation.Properties{"LifecycleConfiguration": read}, &again); err != nil {
				t.Fatalf("read projection is not a valid template property: %v", err)
			}
			second, err := again.LifecycleConfiguration.native()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(input.LifecycleConfiguration.Rules, second.LifecycleConfiguration.Rules) {
				t.Fatalf("read/update round trip changed the rule\nfirst  %+v\nsecond %+v", input.LifecycleConfiguration.Rules, second.LifecycleConfiguration.Rules)
			}
		})
	}
	var conflicting cfnS3BucketProperties
	if err := cfnMessagingDecode(cloudformation.Properties{"LifecycleConfiguration": map[string]any{"Rules": []any{map[string]any{
		"Status": "Enabled", "Transition": map[string]any{"StorageClass": "GLACIER", "TransitionInDays": 1},
		"Transitions": []any{map[string]any{"StorageClass": "GLACIER", "TransitionInDays": 2}}}}}}, &conflicting); err != nil {
		t.Fatal(err)
	}
	if _, err := conflicting.LifecycleConfiguration.native(); err == nil {
		t.Fatal("Transition and Transitions must not both be accepted")
	}
}

func TestCloudFormationS3CorsRoundTrip(t *testing.T) {
	var p cfnS3BucketProperties
	if err := cfnMessagingDecode(cloudformation.Properties{"CorsConfiguration": map[string]any{"CorsRules": []any{map[string]any{
		"Id": "ui", "AllowedOrigins": []any{"*"}, "AllowedMethods": []any{"GET"}, "ExposedHeaders": []any{"ETag"}, "MaxAge": "300"}}}}, &p); err != nil {
		t.Fatal(err)
	}
	native, err := p.CorsConfiguration.native()
	if err != nil {
		t.Fatal(err)
	}
	if len(native.CORSRules) != 1 || int32(*native.CORSRules[0].MaxAgeSeconds) != 300 || len(native.CORSRules[0].ExposeHeaders) != 1 {
		t.Fatalf("CORS translation %+v", native.CORSRules)
	}
	var again cfnS3BucketProperties
	if err := cfnMessagingDecode(cloudformation.Properties{"CorsConfiguration": cfnS3ReadCors(&api.GetBucketCorsOutput{CORSRules: native.CORSRules})}, &again); err != nil {
		t.Fatal(err)
	}
	second, err := again.CorsConfiguration.native()
	if err != nil || !reflect.DeepEqual(native, second) {
		t.Fatalf("CORS read/update round trip: %+v %v", second, err)
	}
	if err := (cfnS3Bucket{}).Validate(cloudformation.Properties{"CorsConfiguration": map[string]any{"CorsRules": []any{map[string]any{"AllowedOrigins": []any{"*"}}}}}); err == nil {
		t.Fatal("a CORS rule without AllowedMethods must be rejected")
	}
}

func TestCloudFormationStorageDocumentForms(t *testing.T) {
	var queue cfnSQSQueueProperties
	if err := cfnMessagingDecode(cloudformation.Properties{"FifoQueue": true,
		"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:000000000000:dlq.fifo","maxReceiveCount":3}`}, &queue); err != nil {
		t.Fatal(err)
	}
	if queue.RedrivePolicy["deadLetterTargetArn"] != "arn:aws:sqs:us-east-1:000000000000:dlq.fifo" {
		t.Fatalf("JSON text RedrivePolicy: %+v", queue.RedrivePolicy)
	}
	if err := cfnMessagingDecode(cloudformation.Properties{"RedrivePolicy": `"not an object"`}, &queue); err == nil {
		t.Fatal("non-object JSON text must be rejected")
	}
	attrs, err := (cfnSQSQueueProperties{FifoQueue: new(cfnMessagingBool(true)), DeduplicationScope: "messageGroup", FifoThroughputLimit: "perMessageGroupId"}).attributes(true)
	if err != nil || attrs["FifoThroughputLimit"] != "perMessageGroupId" || attrs["DeduplicationScope"] != "messageGroup" {
		t.Fatalf("high-throughput FIFO attributes: %+v %v", attrs, err)
	}
	if err := (cfnSQSQueue{}).Validate(cloudformation.Properties{"FifoQueue": true, "FifoThroughputLimit": "perMessageGroupId", "DeduplicationScope": "messageGroup"}); err != nil {
		t.Fatalf("high-throughput FIFO must be admitted: %v", err)
	}
}

func TestCloudFormationS3NotificationFilterNames(t *testing.T) {
	var p cfnS3BucketProperties
	if err := cfnMessagingDecode(cloudformation.Properties{"NotificationConfiguration": map[string]any{"LambdaConfigurations": []any{map[string]any{
		"Event": "s3:ObjectCreated:*", "Function": "arn:aws:lambda:us-east-1:000000000000:function:s3events",
		"Filter": map[string]any{"S3Key": map[string]any{"Rules": []any{map[string]any{"Name": "Suffix", "Value": ".courier"}}}}}}}}, &p); err != nil {
		t.Fatal(err)
	}
	native, err := p.NotificationConfiguration.native()
	if err != nil {
		t.Fatal(err)
	}
	rules := native.LambdaFunctionConfigurations[0].Filter.Key.FilterRules
	if len(rules) != 1 || string(*rules[0].Name) != "suffix" || string(*rules[0].Value) != ".courier" {
		t.Fatalf("Lambda notification filter %+v", rules)
	}
}
