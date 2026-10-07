package integrations

import (
	"context"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/services/cloudformation"
)

func cfnS3BucketIdentifier(r cloudformation.ResourceRequest) (string, error) {
	name := r.PhysicalID
	if strings.HasPrefix(name, "arn:") {
		prefix := "arn:" + r.Scope.Partition + ":s3:::"
		if !strings.HasPrefix(name, prefix) {
			return "", fmt.Errorf("identifier must name a bucket in the request partition")
		}
		name = strings.TrimPrefix(name, prefix)
	}
	if name == "" || strings.ContainsAny(name, "/:") {
		return "", fmt.Errorf("identifier must be a bucket name")
	}
	return name, nil
}
func (h cfnS3Bucket) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, err := cfnS3BucketIdentifier(r)
	if err != nil {
		return nil, err
	}
	bucket, owner := new(api.BucketName(name)), new(api.AccountId(r.Scope.Account))
	location, err := cfnMessagingCall[api.GetBucketLocationOutput](ctx, h.commands, "s3", "GetBucketLocation", &api.GetBucketLocationInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil {
		return nil, err
	}
	region := cfnComputeValue(location.LocationConstraint)
	if region == "" {
		region = "us-east-1"
	}
	if region == "EU" {
		region = "eu-west-1"
	}
	if region != r.Scope.Region {
		return nil, fmt.Errorf("bucket is in region %s, not %s", region, r.Scope.Region)
	}
	tags, err := h.tags(ctx, r, name)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"BucketName": name, "Tags": cfnResourcePublicTags(tags)}
	for key, value := range h.result(r, name).Attributes {
		p[key] = value
	}
	versioning, err := cfnMessagingCall[api.GetBucketVersioningOutput](ctx, h.commands, "s3", "GetBucketVersioning", &api.GetBucketVersioningInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil {
		return nil, err
	}
	if versioning.Status != nil {
		p["VersioningConfiguration"] = map[string]any{"Status": string(*versioning.Status)}
	}
	ownership, err := cfnMessagingCall[api.GetBucketOwnershipControlsOutput](ctx, h.commands, "s3", "GetBucketOwnershipControls", &api.GetBucketOwnershipControlsInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil && !cfnMessagingMissing(err, "OwnershipControlsNotFoundError") {
		return nil, err
	}
	if err == nil && ownership.OwnershipControls != nil {
		rules := make([]any, 0, len(ownership.OwnershipControls.Rules))
		for _, rule := range ownership.OwnershipControls.Rules {
			rules = append(rules, map[string]any{"ObjectOwnership": cfnComputeValue(rule.ObjectOwnership)})
		}
		p["OwnershipControls"] = map[string]any{"Rules": rules}
	}
	public, err := cfnMessagingCall[api.GetPublicAccessBlockOutput](ctx, h.commands, "s3", "GetPublicAccessBlock", &api.GetPublicAccessBlockInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil && !cfnMessagingMissing(err, "NoSuchPublicAccessBlockConfiguration") {
		return nil, err
	}
	if err == nil && public.PublicAccessBlockConfiguration != nil {
		pab := public.PublicAccessBlockConfiguration
		properties := map[string]any{}
		for key, value := range map[string]*api.Setting{"BlockPublicAcls": pab.BlockPublicAcls, "BlockPublicPolicy": pab.BlockPublicPolicy, "IgnorePublicAcls": pab.IgnorePublicAcls, "RestrictPublicBuckets": pab.RestrictPublicBuckets} {
			if value != nil {
				properties[key] = bool(*value)
			}
		}
		p["PublicAccessBlockConfiguration"] = properties
	}
	encryption, err := cfnMessagingCall[api.GetBucketEncryptionOutput](ctx, h.commands, "s3", "GetBucketEncryption", &api.GetBucketEncryptionInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil && !cfnMessagingMissing(err, "ServerSideEncryptionConfigurationNotFoundError") {
		return nil, err
	}
	if err == nil && encryption.ServerSideEncryptionConfiguration != nil {
		rules := make([]any, 0, len(encryption.ServerSideEncryptionConfiguration.Rules))
		for _, rule := range encryption.ServerSideEncryptionConfiguration.Rules {
			properties := map[string]any{}
			if value := rule.ApplyServerSideEncryptionByDefault; value != nil {
				defaults := map[string]any{"SSEAlgorithm": cfnComputeValue(value.SSEAlgorithm)}
				if value.KMSMasterKeyID != nil {
					defaults["KMSMasterKeyID"] = string(*value.KMSMasterKeyID)
				}
				properties["ServerSideEncryptionByDefault"] = defaults
			}
			if rule.BucketKeyEnabled != nil {
				properties["BucketKeyEnabled"] = bool(*rule.BucketKeyEnabled)
			}
			if rule.BlockedEncryptionTypes != nil {
				types := make([]any, 0, len(rule.BlockedEncryptionTypes.EncryptionType))
				for _, value := range rule.BlockedEncryptionTypes.EncryptionType {
					types = append(types, string(value))
				}
				properties["BlockedEncryptionTypes"] = map[string]any{"EncryptionType": types}
			}
			rules = append(rules, properties)
		}
		p["BucketEncryption"] = map[string]any{"ServerSideEncryptionConfiguration": rules}
	}
	acl, err := cfnMessagingCall[api.GetBucketAclOutput](ctx, h.commands, "s3", "GetBucketAcl", &api.GetBucketAclInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil {
		return nil, err
	}
	if canned := cfnS3ReadCannedACL(acl); canned != "" {
		p["AccessControl"] = canned
	}
	notifications, err := cfnMessagingCall[api.GetBucketNotificationConfigurationOutput](ctx, h.commands, "s3", "GetBucketNotificationConfiguration", &api.GetBucketNotificationConfigurationInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil {
		return nil, err
	}
	if properties := cfnS3ReadNotifications(notifications); len(properties) > 0 {
		p["NotificationConfiguration"] = properties
	}
	lifecycle, err := cfnMessagingCall[api.GetBucketLifecycleConfigurationOutput](ctx, h.commands, "s3", "GetBucketLifecycleConfiguration", &api.GetBucketLifecycleConfigurationInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil && !cfnMessagingMissing(err, "NoSuchLifecycleConfiguration") {
		return nil, err
	}
	if err == nil {
		p["LifecycleConfiguration"] = cfnS3ReadLifecycle(lifecycle)
	}
	cors, err := cfnMessagingCall[api.GetBucketCorsOutput](ctx, h.commands, "s3", "GetBucketCors", &api.GetBucketCorsInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil && !cfnMessagingMissing(err, "NoSuchCORSConfiguration") {
		return nil, err
	}
	if err == nil {
		p["CorsConfiguration"] = cfnS3ReadCors(cors)
	}
	return p, nil
}
func (h cfnS3Bucket) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var resources []cloudformation.ResourceDescription
	input := &api.ListBucketsInput{BucketRegion: new(api.BucketRegion(r.Scope.Region)), MaxBuckets: new(api.MaxBuckets(1000))}
	for {
		out, err := cfnMessagingCall[api.ListBucketsOutput](ctx, h.commands, "s3", "ListBuckets", input)
		if err != nil {
			return nil, err
		}
		for _, bucket := range out.Buckets {
			r.PhysicalID = cfnComputeValue(bucket.Name)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			resources = append(resources, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if out.ContinuationToken == nil || *out.ContinuationToken == "" {
			return resources, nil
		}
		input.ContinuationToken = new(api.Token(*out.ContinuationToken))
	}
}

func cfnS3ReadCannedACL(out *api.GetBucketAclOutput) string {
	var owner string
	if out.Owner != nil {
		owner = cfnComputeValue(out.Owner.ID)
	}
	var publicRead, publicWrite, authenticated, logWrite, logRead bool
	for _, grant := range out.Grants {
		if grant.Grantee == nil {
			return ""
		}
		permission := cfnComputeValue(grant.Permission)
		if cfnComputeValue(grant.Grantee.ID) == owner && owner != "" && permission == "FULL_CONTROL" {
			continue
		}
		switch cfnComputeValue(grant.Grantee.URI) + ":" + permission {
		case "http://acs.amazonaws.com/groups/global/AllUsers:READ":
			publicRead = true
		case "http://acs.amazonaws.com/groups/global/AllUsers:WRITE":
			publicWrite = true
		case "http://acs.amazonaws.com/groups/global/AuthenticatedUsers:READ":
			authenticated = true
		case "http://acs.amazonaws.com/groups/s3/LogDelivery:WRITE":
			logWrite = true
		case "http://acs.amazonaws.com/groups/s3/LogDelivery:READ_ACP":
			logRead = true
		default:
			return "" // Custom grants are not a canned AccessControl property.
		}
	}
	switch {
	case publicRead && !authenticated && !logWrite && !logRead:
		if publicWrite {
			return "PublicReadWrite"
		}
		return "PublicRead"
	case authenticated && !publicRead && !publicWrite && !logWrite && !logRead:
		return "AuthenticatedRead"
	case logWrite && logRead && !publicRead && !publicWrite && !authenticated:
		return "LogDeliveryWrite"
	case !publicRead && !publicWrite && !authenticated && !logWrite && !logRead:
		return "Private"
	default:
		return ""
	}
}
func cfnS3ReadNotifications(out *api.NotificationConfiguration) map[string]any {
	p := map[string]any{}
	if out.EventBridgeConfiguration != nil {
		p["EventBridgeConfiguration"] = map[string]any{"EventBridgeEnabled": true}
	}
	appendRule := func(key, destinationKey, destination string, events api.EventList, filter *api.NotificationConfigurationFilter) {
		for _, event := range events {
			rule := map[string]any{"Event": string(event), destinationKey: destination}
			if filter != nil && filter.Key != nil {
				rules := make([]any, 0, len(filter.Key.FilterRules))
				for _, entry := range filter.Key.FilterRules {
					rules = append(rules, map[string]any{"Name": cfnComputeValue(entry.Name), "Value": cfnComputeValue(entry.Value)})
				}
				rule["Filter"] = map[string]any{"S3Key": map[string]any{"Rules": rules}}
			}
			items, _ := p[key].([]any)
			p[key] = append(items, rule)
		}
	}
	for _, rule := range out.QueueConfigurations {
		appendRule("QueueConfigurations", "Queue", cfnComputeValue(rule.QueueArn), rule.Events, rule.Filter)
	}
	for _, rule := range out.TopicConfigurations {
		appendRule("TopicConfigurations", "Topic", cfnComputeValue(rule.TopicArn), rule.Events, rule.Filter)
	}
	for _, rule := range out.LambdaFunctionConfigurations {
		appendRule("LambdaConfigurations", "Function", cfnComputeValue(rule.LambdaFunctionArn), rule.Events, rule.Filter)
	}
	return p
}
