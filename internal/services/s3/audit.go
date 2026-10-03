package s3

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

type eventClass struct{ readOnly, data bool }

// Native classification is independent of the HTTP verb or IAM action. List
// objects is data activity; bucket configuration reads are management activity.
var eventClasses = map[string]eventClass{
	"CreateBucket":                       {},
	"DeleteBucket":                       {},
	"HeadBucket":                         {readOnly: true, data: true},
	"ListBuckets":                        {readOnly: true},
	"GetBucketLocation":                  {readOnly: true},
	"GetBucketAcl":                       {readOnly: true},
	"PutBucketAcl":                       {},
	"GetObjectAcl":                       {readOnly: true, data: true},
	"PutObjectAcl":                       {data: true},
	"PutBucketOwnershipControls":         {},
	"DeleteBucketOwnershipControls":      {},
	"PutPublicAccessBlock":               {},
	"DeletePublicAccessBlock":            {},
	"GetBucketPolicyStatus":              {readOnly: true},
	"GetBucketOwnershipControls":         {readOnly: true},
	"GetPublicAccessBlock":               {readOnly: true},
	"GetAccessPoint":                     {readOnly: true},
	"ListAccessPoints":                   {readOnly: true},
	"GetAccessPointPolicy":               {readOnly: true},
	"GetAccessPointPolicyStatus":         {readOnly: true},
	"ListTagsForResource":                {readOnly: true},
	"PutBucketPolicy":                    {},
	"GetBucketPolicy":                    {readOnly: true},
	"DeleteBucketPolicy":                 {},
	"GetBucketTagging":                   {readOnly: true},
	"PutBucketTagging":                   {},
	"DeleteBucketTagging":                {},
	"GetBucketAbac":                      {readOnly: true},
	"PutBucketAbac":                      {},
	"GetBucketAccelerateConfiguration":   {readOnly: true},
	"PutBucketAccelerateConfiguration":   {},
	"GetBucketVersioning":                {readOnly: true},
	"PutBucketVersioning":                {},
	"GetBucketEncryption":                {readOnly: true},
	"PutBucketEncryption":                {},
	"DeleteBucketEncryption":             {},
	"GetBucketCors":                      {readOnly: true},
	"PutBucketCors":                      {},
	"DeleteBucketCors":                   {},
	"GetBucketWebsite":                   {readOnly: true},
	"PutBucketWebsite":                   {},
	"DeleteBucketWebsite":                {},
	"GetBucketRequestPayment":            {readOnly: true},
	"PutBucketRequestPayment":            {},
	"GetBucketLogging":                   {readOnly: true},
	"PutBucketLogging":                   {},
	"GetBucketMetricsConfiguration":      {readOnly: true},
	"ListBucketMetricsConfigurations":    {readOnly: true},
	"PutBucketMetricsConfiguration":      {},
	"DeleteBucketMetricsConfiguration":   {},
	"GetBucketInventoryConfiguration":    {readOnly: true},
	"ListBucketInventoryConfigurations":  {readOnly: true},
	"PutBucketInventoryConfiguration":    {},
	"DeleteBucketInventoryConfiguration": {},
	"GetBucketAnalyticsConfiguration":    {readOnly: true},
	"ListBucketAnalyticsConfigurations":  {readOnly: true},
	"PutBucketAnalyticsConfiguration":    {},
	"DeleteBucketAnalyticsConfiguration": {},
	"GetBucketNotificationConfiguration": {readOnly: true},
	"PutBucketNotificationConfiguration": {},
	"ListObjectVersions":                 {readOnly: true, data: true},
	"PutObject":                          {data: true},
	"CopyObject":                         {data: true},
	"CreateMultipartUpload":              {data: true},
	"UploadPart":                         {data: true},
	"UploadPartCopy":                     {data: true},
	"CompleteMultipartUpload":            {data: true},
	"AbortMultipartUpload":               {data: true},
	"ListParts":                          {readOnly: true, data: true},
	"ListMultipartUploads":               {readOnly: true},
	"GetObject":                          {readOnly: true, data: true},
	"HeadObject":                         {readOnly: true, data: true},
	"GetObjectAttributes":                {readOnly: true, data: true},
	"RestoreObject":                      {data: true},
	"DeleteObject":                       {data: true},
	"DeleteObjects":                      {data: true},
	"GetObjectTagging":                   {readOnly: true, data: true},
	"PutObjectTagging":                   {data: true},
	"DeleteObjectTagging":                {data: true},
	"GetObjectLockConfiguration":         {readOnly: true},
	"PutObjectLockConfiguration":         {},
	"GetObjectRetention":                 {readOnly: true, data: true},
	"PutObjectRetention":                 {data: true},
	"GetObjectLegalHold":                 {readOnly: true, data: true},
	"PutObjectLegalHold":                 {data: true},
	"ListObjects":                        {readOnly: true, data: true},
	"ListObjectsV2":                      {readOnly: true, data: true},
}

var rejectedProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Bucket":                      {Name: "bucketName"},
	"ExpectedBucketOwner":         {Mode: awsapi.OmitField},
	"Policy":                      {Name: "bucketPolicy", Mode: awsapi.JSONField},
	"ACL":                         {Name: "x-amz-acl"},
	"Metadata":                    {Mode: awsapi.OmitField},
	"ContentMD5":                  {Mode: awsapi.OmitField},
	"ChecksumAlgorithm":           {Mode: awsapi.OmitField},
	"SSECustomerKey":              {Mode: awsapi.OmitField},
	"CopySourceSSECustomerKey":    {Mode: awsapi.OmitField},
	"SSECustomerKeyMD5":           {Mode: awsapi.OmitField},
	"CopySourceSSECustomerKeyMD5": {Mode: awsapi.OmitField},
	"Tagging":                     {Mode: awsapi.OmitField},
	"AbacStatus":                  {Mode: awsapi.OmitField},
	"CreateBucketConfiguration":   {Mode: awsapi.OmitField},
	"AccelerateConfiguration":     {Mode: awsapi.OmitField},
	"WebsiteConfiguration":        {Mode: awsapi.OmitField},
	"CORSConfiguration":           {Mode: awsapi.OmitField},
	"RequestPaymentConfiguration": {Mode: awsapi.OmitField},
	"BucketLoggingStatus":         {Mode: awsapi.OmitField},
	"MetricsConfiguration":        {Mode: awsapi.OmitField},
	"InventoryConfiguration":      {Mode: awsapi.OmitField},
	"AnalyticsConfiguration":      {Mode: awsapi.OmitField},
	"Retention":                   {Mode: awsapi.OmitField},
	"LegalHold":                   {Mode: awsapi.OmitField},
	"ObjectLockConfiguration":     {Mode: awsapi.OmitField},
	"RestoreRequest":              {Mode: awsapi.OmitField},
}}

// rejectedInput is bound for observation, never admitted for dispatch.
// The original transport request owns its host and measured body bytes.
type rejectedInput struct {
	input   any
	request awsapi.Request
}

func bindRejectedInput(model awscatalog.Service, operation awscatalog.Operation, request awsapi.Request, input any) *rejectedInput {
	if err := awsapi.BindHTTP(model, operation, request, input); err != nil {
		envelope := request
		envelope.Body = nil
		_ = awsapi.BindHTTP(model, operation, envelope, input)
	}
	return &rejectedInput{input: input, request: request}
}

func (s *Service) RequestErrorInput(operation awscatalog.Operation, request awsapi.Request) any {
	if s.events == nil {
		return nil
	}
	if _, known := eventClasses[string(operation.Name)]; !known {
		return nil
	}
	input, err := api.NewInput(string(operation.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("s3")
	// Admission already rejected this request. Retain the transport fields
	// bound before a malformed payload; its original XML is projected only
	// when independently parseable, never admitted as a command.
	return bindRejectedInput(model, operation, request, input)
}

func (s *Service) RecordRequestError(ctx context.Context, decoded awsapi.DecodedRequest, failure *awswire.Error) error {
	if s.events == nil {
		return nil
	}
	name := string(decoded.Operation.Name)
	if _, known := eventClasses[name]; !known {
		return nil
	}
	input := decoded.Input
	var request *awsapi.Request
	if rejected, ok := input.(*rejectedInput); ok {
		input, request = rejected.input, &rejected.request
	}
	var c *apiCall
	if copy, ok := input.(*api.CopyObjectInput); ok {
		c = s.copyCall(ctx, copy)
	} else {
		model, _ := awscatalog.LookupService("s3")
		body, err := awsapi.EncodeDocument(model, decoded.Operation.Input, input, &rejectedProjection)
		if err != nil {
			return err
		}
		var params map[string]any
		if err := json.Unmarshal(body, &params); err != nil {
			return err
		}
		bucket, _ := params["bucketName"].(string)
		key, _ := params["key"].(string)
		if request == nil {
			c = call(ctx, name, bucket, key)
		} else {
			c = s.transferCall(ctx, name, bucket, key)
		}
		if params != nil {
			c.params = params
		}
		switch in := input.(type) {
		case *api.CreateBucketInput:
			if request != nil {
				xmlAuditParameters(c, request.Body)
			}
		case *api.GetBucketLocationInput:
			c.params["location"] = ""
		case *api.PutBucketPolicyInput, *api.GetBucketPolicyInput, *api.DeleteBucketPolicyInput:
			c.params["policy"] = ""
		case *api.PutBucketTaggingInput:
			bucketTaggingParameters(c, in.Tagging)
			c.params["tagging"] = ""
		case *api.GetBucketTaggingInput, *api.DeleteBucketTaggingInput:
			c.params["tagging"] = ""
		case *api.GetBucketAbacInput, *api.PutBucketAbacInput:
			c.params["abac"] = ""
		case *api.GetBucketAccelerateConfigurationInput, *api.PutBucketAccelerateConfigurationInput:
			c.params["accelerate"] = ""
		case *api.GetObjectTaggingInput, *api.PutObjectTaggingInput, *api.DeleteObjectTaggingInput:
			c.params["tagging"] = ""
		case *api.PutBucketEncryptionInput:
			bucketEncryptionParameters(c, in.ServerSideEncryptionConfiguration)
		case *api.GetBucketEncryptionInput, *api.DeleteBucketEncryptionInput:
			c.params["encryption"] = ""
		case *api.PutBucketCorsInput:
			corsParameters(c, in.CORSConfiguration)
			c.params["cors"] = ""
		case *api.GetBucketCorsInput, *api.DeleteBucketCorsInput:
			c.params["cors"] = ""
		case *api.PutBucketWebsiteInput:
			websiteParameters(c, in.WebsiteConfiguration)
			c.params["website"] = ""
		case *api.GetBucketWebsiteInput, *api.DeleteBucketWebsiteInput:
			c.params["website"] = ""
		case *api.GetBucketRequestPaymentInput, *api.PutBucketRequestPaymentInput:
			c.params["requestPayment"] = ""
			if request != nil {
				xmlAuditParameters(c, request.Body)
			}
		case *api.GetBucketLoggingInput, *api.PutBucketLoggingInput:
			c.params["logging"] = ""
			if request != nil {
				xmlAuditParameters(c, request.Body)
			}
		case *api.PutBucketMetricsConfigurationInput, *api.GetBucketMetricsConfigurationInput,
			*api.DeleteBucketMetricsConfigurationInput, *api.ListBucketMetricsConfigurationsInput:
			c.params["metrics"] = ""
		case *api.PutBucketInventoryConfigurationInput, *api.GetBucketInventoryConfigurationInput,
			*api.DeleteBucketInventoryConfigurationInput, *api.ListBucketInventoryConfigurationsInput:
			c.params["inventory"] = ""
			if request != nil {
				xmlAuditParameters(c, request.Body)
			}
		case *api.PutBucketAnalyticsConfigurationInput, *api.GetBucketAnalyticsConfigurationInput,
			*api.DeleteBucketAnalyticsConfigurationInput, *api.ListBucketAnalyticsConfigurationsInput:
			c.params["analytics"] = ""
			if token, ok := c.params["continuationToken"]; ok {
				c.params["continuation-token"] = token
				delete(c.params, "continuationToken")
			}
			if request != nil {
				analyticsParameters(c, request.Query)
			}
		case *api.GetObjectLockConfigurationInput, *api.PutObjectLockConfigurationInput:
			c.params["object-lock"] = ""
			if request != nil {
				xmlAuditParameters(c, request.Body)
			}
		case *api.GetObjectRetentionInput, *api.PutObjectRetentionInput:
			c.params["retention"] = ""
		case *api.GetObjectLegalHoldInput, *api.PutObjectLegalHoldInput:
			c.params["legal-hold"] = ""
		case *api.RestoreObjectInput:
			c.params["restore"] = ""
			if request != nil {
				xmlAuditParameters(c, request.Body)
			}
		case *api.PutBucketNotificationConfigurationInput:
			notificationParameters(c, in.NotificationConfiguration)
		case *api.GetBucketNotificationConfigurationInput:
			c.params["notification"] = ""
		}
	}
	if request != nil {
		c.params["Host"] = request.Host
		c.additional["bytesTransferredIn"] = len(request.Body)
		switch input.(type) {
		case *api.GetBucketAbacInput, *api.PutBucketAbacInput:
			abacBodyParameters(c, request.Body, request.Header.Get("x-amz-expected-bucket-owner"), failure)
		case *api.PutBucketAccelerateConfigurationInput:
			switch failure.Code {
			case "AccessDenied", "NoSuchBucket", "InvalidBucketOwnerAWSAccountID", "PermanentRedirect", "InvalidDigest", "InvalidRequest":
				// Native acceleration rejects authority, routing and header
				// failures before admitting document bytes. BadDigest differs:
				// it consumed the body while checking its checksum.
				c.additional["bytesTransferredIn"] = 0
			}
		}
	}
	if c.bucket != "" {
		if err := s.repository.View(ctx, func(reader Reader) error {
			b, point, err := resolveBucketReference(reader, c.bucket)
			if err != nil {
				if errors.Is(err, ErrNotFound) || wireError(err).StatusCode < 500 {
					return nil
				}
				return err
			}
			if point != nil {
				c.accessPoint, c.accessPointReference = point, c.bucket
				c.bucket = b.Key.Name
			}
			c.account, c.region = b.AccountID, b.Region
			s.captureRequest(reader, b, point)
			return nil
		}); err != nil {
			return err
		}
	}
	return s.record(ctx, c, failure)
}

// Analytics records only query selectors, never the configuration document.
// Native duplicate selectors retain their submitted order as JSON arrays.
func analyticsParameters(c *apiCall, query url.Values) {
	c.params["analytics"] = ""
	for _, name := range []string{"id", "continuation-token"} {
		values := query[name]
		switch len(values) {
		case 0:
		case 1:
			c.params[name] = values[0]
		default:
			c.params[name] = values
		}
	}
}

// CreateBucket records creation headers independently of whether admission
// succeeds. Native records omit the Object Lock flag and nest custom grants.
func createBucketParameters(c *apiCall, in *api.CreateBucketInput) {
	if in.ObjectOwnership != nil {
		c.params["x-amz-object-ownership"] = value(in.ObjectOwnership)
	}
	if in.ACL != nil {
		c.params["x-amz-acl"] = value(in.ACL)
	}
	var grants map[string]any
	for _, grant := range []struct{ name, value string }{
		{"x-amz-grant-full-control", value(in.GrantFullControl)},
		{"x-amz-grant-read", value(in.GrantRead)},
		{"x-amz-grant-read-acp", value(in.GrantReadACP)},
		{"x-amz-grant-write", value(in.GrantWrite)},
		{"x-amz-grant-write-acp", value(in.GrantWriteACP)},
	} {
		if grant.value != "" {
			if grants == nil {
				grants = map[string]any{}
			}
			grants[grant.name] = grant.value
		}
	}
	if grants != nil {
		c.params["accessControlList"] = grants
	}
}

func ownershipParameters(c *apiCall, controls *api.OwnershipControls) {
	if controls == nil {
		return
	}
	rules := make([]any, 0, len(controls.Rules))
	for _, rule := range controls.Rules {
		rules = append(rules, map[string]any{"ObjectOwnership": value(rule.ObjectOwnership)})
	}
	document := map[string]any{"xmlns": "http://s3.amazonaws.com/doc/2006-03-01/"}
	if len(rules) == 1 {
		document["Rule"] = rules[0]
	} else {
		document["Rule"] = rules
	}
	c.params["OwnershipControls"] = document
}

func aclParameters(c *apiCall, canned string, policy *api.AccessControlPolicy) {
	if canned != "" {
		c.params["x-amz-acl"] = canned
	}
	if policy == nil {
		return
	}
	document := map[string]any{"xmlns": "http://s3.amazonaws.com/doc/2006-03-01/"}
	if policy.Owner != nil {
		owner := map[string]any{}
		if policy.Owner.ID != nil {
			owner["ID"] = value(policy.Owner.ID)
		}
		if policy.Owner.DisplayName != nil {
			owner["DisplayName"] = value(policy.Owner.DisplayName)
		}
		document["Owner"] = owner
	}
	grants := make([]any, 0, len(policy.Grants))
	for _, grant := range policy.Grants {
		entry := map[string]any{}
		if grant.Permission != nil {
			entry["Permission"] = value(grant.Permission)
		}
		if g := grant.Grantee; g != nil {
			grantee := map[string]any{"xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance"}
			if g.Type != nil {
				grantee["xsi:type"] = value(g.Type)
			}
			if g.ID != nil {
				grantee["ID"] = value(g.ID)
			}
			if g.DisplayName != nil {
				grantee["DisplayName"] = value(g.DisplayName)
			}
			if g.EmailAddress != nil {
				grantee["EmailAddress"] = value(g.EmailAddress)
			}
			if g.URI != nil {
				grantee["URI"] = value(g.URI)
			}
			entry["Grantee"] = grantee
		}
		grants = append(grants, entry)
	}
	list := map[string]any{}
	if len(grants) == 1 {
		list["Grant"] = grants[0]
	} else if len(grants) > 1 {
		list["Grant"] = grants
	}
	document["AccessControlList"] = list
	c.params["AccessControlPolicy"] = document
}
