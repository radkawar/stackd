package s3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// apiCall is the source-owned, sanitized projection. Payloads, user metadata and
// encryption material never enter the journal through this boundary.
type apiCall struct {
	service                            string
	name, bucket, key, account, region string
	readOnly, data                     bool
	params                             map[string]any
	additional                         map[string]any
	response                           map[string]any
	resources                          []journal.APIEventResource
	eventID                            string
	requestID                          string
	notifications                      *NotificationConfiguration
	statusOverride                     int
	accountingCaptured                 bool
	accessLogOperation                 string
	aclRequired                        bool
	publicAccess                       PublicAccessBlock
	bucketTags                         []Tag
	accessPoint                        *AccessPointRecord
	accessPointTags                    []Tag
	accessPointReference               string
	copySource                         bool
	accessLog                          *AccessLogDelivery
	requestMetrics                     *requestMetricsObservation
}

func call(ctx context.Context, name, bucket, key string) *apiCall {
	noteRequestCommand(ctx)
	m := awsctx.FromContext(ctx)
	class := eventClasses[name]
	c := &apiCall{service: "s3", name: name, bucket: bucket, key: key, account: m.AccountID, region: m.Region, readOnly: class.readOnly, data: class.data, params: map[string]any{}}
	if host, ok := ctx.Value(requestHostKey{}).(string); ok && host != "" {
		c.params["Host"] = host
	}
	if payment, ok := ctx.Value(requestPaymentKey{}).(*requestPayment); ok && payment.payer != "" {
		c.params["x-amz-request-payer"] = payment.payer
	}
	if bucket != "" {
		c.params["bucketName"] = bucket
	}
	if key != "" {
		c.params["key"] = key
	}
	return c
}

// observationContext gives an internal API call its own request identity while
// retaining the worker's role session and originating causal event.
func (c *apiCall) observationContext(ctx context.Context) context.Context {
	if c.requestID == "" {
		return ctx
	}
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID, metadata.Region = c.requestID, c.region
	return awsctx.WithMetadata(ctx, metadata)
}

func (s *Service) transferCall(ctx context.Context, name, bucket, key string) *apiCall {
	c := call(ctx, name, bucket, key)
	c.additional = map[string]any{
		"x-amz-id-2": awswire.S3HostID(awsctx.FromContext(ctx).RequestID),
	}
	if s.events != nil {
		c.eventID = uuid.NewString()
	}
	return c
}

// accessCall measures the public request, including XML configuration bodies.
func (s *Service) accessCall(ctx context.Context, name, bucket, key, marker string) *apiCall {
	c := s.transferCall(ctx, name, bucket, key)
	if marker != "" {
		c.params[marker] = ""
	}
	request, _ := awsapi.FromContext(ctx)
	c.additional["bytesTransferredIn"] = len(request.Body)
	return c
}
func (s *Service) record(ctx context.Context, c *apiCall, wire *awswire.Error) error {
	ctx = c.observationContext(ctx)
	if s.events == nil {
		return s.recordRequestCommand(ctx, c, wire)
	}
	m := awsctx.FromContext(ctx)
	if point := c.accessPoint; point != nil {
		c.params["bucketName"] = point.Bucket.Name
		if strings.HasPrefix(c.accessPointReference, "arn:") {
			c.params["accountId"], c.params["accessPointName"] = point.Key.AccountID, point.Key.Name
		} else {
			c.params["accessPointAlias"] = c.accessPointReference
		}
	}
	params, err := json.Marshal(c.params)
	if err != nil {
		return err
	}
	category := journal.APICallCategory("Management")
	if c.data {
		category = journal.APICallCategory("Data")
	}
	event := journal.APICallCompleted{EventID: c.eventID, EventSource: "s3.amazonaws.com", EventName: c.name, Category: category, ReadOnly: c.readOnly, RequestParameters: params, ResponseElements: json.RawMessage("null")}
	if c.response != nil {
		event.ResponseElements, err = json.Marshal(c.response)
		if err != nil {
			return err
		}
	}
	if c.bucket != "" {
		arn := (BucketKey{m.Partition, c.bucket}).ARN()
		event.Resources = []journal.APIResource{{Type: "AWS::S3::Bucket", Name: c.bucket}}
		includeBucket := c.name != "CreateBucket"
		if wire != nil && wire.Code == "NoSuchBucket" {
			switch c.name {
			case "GetBucketAbac", "PutBucketAbac", "GetBucketAccelerateConfiguration", "PutBucketAccelerateConfiguration",
				"PutBucketAnalyticsConfiguration", "GetBucketAnalyticsConfiguration", "DeleteBucketAnalyticsConfiguration", "ListBucketAnalyticsConfigurations":
				includeBucket = false
			}
		}
		if includeBucket {
			event.EventResources = []journal.APIEventResource{{AccountID: c.account, Type: "AWS::S3::Bucket", ARN: arn}}
		}
		if c.name == "HeadBucket" || c.name == "DeleteObjects" {
			event.EventResources = append(event.EventResources, journal.APIEventResource{Type: "AWS::S3::Object", ARNPrefix: arn + "/"})
		}
		if c.name == "ListObjects" || c.name == "ListObjectsV2" {
			event.EventName = "ListObjects"
			prefix, _ := c.params["prefix"].(string)
			event.EventResources = append(event.EventResources, journal.APIEventResource{Type: "AWS::S3::Object", ARNPrefix: arn + "/" + prefix})
		}
		if c.name == "ListObjectVersions" {
			prefix, _ := c.params["prefix"].(string)
			event.EventResources = append(event.EventResources, journal.APIEventResource{Type: "AWS::S3::Object", ARNPrefix: arn + "/" + prefix})
		}
		if c.key != "" {
			event.EventResources = append(event.EventResources, journal.APIEventResource{Type: "AWS::S3::Object", ARN: arn + "/" + c.key})
		}
	}
	if point := c.accessPoint; point != nil {
		event.EventResources = append(event.EventResources, journal.APIEventResource{AccountID: point.Key.AccountID, Type: "AWS::S3::AccessPoint", ARN: point.Key.ARN()})
	}
	if c.aclRequired {
		if c.additional == nil {
			c.additional = map[string]any{}
		}
		c.additional["aclRequired"] = "Yes"
	}
	if c.data || c.additional != nil {
		if c.additional == nil {
			c.additional = map[string]any{}
		}
		for _, name := range []string{"bytesTransferredIn", "bytesTransferredOut"} {
			if _, measured := c.additional[name]; !measured {
				c.additional[name] = 0
			}
		}
		if _, supplied := c.additional["x-amz-id-2"]; !supplied {
			c.additional["x-amz-id-2"] = awswire.S3HostID(m.RequestID)
		}
		if m.SignatureVersion != "" {
			c.additional["SignatureVersion"] = m.SignatureVersion
			c.additional["AuthenticationMethod"] = m.AuthenticationMethod
		}
		if wire != nil {
			c.additional["httpStatusCode"] = wire.StatusCode
		} else if _, supplied := c.additional["httpStatusCode"]; !supplied {
			model, _ := awscatalog.LookupService(c.service)
			operation, _ := model.Operation(c.name)
			c.additional["httpStatusCode"] = operation.HTTPStatus
		}
		if c.statusOverride != 0 {
			c.additional["httpStatusCode"] = c.statusOverride
		}
		// Native HEAD errors account for their logical XML error document.
		// Internal copy reads have no public response and retain zero traffic.
		if wire != nil && m.InvokedBy != "AWS Internal" {
			if err := prepareErrorResponse(c, m.RequestID, wire); err != nil {
				return err
			}
		}
	}
	switch c.name {
	case "GetBucketAccelerateConfiguration", "PutBucketAccelerateConfiguration":
		event.EventName = "PutAccelerateConfiguration"
		if c.readOnly {
			event.EventName = "GetAccelerateConfiguration"
		}
		event.Resources = nil
	case "ListBucketMetricsConfigurations":
		event.EventName = "GetBucketMetricsConfiguration"
	case "PutBucketInventoryConfiguration", "GetBucketInventoryConfiguration", "DeleteBucketInventoryConfiguration", "ListBucketInventoryConfigurations":
		// Native inventory history is not indexed by bucket resource name.
		event.Resources = nil
		if c.name == "ListBucketInventoryConfigurations" {
			event.EventName = "GetBucketInventoryConfiguration"
		}
	case "PutBucketAnalyticsConfiguration", "GetBucketAnalyticsConfiguration", "DeleteBucketAnalyticsConfiguration", "ListBucketAnalyticsConfigurations":
		// Correlated native Analytics records omit history resource indexes
		// and do not admit request bytes when the bucket does not exist.
		event.Resources = nil
		if c.name == "ListBucketAnalyticsConfigurations" {
			event.EventName = "GetBucketAnalyticsConfiguration"
		}
		if wire != nil && wire.Code == "NoSuchBucket" && c.additional != nil {
			c.additional["bytesTransferredIn"] = 0
		}
	case "GetObjectLockConfiguration", "PutObjectLockConfiguration":
		event.EventName = strings.Replace(c.name, "ObjectLockConfiguration", "BucketObjectLockConfiguration", 1)
	case "GetObjectRetention", "PutObjectRetention":
		event.EventName = strings.Replace(c.name, "ObjectRetention", "ObjectLockRetention", 1)
	case "GetObjectLegalHold", "PutObjectLegalHold":
		event.EventName = strings.Replace(c.name, "ObjectLegalHold", "ObjectLockLegalHold", 1)
	case "PutBucketNotificationConfiguration":
		event.EventName = "PutBucketNotification"
	case "GetBucketNotificationConfiguration":
		event.EventName = "GetBucketNotification"
	case "GetPublicAccessBlock", "PutPublicAccessBlock", "DeletePublicAccessBlock":
		scope := "Bucket"
		if c.service == "s3control" {
			scope = "Account"
		}
		event.EventName = strings.TrimSuffix(c.name, "PublicAccessBlock") + scope + "PublicAccessBlock"
	}
	event.EventResources = append(event.EventResources, c.resources...)
	if c.additional != nil {
		event.AdditionalEventData, err = json.Marshal(c.additional)
		if err != nil {
			return err
		}
	}
	if wire != nil {
		event.ErrorCode, event.ErrorMessage = wire.Code, wire.Message
	}
	scope := journal.Envelope{At: s.clock.Now(), Partition: m.Partition, AccountID: c.account, Region: c.region}
	return s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.recordRequestCommand(tx.Context(), c, wire); err != nil {
			return err
		}
		if m.AccountID != c.account && m.PrincipalARN != "" && m.ServicePrincipal.Name == "" {
			// Native cross-account calls produce distinct caller and owner
			// records with one shared identity. Keep both in the source commit.
			event.SharedEventID = uuid.NewString()
			ownerEventID := event.EventID
			event.EventID = ""
			callerScope := scope
			ownerResources := event.EventResources
			event.EventResources = slices.Clone(ownerResources)
			for i := range event.EventResources {
				if event.EventResources[i].AccountID == c.account {
					event.EventResources[i].AccountID = "HIDDEN_DUE_TO_SECURITY_REASONS"
				}
			}
			callerScope.AccountID = m.AccountID
			if err := s.events.Record(tx.Context(), callerScope, event); err != nil {
				return err
			}
			event.EventResources = ownerResources
			event.EventID = ownerEventID
			event.Identity = journal.APIIdentity{Type: "AWSAccount", AccountID: m.AccountID, PrincipalID: m.PrincipalID}
		}
		return s.events.Record(tx.Context(), scope, event)
	})
}
func (s *Service) execute(ctx context.Context, c *apiCall, fn func(Transaction) error) *awswire.Error {
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := fn(tx); err != nil {
			return err
		}
		return s.record(tx.Context(), c, nil)
	})
	if err == nil {
		return nil
	}
	return s.complete(ctx, c, err)
}

// complete records reads and rejected commands after their repository/KMS
// callbacks have ended. Successful mutations record within execute instead.
func (s *Service) complete(ctx context.Context, c *apiCall, err error) *awswire.Error {
	wire := wireError(err)
	if recordErr := s.record(ctx, c, wire); recordErr != nil {
		return wireError(recordErr)
	}
	return wire
}

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func validateBucket(name string) *awswire.Error {
	if !bucketName.MatchString(name) || strings.Contains(name, "..") || net.ParseIP(name) != nil || strings.HasPrefix(name, "xn--") || strings.HasPrefix(name, "sthree-") || strings.HasPrefix(name, "amzn-s3-demo-") {
		return failure("InvalidBucketName", "The specified bucket is not valid.", 400)
	}
	for _, suffix := range []string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"} {
		if strings.HasSuffix(name, suffix) {
			return failure("InvalidBucketName", "The specified bucket is not valid.", 400)
		}
	}
	return nil
}
func validateKey(key string) *awswire.Error {
	if key == "" || len(key) > 1024 || !utf8.ValidString(key) {
		return invalid("Object keys must contain between 1 and 1024 UTF-8 bytes.")
	}
	depth := 0
	for _, part := range strings.Split(key, "/") {
		if part == ".." {
			depth--
		} else if part != "" && part != "." {
			depth++
		}
		if depth < 0 {
			return invalid("Invalid relative object key.")
		}
	}
	return nil
}
func (s *Service) bucket(tx Reader, c *apiCall, expected string) (BucketRecord, error) {
	reference := c.bucket
	if c.accessPointReference != "" {
		reference = c.accessPointReference
	}
	b, point, err := resolveBucketReference(tx, reference)
	if errors.Is(err, ErrNotFound) {
		wire := failure("NoSuchBucket", "The specified bucket does not exist.", 404)
		wire.BucketName = c.bucket
		err = wire
	}
	c.accessPoint = point
	if point != nil {
		c.accessPointReference = reference
	}
	if err != nil {
		return b, err
	}
	if c.accessPointReference != "" && c.bucket != reference && c.bucket != b.Key.Name {
		return b, failure("OperationAborted", "A conflicting operation changed the access point's bucket.", 409)
	}
	c.bucket = b.Key.Name
	c.account, c.region = b.AccountID, b.Region
	s.captureRequestCommand(tx, c, b)
	if point != nil {
		if wire := admitAccessPoint(tx.Context(), c); wire != nil {
			return b, wire
		}
	}
	if wire := admitAcceleration(tx.Context(), c, b); wire != nil {
		return b, wire
	}
	if expected != "" && !accountNumber.MatchString(expected) {
		return b, failure("InvalidBucketOwnerAWSAccountID", "The value of the expected bucket owner parameter must be an AWS Account ID. Please use a valid AWS Account ID and retry the request. ["+expected+"]", 400)
	}
	if expected != "" && expected != b.AccountID {
		return b, denied()
	}
	if wire := admitRequestPayment(tx.Context(), b); wire != nil {
		return b, wire
	}
	if point == nil {
		c.publicAccess, err = s.bucketPublicAccess(tx, b)
	} else {
		c.publicAccess, err = s.accessPointPublicAccess(tx, *point, b)
	}
	if err != nil {
		return b, err
	}
	c.bucketTags = nil
	if b.ABACEnabled {
		c.bucketTags, err = tx.BucketTags(b.Key)
		if err != nil {
			return b, err
		}
	}
	c.accessPointTags = nil
	if point != nil {
		c.accessPointTags, err = tx.AccessPointTags(point.Key)
		if err != nil {
			return b, err
		}
	}
	return b, nil
}
func (s *Service) authorize(ctx context.Context, c *apiCall, b BucketRecord, action, key string, conditions map[string][]string) *awswire.Error {
	return s.authorizeACL(ctx, c, b, action, key, conditions, nil, nil)
}

func (s *Service) authorizeObject(ctx context.Context, c *apiCall, b BucketRecord, object ObjectRecord, action string, conditions map[string][]string) *awswire.Error {
	return s.authorizeACL(ctx, c, b, action, object.Key.Name, conditions, &object, nil)
}

func (s *Service) authorizeACL(ctx context.Context, c *apiCall, b BucketRecord, action, key string, conditions map[string][]string, object *ObjectRecord, additionalDenyActions []string) *awswire.Error {
	arn := b.Key.ARN()
	if key != "" {
		arn += "/" + key
	}
	if len(c.bucketTags) != 0 || len(c.accessPointTags) != 0 {
		// Keep request conditions reusable when external work is followed by
		// authorization against a newer bucket-tag snapshot.
		conditions = maps.Clone(conditions)
	}
	if conditions == nil {
		conditions = map[string][]string{}
	}
	conditions["s3:ResourceAccount"] = []string{b.AccountID}
	for _, tag := range c.bucketTags {
		values := []string{tag.Value}
		conditions["aws:ResourceTag/"+tag.Key] = values
		conditions["s3:BucketTag/"+tag.Key] = values
	}
	for _, tag := range c.accessPointTags {
		conditions["s3:AccessPointTag/"+tag.Key] = []string{tag.Value}
	}
	if point := c.accessPoint; point != nil {
		conditions["s3:DataAccessPointArn"] = []string{point.Key.ARN()}
		conditions["s3:DataAccessPointAccount"] = []string{point.Key.AccountID}
		conditions["s3:AccessPointNetworkOrigin"] = []string{accessPointNetworkOrigin(*point)}
	}
	bound := b.Policy
	m := awsctx.FromContext(ctx)
	// Bucket-owner root recovery bypasses only this bucket policy, never IAM or
	// Organizations controls evaluated by the shared authorizer.
	if (action == "GetBucketPolicy" || action == "PutBucketPolicy" || action == "DeleteBucketPolicy") && m.AccountID == b.AccountID && m.PrincipalARN == "arn:"+b.Key.Partition+":iam::"+b.AccountID+":root" {
		bound = authorization.BoundPolicy{}
	}
	if c.publicAccess.RestrictPublicBuckets && bound.Document != "" && m.AccountID != b.AccountID && m.ServicePrincipal.Name == "" {
		public, err := bucketPolicyPublic(bound.Document, b.Key.ARN())
		if err != nil {
			return wireError(err)
		}
		if public {
			return denied()
		}
	}
	acl := effectiveACL(b, b.ACL, c.publicAccess.IgnorePublicACLs)
	permission := aclPermission(action, true)
	foreign := false
	if object != nil {
		acl = effectiveACL(b, object.ACL, c.publicAccess.IgnorePublicACLs)
		permission = aclPermission(action, false)
		foreign = permission != "" && acl.OwnerAccountID != b.AccountID
	}
	accountGrant, publicGrant := aclGrants(ctx, b, acl, permission, object != nil)
	request := authorization.Request{Action: "s3:" + action, AdditionalDenyActions: additionalDenyActions, ResourceARN: arn, ResourceAccountID: b.AccountID, ResourcePolicies: []authorization.BoundPolicy{bound}, Context: conditions, ResourceAccountGrant: accountGrant, ResourcePublicGrant: publicGrant, ResourcePolicyDenyOnly: foreign, RequireResourcePolicy: foreign}
	// ACL authority does not grant unmapped actions such as object tagging.
	// Those use the bucket's IAM resource policy, including foreign-owned objects.
	if permission != "" && b.Ownership != "BucketOwnerEnforced" && (accountGrant || publicGrant) {
		request.ObserveDecision = c.observeAuthorization
	}
	if wire := s.authorizer.Authorize(ctx, request); wire != nil {
		return wire
	}
	if (action == "GetBucketPolicy" || action == "PutBucketPolicy" || action == "DeleteBucketPolicy") && m.AccountID != b.AccountID {
		return failure("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)
	}
	if c.accessPoint != nil {
		return s.authorizeAccessPointData(ctx, c, action, key, conditions)
	}
	return nil
}

func (c *apiCall) observeAuthorization(result policy.AuthorizationResult) {
	if result.Decision == policy.Allow && result.ServiceGrantRequired {
		c.aclRequired = true
	}
}

func (s *Service) objectWrite(ctx context.Context, c *apiCall, b BucketRecord, key, acl string, conditions map[string][]string) *awswire.Error {
	if wire := validateKey(key); wire != nil {
		return wire
	}
	if conditions == nil {
		conditions = map[string][]string{}
	}
	if acl != "" {
		conditions["s3:x-amz-acl"] = []string{acl}
	}
	if wire := s.authorize(ctx, c, b, "PutObject", key, conditions); wire != nil {
		return wire
	}
	return nil
}
func canonicalID(partition, account string) string {
	sum := sha256.Sum256([]byte(partition + ":" + account))
	return hex.EncodeToString(sum[:])
}
