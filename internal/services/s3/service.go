// Package s3 owns general-purpose buckets and encrypted object version histories.
package s3

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type Config struct {
	Repository       Repository
	Authorizer       authorization.Authorizer
	PolicyBinder     authorization.PolicyBinder
	AccountPolicies  AccountPolicySource
	APIEvents        apievents.Recorder
	Clock            clock.Clock
	Keys             EncryptionKeys
	Notifications    NotificationDestinations
	ObjectEvents     NativeObjectEvents
	ReplicationRoles ReplicationRoles
	Metrics          MetricPublisher
	InventoryORC     InventoryORCEncoder
}
type Service struct {
	repository       Repository
	authorizer       authorization.Authorizer
	binder           authorization.PolicyBinder
	accountPolicies  AccountPolicySource
	events           apievents.Recorder
	clock            clock.Clock
	keys             EncryptionKeys
	notifications    NotificationDestinations
	objectEvents     NativeObjectEvents
	replicationRoles ReplicationRoles
	metrics          MetricPublisher
	inventoryORC     InventoryORCEncoder
	jobs             *scheduler.Driver
	operations       map[string]func(context.Context, any) (any, *awswire.Error)
}

func New(c Config) *Service {
	if c.Repository == nil {
		c.Repository = NewMemoryRepository(nil)
	}
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	if c.PolicyBinder == nil {
		c.PolicyBinder, _ = c.Authorizer.(authorization.PolicyBinder)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, events: c.APIEvents, clock: c.Clock, keys: c.Keys, operations: map[string]func(context.Context, any) (any, *awswire.Error){}}
	s.notifications, s.objectEvents = c.Notifications, c.ObjectEvents
	s.accountPolicies = c.AccountPolicies
	s.replicationRoles = c.ReplicationRoles
	s.metrics = c.Metrics
	s.inventoryORC = c.InventoryORC
	s.jobs = scheduler.New(c.Clock, notificationChanges{s}, notificationDeliveries{s}, accessLogDeliveries{s}, objectRestoreJobs{s}, replicationJobs{s}, replicationMetricJobs{s}, lifecycleJobs{s}, tieringJobs{s}, inventoryReports{s})
	register(s, "CreateBucket", s.createBucket)
	register(s, "DeleteBucket", s.deleteBucket)
	register(s, "HeadBucket", s.HeadBucket)
	register(s, "ListBuckets", s.listBuckets)
	register(s, "GetBucketLocation", s.getBucketLocation)
	register(s, "GetBucketAcl", s.getBucketACL)
	register(s, "PutBucketAcl", s.putBucketACL)
	register(s, "GetObjectAcl", s.getObjectACL)
	register(s, "PutObjectAcl", s.putObjectACL)
	register(s, "PutBucketPolicy", s.putBucketPolicy)
	register(s, "GetBucketPolicy", s.getBucketPolicy)
	register(s, "DeleteBucketPolicy", s.deleteBucketPolicy)
	register(s, "GetBucketPolicyStatus", s.getBucketPolicyStatus)
	register(s, "GetBucketTagging", s.getBucketTagging)
	register(s, "PutBucketTagging", s.putBucketTagging)
	register(s, "DeleteBucketTagging", s.deleteBucketTagging)
	register(s, "GetBucketOwnershipControls", s.getBucketOwnershipControls)
	register(s, "PutBucketOwnershipControls", s.putBucketOwnershipControls)
	register(s, "DeleteBucketOwnershipControls", s.deleteBucketOwnershipControls)
	register(s, "GetPublicAccessBlock", s.getPublicAccessBlock)
	register(s, "PutPublicAccessBlock", s.putPublicAccessBlock)
	register(s, "DeletePublicAccessBlock", s.deletePublicAccessBlock)
	register(s, "GetBucketAbac", s.getBucketAbac)
	register(s, "PutBucketAbac", s.putBucketAbac)
	register(s, "GetBucketEncryption", s.getBucketEncryption)
	register(s, "PutBucketEncryption", s.putBucketEncryption)
	register(s, "DeleteBucketEncryption", s.deleteBucketEncryption)
	register(s, "GetBucketCors", s.getBucketCors)
	register(s, "PutBucketCors", s.putBucketCors)
	register(s, "DeleteBucketCors", s.deleteBucketCors)
	register(s, "GetBucketWebsite", s.getBucketWebsite)
	register(s, "PutBucketWebsite", s.putBucketWebsite)
	register(s, "DeleteBucketWebsite", s.deleteBucketWebsite)
	register(s, "GetBucketRequestPayment", s.getBucketRequestPayment)
	register(s, "PutBucketRequestPayment", s.putBucketRequestPayment)
	register(s, "GetBucketLogging", s.getBucketLogging)
	register(s, "PutBucketLogging", s.putBucketLogging)
	register(s, "GetBucketNotificationConfiguration", s.getBucketNotificationConfiguration)
	register(s, "PutBucketNotificationConfiguration", s.putBucketNotificationConfiguration)
	register(s, "PutObject", s.putObjectResponse)
	register(s, "CopyObject", s.copyObject)
	register(s, "CreateMultipartUpload", s.createMultipartUpload)
	register(s, "UploadPart", s.uploadPart)
	register(s, "UploadPartCopy", s.uploadPartCopy)
	register(s, "CompleteMultipartUpload", s.completeMultipartUpload)
	register(s, "AbortMultipartUpload", s.abortMultipartUpload)
	register(s, "ListMultipartUploads", s.listMultipartUploads)
	register(s, "ListParts", s.listParts)
	register(s, "GetObjectAttributes", s.getObjectAttributes)
	register(s, "RestoreObject", s.restoreObject)
	register(s, "GetObject", s.GetObject)
	register(s, "HeadObject", s.HeadObject)
	register(s, "GetObjectTagging", s.getObjectTagging)
	register(s, "PutObjectTagging", s.putObjectTagging)
	register(s, "DeleteObjectTagging", s.deleteObjectTagging)
	register(s, "DeleteObject", s.deleteObject)
	register(s, "DeleteObjects", s.deleteObjects)
	register(s, "ListObjects", s.listObjects)
	register(s, "ListObjectsV2", s.listObjectsV2)
	register(s, "GetBucketVersioning", s.getBucketVersioning)
	register(s, "PutBucketVersioning", s.putBucketVersioning)
	register(s, "PutBucketReplication", s.putBucketReplication)
	register(s, "GetBucketReplication", s.getBucketReplication)
	register(s, "DeleteBucketReplication", s.deleteBucketReplication)
	register(s, "PutBucketLifecycleConfiguration", s.putBucketLifecycleConfiguration)
	register(s, "GetBucketLifecycleConfiguration", s.getBucketLifecycleConfiguration)
	register(s, "DeleteBucketLifecycle", s.deleteBucketLifecycle)
	register(s, "PutBucketIntelligentTieringConfiguration", s.putBucketIntelligentTieringConfiguration)
	register(s, "GetBucketIntelligentTieringConfiguration", s.getBucketIntelligentTieringConfiguration)
	register(s, "DeleteBucketIntelligentTieringConfiguration", s.deleteBucketIntelligentTieringConfiguration)
	register(s, "ListBucketIntelligentTieringConfigurations", s.listBucketIntelligentTieringConfigurations)
	register(s, "PutBucketMetricsConfiguration", s.putBucketMetricsConfiguration)
	register(s, "GetBucketMetricsConfiguration", s.getBucketMetricsConfiguration)
	register(s, "DeleteBucketMetricsConfiguration", s.deleteBucketMetricsConfiguration)
	register(s, "ListBucketMetricsConfigurations", s.listBucketMetricsConfigurations)
	register(s, "PutBucketInventoryConfiguration", s.putBucketInventoryConfiguration)
	register(s, "GetBucketInventoryConfiguration", s.getBucketInventoryConfiguration)
	register(s, "DeleteBucketInventoryConfiguration", s.deleteBucketInventoryConfiguration)
	register(s, "ListBucketInventoryConfigurations", s.listBucketInventoryConfigurations)
	register(s, "PutBucketAnalyticsConfiguration", s.putBucketAnalyticsConfiguration)
	register(s, "GetBucketAnalyticsConfiguration", s.getBucketAnalyticsConfiguration)
	register(s, "DeleteBucketAnalyticsConfiguration", s.deleteBucketAnalyticsConfiguration)
	register(s, "ListBucketAnalyticsConfigurations", s.listBucketAnalyticsConfigurations)
	register(s, "GetBucketAccelerateConfiguration", s.getBucketAccelerateConfiguration)
	register(s, "PutBucketAccelerateConfiguration", s.putBucketAccelerateConfiguration)
	register(s, "ListObjectVersions", s.listObjectVersions)
	register(s, "GetObjectLockConfiguration", s.getObjectLockConfiguration)
	register(s, "PutObjectLockConfiguration", s.putObjectLockConfiguration)
	register(s, "GetObjectRetention", s.getObjectRetention)
	register(s, "PutObjectRetention", s.putObjectRetention)
	register(s, "GetObjectLegalHold", s.getObjectLegalHold)
	register(s, "PutObjectLegalHold", s.putObjectLegalHold)
	return s
}
func register[I, O any](s *Service, name string, fn func(context.Context, *I) (*O, *awswire.Error)) {
	s.operations[name] = func(ctx context.Context, in any) (any, *awswire.Error) { return fn(ctx, in.(*I)) }
}
func (s *Service) Operations() []string {
	names := make([]string, 0, len(s.operations))
	for n := range s.operations {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}
func (s *Service) RequestError(name string, err error) *awswire.Error {
	if mapped := aclRequestError(name, err); mapped != nil {
		return mapped
	}
	if mapped := createBucketRequestError(name, err); mapped != nil {
		return mapped
	}
	if mapped := websiteRequestError(name, err); mapped != nil {
		return mapped
	}
	if mapped := objectLockRequestError(name, err); mapped != nil {
		return mapped
	}
	if mapped := storageClassRequestError(name, err); mapped != nil {
		return mapped
	}
	if mapped := restoreRequestError(name, err); mapped != nil {
		return mapped
	}
	if mapped := lifecycleRequestError(name, err); mapped != nil {
		return mapped
	}
	if mapped := tieringRequestError(name, err); mapped != nil {
		return mapped
	}
	if mapped := configurationRequestError(name, err); mapped != nil {
		return mapped
	}
	if errors.Is(err, awsapi.ErrUnknownOperation) || errors.Is(err, awsapi.ErrUnsupportedBinding) {
		return unsupported(err.Error())
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) {
		if name == "PutPublicAccessBlock" && validation.Path == "PublicAccessBlockConfiguration" && validation.Constraint == "required" {
			return failure("MissingRequestBodyError", "Request Body is empty", 400)
		}
		if name == "PutBucketVersioning" && validation.Path == "VersioningConfiguration.Status" && validation.EnumValue == "" {
			return failure("IllegalVersioningConfigurationException", "The Versioning element must be specified", 400)
		}
		if name == "GetObjectAttributes" && strings.HasPrefix(validation.Path, "ObjectAttributes") {
			if validation.Constraint == "required" {
				return failure("InvalidRequest", "The x-amz-object-attributes header specifying the attributes to be retrieved is either missing or empty", 400)
			}
			return argumentError("x-amz-object-attributes", validation.EnumValue, "Invalid attribute name specified.")
		}
		if name == "CopyObject" && validation.Constraint == "enum" {
			var header, message string
			switch validation.Path {
			case "MetadataDirective":
				header, message = "x-amz-metadata-directive", "Unknown metadata directive."
			case "TaggingDirective":
				header, message = "x-amz-tagging-directive", "Unknown tagging directive."
			case "AnnotationDirective":
				header, message = "x-amz-object-annotation-directive", "The annotation directive is not valid. Valid values are COPY and EXCLUDE."
			}
			if header != "" {
				return argumentError(header, validation.EnumValue, message)
			}
		}
		if name == "PutBucketNotificationConfiguration" && validation.Constraint == "enum" && strings.Contains(validation.Path, ".Events[") {
			return invalid("The event is not supported for notifications")
		}
		if (name == "PutObjectTagging" || name == "PutBucketTagging") && strings.HasPrefix(validation.Constraint, "length.") && strings.Contains(validation.Path, ".TagSet[") && strings.HasSuffix(validation.Path, ".Key") {
			return failure("InvalidTag", "The TagKey you have provided is invalid", 400)
		}
		model, _ := awscatalog.LookupService("s3")
		operation, _ := model.Operation(name)
		input, _ := model.Shape(operation.Input)
		root := validation.Path
		if i := strings.IndexAny(root, ".["); i >= 0 {
			root = root[:i]
		}
		for _, member := range input.Members {
			if root != "" && root != member.Name {
				continue
			}
			target, _ := model.Shape(member.Target)
			if validation.Constraint != "required" && (member.HTTPQuery != "" || member.HTTPHeader != "") {
				switch target.Kind {
				case "byte", "short", "integer", "long", "intEnum":
					binding := member.HTTPQuery
					if binding == "" {
						binding = member.HTTPHeader
					}
					message := "Provided " + binding + " not an integer or within integer range"
					if binding == "partNumber" {
						message = "Part number must be an integer between 1 and 10000, inclusive"
					}
					return argumentError(binding, validation.HTTPValue, message)
				}
			}
			if member.HTTPLabel || member.HostLabel || member.HTTPQuery != "" || member.HTTPHeader != "" || member.HTTPQueryParams || member.HTTPPrefixHeadersSet {
				continue
			}
			// XML document/schema failures differ from invalid labels, query
			// values and raw blob/string payloads. Bindings come from Smithy.
			if !member.HTTPPayload || target.Kind == "structure" || target.Kind == "list" || target.Kind == "map" {
				return failure("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema", 400)
			}
		}
	}
	return failure("InvalidRequest", err.Error(), 400)
}

type requestHostKey struct{}

func (s *Service) dispatch(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	fn, ok := s.operations[string(decoded.Operation.Name)]
	// TODO: Comeback complete remaining notification producers, AP families/VPC transport, region routing and full audit projections.
	if !ok {
		return nil, unsupported("The requested S3 operation is not implemented.")
	}
	return fn(awsapi.WithDecodedRequest(ctx, decoded), decoded.Input)
}

// ExecuteCommand uses the same admitted operation and transaction as HTTP,
// returning its generated output without transport-only response metadata.
func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	payment := &requestPayment{payer: commandRequestPayer(decoded.Input)}
	ctx = context.WithValue(ctx, requestPaymentKey{}, payment)
	out, wire := s.dispatch(ctx, decoded)
	if wire != nil {
		return nil, wire
	}
	if native, ok := out.(interface{ modeledOutput() any }); ok {
		out = native.modeledOutput()
	}
	if payment.charged {
		setCommandRequestCharged(out)
	}
	return out, wire
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("s3")
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTXMLError(w, r, &model, failure("InternalError", "Missing generated request.", 500))
		return
	}
	if _, ok := s.operations[string(decoded.Operation.Name)]; !ok {
		_, wire := s.dispatch(r.Context(), decoded)
		awswire.RESTXMLError(w, r, &model, wire)
		return
	}
	if wire := customerTransportError(r); wire != nil {
		if err := s.RecordRequestError(r.Context(), decoded, wire); err != nil {
			wire = wireError(err)
		}
		awswire.RESTXMLError(w, r, &model, wire)
		return
	}
	ctx := context.WithValue(r.Context(), requestHostKey{}, r.Host)
	payment := &requestPayment{payer: r.Header.Get("x-amz-request-payer")}
	ctx = context.WithValue(ctx, requestPaymentKey{}, payment)
	out, wire := s.dispatch(ctx, decoded)
	if payment.charged {
		w.Header().Set("x-amz-request-charged", "requester")
	}
	if native, ok := out.(interface{ responseWithHeaders(http.Header) any }); ok {
		out = native.responseWithHeaders(w.Header())
	}
	if got, ok := out.(*api.HeadBucketOutput); ok && got.BucketRegion != nil {
		w.Header().Set("x-amz-bucket-region", value(got.BucketRegion))
	}
	// Marker failures retain the generated response's version headers.
	if wire != nil {
		var marker *api.DeleteMarker
		var version *api.ObjectVersionId
		var modified *api.LastModified
		switch got := out.(type) {
		case *api.GetObjectOutput:
			marker, version, modified = got.DeleteMarker, got.VersionId, got.LastModified
		case *api.HeadObjectOutput:
			marker, version, modified = got.DeleteMarker, got.VersionId, got.LastModified
		}
		if marker != nil && bool(*marker) {
			w.Header().Set("x-amz-delete-marker", "true")
			w.Header().Set("x-amz-version-id", value(version))
			if wire.StatusCode == http.StatusMethodNotAllowed && modified != nil {
				w.Header().Set("Last-Modified", modified.UTC().Format(http.TimeFormat))
			}
		}
	}
	if wire != nil && wire.StatusCode == 304 {
		w.Header().Set("x-amz-request-id", awsctx.FromContext(r.Context()).RequestID)
		w.Header().Set("x-amz-id-2", awswire.S3HostID(awsctx.FromContext(r.Context()).RequestID))
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if wire != nil {
		awswire.RESTXMLError(w, r, &model, wire)
		return
	}
	var response awsapi.HTTPResponse
	if prepared, ok := out.(interface{ encodedResponse() awsapi.HTTPResponse }); ok {
		response = prepared.encodedResponse()
	} else {
		var err error
		response, err = awsapi.EncodeHTTPResponse(model, decoded.Operation, out)
		if err != nil {
			awswire.RESTXMLError(w, r, &model, failure("InternalError", "Unable to encode S3 response.", 500))
			return
		}
	}
	for k, v := range response.Header {
		w.Header()[k] = v
	}
	w.Header().Set("x-amz-request-id", awsctx.FromContext(r.Context()).RequestID)
	w.Header().Set("x-amz-id-2", awswire.S3HostID(awsctx.FromContext(r.Context()).RequestID))
	if got, ok := out.(*api.GetObjectOutput); ok && got.ContentRange != nil {
		response.StatusCode = 206
	}
	if got, ok := out.(*api.HeadObjectOutput); ok && got.ContentRange != nil {
		response.StatusCode = 206
	}
	w.WriteHeader(response.StatusCode)
	if r.Method != "HEAD" {
		_, _ = w.Write(response.Body)
	}
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func noSuchKey(key string) *awswire.Error {
	wire := failure("NoSuchKey", "The specified key does not exist.", 404)
	wire.Key = key
	return wire
}
func malformedXML() *awswire.Error {
	return failure("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema", 400)
}
func unsupported(message string) *awswire.Error { return failure("NotImplemented", message, 501) }
func invalid(message string) *awswire.Error     { return failure("InvalidArgument", message, 400) }
func argumentError(name, value, message string) *awswire.Error {
	wire := invalid(message)
	wire.ArgumentName, wire.ArgumentValue = name, new(value)
	return wire
}
func denied() *awswire.Error { return failure("AccessDenied", "Access Denied", 403) }
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		return wire
	}
	return failure("InternalError", "An internal error occurred.", 500)
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
