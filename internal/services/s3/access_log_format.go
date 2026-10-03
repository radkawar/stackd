package s3

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"stackd/iam/policy"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/gateway"
)

// Operation spellings come from delivered native records and AWS's log-format
// and ACL documentation. Unobserved spellings are unavailable, not mechanically
// derived API names.
func accessLogOperation(action string) string {
	switch action {
	case "CopyObject":
		return "REST.COPY.OBJECT"
	case "UploadPartCopy":
		return "REST.COPY.PART"
	case "DeleteBucket":
		return "REST.DELETE.BUCKET"
	case "DeleteBucketPolicy":
		return "REST.DELETE.BUCKETPOLICY"
	case "DeleteBucketCors":
		return "REST.DELETE.CORS"
	case "DeleteBucketEncryption":
		return "REST.DELETE.ENCRYPTION"
	case "DeleteObject":
		return "REST.DELETE.OBJECT"
	case "DeleteObjectTagging":
		return "REST.DELETE.OBJECT_TAGGING"
	case "DeleteBucketOwnershipControls":
		return "REST.DELETE.OWNERSHIP_CONTROLS"
	case "DeletePublicAccessBlock":
		return "REST.DELETE.PUBLIC_ACCESS_BLOCK"
	case "DeleteBucketTagging":
		return "REST.DELETE.TAGGING"
	case "AbortMultipartUpload":
		return "REST.DELETE.UPLOAD"
	case "DeleteBucketWebsite":
		return "REST.DELETE.WEBSITE"
	case "GetBucketAcl", "GetObjectAcl":
		return "REST.GET.ACL"
	case "ListObjects", "ListObjectsV2":
		return "REST.GET.BUCKET"
	case "GetBucketPolicy":
		return "REST.GET.BUCKETPOLICY"
	case "ListObjectVersions":
		return "REST.GET.BUCKETVERSIONS"
	case "GetBucketCors":
		return "REST.GET.CORS"
	case "GetBucketEncryption":
		return "REST.GET.ENCRYPTION"
	case "GetBucketLocation":
		return "REST.GET.LOCATION"
	case "GetBucketLogging":
		return "REST.GET.LOGGING_STATUS"
	case "GetBucketNotificationConfiguration":
		return "REST.GET.NOTIFICATION"
	case "GetObject":
		return "REST.GET.OBJECT"
	case "GetObjectAttributes":
		return "REST.GET.OBJECT_ATTRIBUTES"
	case "GetObjectTagging":
		return "REST.GET.OBJECT_TAGGING"
	case "GetBucketOwnershipControls":
		return "REST.GET.OWNERSHIP_CONTROLS"
	case "GetBucketPolicyStatus":
		return "REST.GET.POLICY_STATUS"
	case "GetPublicAccessBlock":
		return "REST.GET.PUBLIC_ACCESS_BLOCK"
	case "GetBucketRequestPayment":
		return "REST.GET.REQUEST_PAYMENT"
	case "GetBucketTagging":
		return "REST.GET.TAGGING"
	case "ListParts":
		return "REST.GET.UPLOAD"
	case "ListMultipartUploads":
		return "REST.GET.UPLOADS"
	case "GetBucketVersioning":
		return "REST.GET.VERSIONING"
	case "GetBucketWebsite":
		return "REST.GET.WEBSITE"
	case "HeadBucket":
		return "REST.HEAD.BUCKET"
	case "HeadObject":
		return "REST.HEAD.OBJECT"
	case "DeleteObjects":
		return "REST.POST.MULTI_OBJECT_DELETE"
	case "CompleteMultipartUpload":
		return "REST.POST.UPLOAD"
	case "CreateMultipartUpload":
		return "REST.POST.UPLOADS"
	case "PutBucketAcl", "PutObjectAcl":
		return "REST.PUT.ACL"
	case "PutBucketPolicy":
		return "REST.PUT.BUCKETPOLICY"
	case "PutBucketCors":
		return "REST.PUT.CORS"
	case "PutBucketEncryption":
		return "REST.PUT.ENCRYPTION"
	case "PutBucketLogging":
		return "REST.PUT.LOGGING_STATUS"
	case "PutBucketNotificationConfiguration":
		return "REST.PUT.NOTIFICATION"
	case "PutObject":
		return "REST.PUT.OBJECT"
	case "PutObjectTagging":
		return "REST.PUT.OBJECT_TAGGING"
	case "PutBucketOwnershipControls":
		return "REST.PUT.OWNERSHIP_CONTROLS"
	case "UploadPart":
		return "REST.PUT.PART"
	case "PutPublicAccessBlock":
		return "REST.PUT.PUBLIC_ACCESS_BLOCK"
	case "PutBucketRequestPayment":
		return "REST.PUT.REQUEST_PAYMENT"
	case "PutBucketTagging":
		return "REST.PUT.TAGGING"
	case "PutBucketVersioning":
		return "REST.PUT.VERSIONING"
	case "PutBucketWebsite":
		return "REST.PUT.WEBSITE"
	default:
		// TODO: Comeback capture remaining native server-access-log operation spellings.
		return ""
	}
}

// accessLogRecord owns the native field order for HTTP and internal commands.
// Negative measurements mean unavailable, not fabricated network activity.
type accessLogRecord struct {
	owner, bucket, remoteIP, requester, requestID, operation, key, uri                  string
	at                                                                                  time.Time
	status                                                                              int
	errorCode                                                                           string
	aclRequired                                                                         bool
	bytesSent, objectSize, totalMillis, turnaroundMillis                                int64
	referer, userAgent, versionID, hostID, signature, cipher, authentication, host, tls string
	accessPoint                                                                         string
}

func (r accessLogRecord) format() string {
	key := strings.ReplaceAll(url.QueryEscape(url.QueryEscape(r.key)), "%252F", "/")
	bytesSent := "-"
	if r.bytesSent > 0 {
		bytesSent = strconv.FormatInt(r.bytesSent, 10)
	}
	aclRequired := "-"
	if r.aclRequired {
		aclRequired = "Yes"
	}
	uri, referer, userAgent := "-", "-", "-"
	if r.uri != "" {
		uri, referer, userAgent = accessLogQuote(r.uri), accessLogQuote(r.referer), accessLogQuote(r.userAgent)
	}
	fields := [27]string{
		accessLogToken(r.owner), accessLogToken(r.bucket), r.at.UTC().Format("[02/Jan/2006:15:04:05 -0700]"),
		accessLogToken(r.remoteIP), accessLogToken(r.requester), accessLogToken(r.requestID),
		accessLogToken(r.operation), accessLogToken(key), uri,
		accessLogMeasurement(int64(r.status)), accessLogToken(r.errorCode), bytesSent, accessLogMeasurement(r.objectSize),
		accessLogMeasurement(r.totalMillis), accessLogMeasurement(r.turnaroundMillis),
		referer, userAgent, accessLogToken(r.versionID),
		accessLogToken(r.hostID), accessLogToken(r.signature), accessLogToken(r.cipher), accessLogToken(r.authentication),
		accessLogToken(r.host), accessLogToken(r.tls), accessLogToken(r.accessPoint), aclRequired, "-",
	}
	return strings.Join(fields[:], " ") + "\n"
}

// Copy-source records retain the parent transport without inventing a second
// HTTP request, transfer measurement, or turnaround time.
func (r *accessLogRecord) captureTransport(request *http.Request, m awsctx.Metadata) {
	gateway.BindRequestTransport(request, &m)
	r.remoteIP, r.requester, r.requestID = m.SourceIP, accessLogRequester(m), m.RequestID
	r.signature, r.authentication, r.host = m.SignatureVersion, m.AuthenticationMethod, request.Host
	r.cipher, r.tls = accessLogTLS(request)
}

func accessLogMeasurement(value int64) string {
	if value < 0 {
		return "-"
	}
	return strconv.FormatInt(value, 10)
}

// formatAccessLog emits the 27-field general-purpose bucket log format. The
// response observer measures body bytes actually accepted by the writer; object
// size comes only from S3's selected snapshot, never response Content-Length.
func formatAccessLog(o *requestObservation, elapsed time.Duration) string {
	r, w := o.request, o.writer
	owner := canonicalID(o.bucket.Key.Partition, o.bucket.AccountID)
	if o.bucket.ACL != nil && o.bucket.ACL.OwnerID != "" {
		owner = o.bucket.ACL.OwnerID
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	errorCode := w.errorCode
	if status == http.StatusNotModified {
		errorCode = ""
	}
	uri := r.RequestURI
	if uri == "" {
		uri = websiteRawTarget(r)
	}
	turnaround := int64(-1)
	// Native availability is operation-specific, including selected 204 controls
	// and HeadBucket, but not HeadObject or conditional/error replies.
	switch o.operation {
	case "REST.COPY.OBJECT", "REST.COPY.PART", "REST.DELETE.CORS", "REST.DELETE.OWNERSHIP_CONTROLS",
		"REST.DELETE.TAGGING", "REST.DELETE.UPLOAD", "REST.DELETE.WEBSITE", "REST.GET.BUCKET",
		"REST.GET.BUCKETVERSIONS", "REST.GET.CORS", "REST.GET.OBJECT", "REST.GET.OBJECT_ATTRIBUTES",
		"REST.GET.OBJECT_TAGGING", "REST.GET.OWNERSHIP_CONTROLS", "REST.GET.TAGGING", "REST.GET.UPLOAD",
		"REST.GET.UPLOADS", "REST.GET.WEBSITE", "REST.HEAD.BUCKET", "REST.POST.UPLOAD",
		"REST.POST.UPLOADS", "REST.PUT.CORS", "REST.PUT.OBJECT", "REST.PUT.OWNERSHIP_CONTROLS",
		"REST.PUT.PART", "REST.PUT.TAGGING", "REST.PUT.WEBSITE", "WEBSITE.GET.OBJECT":
		if status >= 200 && status < 300 && errorCode == "" && !o.received.IsZero() && !o.firstByte.IsZero() {
			turnaround = o.firstByte.Sub(o.received).Milliseconds()
		}
	}
	record := accessLogRecord{
		owner: owner, bucket: o.bucket.Key.Name, at: o.at,
		operation: o.operation, key: o.key, uri: r.Method + " " + accessLogURI(uri) + " " + r.Proto,
		status: status, errorCode: errorCode, bytesSent: w.bytes, objectSize: o.objectSize,
		totalMillis: elapsed.Milliseconds(), turnaroundMillis: turnaround,
		referer: r.Referer(), userAgent: r.UserAgent(), versionID: accessLogVersion(r),
		hostID:      w.hostID,
		aclRequired: o.call != nil && o.call.aclRequired,
		accessPoint: o.accessPointARN,
	}
	record.captureTransport(r, awsctx.FromContext(r.Context()))
	if w.requestID != "" {
		record.requestID = w.requestID
	}
	return record.format()
}

func accessLogRequester(m awsctx.Metadata) string {
	if m.ServicePrincipal.Name != "" {
		return canonicalID(m.Partition, m.ServicePrincipal.Name)
	}
	if m.AccountID == "" || m.AccountID == policy.AnonymousAccountID || m.PrincipalARN == "" {
		return ""
	}
	if strings.HasSuffix(m.PrincipalARN, ":root") {
		return canonicalID(m.Partition, m.AccountID)
	}
	return m.PrincipalARN
}

// Native logs mask presigned signatures while retaining the spelling and order
// of the remaining request URI, including caller-provided query parameters.
func accessLogURI(uri string) string {
	query := strings.IndexByte(uri, '?')
	if query < 0 {
		return uri
	}
	offset, copied := query+1, 0
	var redacted strings.Builder
	for parameter := range strings.SplitSeq(uri[offset:], "&") {
		key, _, hasValue := strings.Cut(parameter, "=")
		name, _ := url.QueryUnescape(key)
		if hasValue && name == "X-Amz-Signature" {
			if copied == 0 {
				redacted.Grow(len(uri))
			}
			redacted.WriteString(uri[copied : offset+len(key)+1])
			redacted.WriteString("XXXXXXXX")
			copied = offset + len(parameter)
		}
		offset += len(parameter) + 1
	}
	if copied == 0 {
		return uri
	}
	redacted.WriteString(uri[copied:])
	return redacted.String()
}

// Only a modeled request versionId belongs in this field. A newly-created
// version in x-amz-version-id is a response value, not the requested version.
func accessLogVersion(r *http.Request) string {
	if websiteRequest(r) {
		return ""
	}
	query := r.URL.Query()
	version := query.Get("versionId")
	if version == "" {
		return ""
	}
	model, _ := awscatalog.LookupService("s3")
	op, _, ok := model.MatchHTTPOperation(r.Method, gateway.S3RequestPath(r), query, r.Header)
	if !ok {
		return ""
	}
	input, _ := model.Shape(op.Input)
	for _, member := range input.Members {
		if member.HTTPQuery == "versionId" {
			return version
		}
	}
	return ""
}

// Quoted fields retain user-controlled text without allowing it to create
// another record or escape its field. Bare fields escape framing bytes only.
func accessLogQuote(value string) string {
	if value == "" {
		value = "-"
	}
	return strconv.Quote(value)
}

func accessLogToken(value string) string {
	if value == "" {
		return "-"
	}
	const hex = "0123456789ABCDEF"
	var escaped strings.Builder
	for i := range len(value) {
		c := value[i]
		if c > ' ' && c != 0x7f && c != '"' && c != '\\' {
			if escaped.Cap() != 0 {
				escaped.WriteByte(c)
			}
			continue
		}
		if escaped.Cap() == 0 {
			escaped.Grow(len(value) + 2)
			escaped.WriteString(value[:i])
		}
		escaped.WriteByte('%')
		escaped.WriteByte(hex[c>>4])
		escaped.WriteByte(hex[c&15])
	}
	if escaped.Cap() == 0 {
		return value
	}
	return escaped.String()
}

func accessLogTLS(r *http.Request) (cipher, version string) {
	cipher, version = "-", "-"
	if r.TLS == nil {
		return
	}
	switch r.TLS.Version {
	case tls.VersionTLS10:
		version = "TLSv1"
	case tls.VersionTLS11:
		version = "TLSv1.1"
	case tls.VersionTLS12:
		version = "TLSv1.2"
	case tls.VersionTLS13:
		version = "TLSv1.3"
	}
	// S3 uses OpenSSL names for pre-1.3 suites, IANA names for TLS 1.3.
	switch r.TLS.CipherSuite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256:
		cipher = tls.CipherSuiteName(r.TLS.CipherSuite)
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		cipher = "ECDHE-RSA-AES128-GCM-SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		cipher = "ECDHE-RSA-AES256-GCM-SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		cipher = "ECDHE-ECDSA-AES128-GCM-SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		cipher = "ECDHE-ECDSA-AES256-GCM-SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		cipher = "ECDHE-RSA-CHACHA20-POLY1305"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		cipher = "ECDHE-ECDSA-CHACHA20-POLY1305"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		cipher = "ECDHE-RSA-AES128-SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		cipher = "ECDHE-RSA-AES256-SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		cipher = "ECDHE-ECDSA-AES128-SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		cipher = "ECDHE-ECDSA-AES256-SHA"
	}
	return
}
