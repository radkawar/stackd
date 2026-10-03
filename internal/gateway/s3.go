package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"stackd/iam/policy"
	"stackd/internal/awscatalog"
	"stackd/internal/awschecksum"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Unsigned S3 requests still pass through the service's resource authorization.
// The caller has already excluded every form of signing material; malformed
// signatures never reach this path. Root Query requests remain owned by STS.
func (g *Gateway) serveUnsignedS3(w http.ResponseWriter, r *http.Request) bool {
	service := g.s3Service(r)
	if service == nil {
		return false
	}
	metadata := awsctx.FromContext(r.Context())
	metadata.AccountID = policy.AnonymousAccountID
	metadata.Region = g.config.UnsignedRegion
	metadata.Partition = awscatalog.RegionPartition(metadata.Region)
	BindRequestTransport(r, &metadata)
	r = r.WithContext(awsctx.WithMetadata(r.Context(), metadata))
	if observer, ok := service.Provider.(httpObserver); ok {
		var finish func(*http.Request)
		w, r, finish = observer.ObserveHTTP(w, r)
		defer func() { finish(r) }()
	}
	if g.serveS3CORS(w, r, service, metadata.Region) {
		return true
	}
	g.serveOperation(w, r, service, func(failure *awswire.Error) {
		awswire.RESTXMLError(w, r, service.Model, failure)
	})
	return true
}

// CORS is a browser permission check, not object authentication. Its source
// owns matching and response headers, including headers on later auth errors.
type s3CORSProvider interface {
	ServeCORS(http.ResponseWriter, *http.Request, string) bool
}

// s3ControlAccount recognizes account-scoped AWS control endpoints, not S3
// virtual-hosted buckets. Keep the literal account even when it is malformed:
// generated input validation and the provider own account errors.
func s3ControlAccount(host string) (string, bool) {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	account, endpoint, ok := strings.Cut(host, ".s3-control.")
	if !ok || account == "" || strings.Contains(account, ".") {
		return "", false
	}
	region, suffix, ok := strings.Cut(strings.TrimPrefix(endpoint, "dualstack."), ".")
	if !ok || region == "" || (suffix != "amazonaws.com" && suffix != "amazonaws.com.cn") {
		return "", false
	}
	return account, true
}

// A custom endpoint has no AWS hostname discriminator. Its account header
// selects Control only when the generated model also matches the HTTP route.
func (g *Gateway) s3ControlRequest(r *http.Request) bool {
	if _, ok := s3ControlAccount(r.Host); ok {
		return true
	}
	accountHeader := len(r.Header.Values("X-Amz-Account-Id")) != 0
	method := r.Method
	if method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		method = r.Header.Get("Access-Control-Request-Method")
		for _, names := range r.Header.Values("Access-Control-Request-Headers") {
			for name := range strings.SplitSeq(names, ",") {
				accountHeader = accountHeader || strings.EqualFold(strings.TrimSpace(name), "x-amz-account-id")
			}
		}
	}
	if !accountHeader {
		return false
	}
	for i := range g.services {
		service := &g.services[i]
		if service.Name == "s3control" && service.SigningName == "s3" && service.Protocol == RestXML {
			_, _, ok := service.Model.MatchHTTPOperation(method, r.URL.EscapedPath(), r.URL.Query(), r.Header)
			return ok
		}
	}
	return false
}

func (g *Gateway) s3Service(r *http.Request) *Service {
	if g.s3ControlRequest(r) {
		return nil
	}
	if len(r.Header.Values("X-Amz-Target")) != 0 {
		return nil
	}
	if S3RequestPath(r) == "/" && (r.Method == http.MethodPost || r.URL.Query().Has("Action")) {
		return nil
	}
	for i := range g.services {
		service := &g.services[i]
		if service.Name == "s3" && service.SigningName == "s3" && service.Protocol == RestXML {
			return service
		}
	}
	return nil
}

func (g *Gateway) serveS3CORS(w http.ResponseWriter, r *http.Request, service *Service, region string) bool {
	if r.Method != http.MethodOptions && len(r.Header.Values("Origin")) == 0 {
		return false
	}
	if len(r.Header.Values("X-Amz-Target")) != 0 {
		return false
	}
	if service == nil {
		service = g.s3Service(r)
	}
	if service == nil || service.Name != "s3" {
		return false
	}
	provider, ok := service.Provider.(s3CORSProvider)
	if !ok {
		return false
	}
	bucket, _, _ := strings.Cut(strings.TrimPrefix(S3RequestPath(r), "/"), "/")
	bucket, err := url.PathUnescape(bucket)
	if err != nil {
		return false
	}
	metadata := awsctx.FromContext(r.Context())
	metadata.AccountID = policy.AnonymousAccountID
	if awscatalog.RegionPartition(region) == "" {
		region = g.config.UnsignedRegion
	}
	metadata.Region, metadata.Partition = region, awscatalog.RegionPartition(region)
	BindRequestTransport(r, &metadata)
	return provider.ServeCORS(w, r.WithContext(awsctx.WithMetadata(r.Context(), metadata)), bucket)
}

func validateS3Authentication(r *http.Request) *awswire.Error {
	if authorization := r.Header.Get("Authorization"); authorization != "" {
		if strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 ") && r.Header.Get("X-Amz-Content-Sha256") == "" {
			return &awswire.Error{Code: "InvalidRequest", Message: "Missing required header for this request: x-amz-content-sha256", StatusCode: 400}
		}
		return nil
	}
	query := r.URL.Query()
	for _, name := range []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Signature", "X-Amz-Date", "X-Amz-SignedHeaders", "X-Amz-Expires"} {
		if query.Get(name) == "" {
			return &awswire.Error{Code: "AuthorizationQueryParametersError", Message: "Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.", StatusCode: 400}
		}
	}
	return nil
}

// S3RequestPath resolves the escaped route without changing the original host
// or escaped path used by signature verification.
func S3RequestPath(r *http.Request) string {
	if _, control := s3ControlAccount(r.Host); control {
		return r.URL.EscapedPath()
	}
	host := r.Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	bucket := s3AccessPointBucket(host)
	if bucket == "" {
		if before, _, ok := strings.Cut(host, ".s3."); ok {
			bucket = before
		} else if before, _, ok := strings.Cut(host, ".s3-"); ok {
			bucket = before
		} else if strings.HasSuffix(host, ".localhost") {
			bucket = strings.TrimSuffix(host, ".localhost")
		}
	}
	path := r.URL.EscapedPath()
	if bucket != "" {
		return "/" + url.PathEscape(bucket) + path
	}
	return path
}

// Access-point hosts bind the model's Bucket label to its scoped ARN. The
// original host and escaped object path remain untouched for authentication.
func s3AccessPointBucket(host string) string {
	name, endpoint, ok := strings.Cut(host, ".s3-accesspoint.")
	if !ok {
		name, endpoint, ok = strings.Cut(host, ".s3-accesspoint-fips.")
	}
	if !ok {
		return ""
	}
	endpoint = strings.TrimPrefix(endpoint, "dualstack.")
	region, _, ok := strings.Cut(endpoint, ".")
	partition := awscatalog.RegionPartition(region)
	separator := strings.LastIndexByte(name, '-')
	if !ok || partition == "" || separator < 1 {
		return ""
	}
	return "arn:" + partition + ":s3:" + region + ":" + name[separator+1:] + ":accesspoint/" + name[:separator]
}

// S3 accepts these fields as either headers or query parameters, never both.
// Other x-amz query fields are not generic header aliases: native S3 ignores a
// query-only ChecksumMode even when an SDK presigner places it there.
func bindS3QueryHeaders(r *http.Request, query url.Values) *awswire.Error {
	for name, values := range query {
		payer := strings.EqualFold(name, "x-amz-request-payer")
		if !payer && !strings.EqualFold(name, "x-amz-expected-bucket-owner") {
			continue
		}
		header := http.CanonicalHeaderKey(name)
		if _, present := r.Header[header]; present {
			if payer {
				return &awswire.Error{
					Code: "InvalidArgument", Message: "Either the payer query string parameter or the x-amz-payer header should be specified, not both", StatusCode: http.StatusBadRequest,
					S3ErrorDetails: awswire.S3ErrorDetails{ArgumentName: "x-amz-request-payer", ArgumentValue: new(r.Header.Get(header))},
				}
			}
			return &awswire.Error{Code: "InvalidBucketOwnerAWSAccountID", Message: "Expected bucket owner must be provided as either a header or parameter, not both", StatusCode: http.StatusBadRequest}
		}
		r.Header[header] = values
	}
	return nil
}

func s3PayloadMarker(value string) bool {
	switch value {
	case "UNSIGNED-PAYLOAD", "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER":
		return true
	}
	return false
}

// decodeS3Payload consumes aws-chunked framing only after the seed request
// signature passed. Chunk and trailer signatures chain to that verified seed.
// Body buffering is still bounded by the gateway's configured request limit.
func decodeS3Payload(r *http.Request, body []byte, marker, timestamp, scope string, key []byte, seed string) *awswire.Error {
	if !strings.HasPrefix(marker, "STREAMING-") {
		return nil
	}
	bad := func(message string) *awswire.Error {
		return &awswire.Error{Code: "InvalidRequest", Message: message, StatusCode: 400}
	}
	badSignature := func() *awswire.Error {
		return &awswire.Error{Code: "SignatureDoesNotMatch", Message: "The chunk or trailer signature does not match.", StatusCode: 403}
	}
	decodedLength, err := strconv.ParseInt(r.Header.Get("X-Amz-Decoded-Content-Length"), 10, 64)
	if err != nil || decodedLength < 0 || decodedLength > int64(len(body)) {
		return bad("Invalid decoded content length.")
	}
	signed := marker != "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	withTrailers := strings.HasSuffix(marker, "-TRAILER")
	remaining := body
	decoded := make([]byte, 0, int(decodedLength))
	previous := seed
	for {
		line, rest, found := bytes.Cut(remaining, []byte("\r\n"))
		if !found {
			return bad("Incomplete aws-chunked header.")
		}
		remaining = rest
		sizeText, extension, hasExtension := strings.Cut(string(line), ";")
		size, parseErr := strconv.ParseUint(sizeText, 16, 64)
		if parseErr != nil || size > uint64(len(remaining)) || size > uint64(decodedLength)-uint64(len(decoded)) {
			return bad("Invalid aws-chunked size.")
		}
		chunk := remaining[:int(size)]
		if signed {
			signature, ok := strings.CutPrefix(extension, "chunk-signature=")
			if !hasExtension || !ok {
				return badSignature()
			}
			actual, decodeErr := hex.DecodeString(signature)
			toSign := strings.Join([]string{"AWS4-HMAC-SHA256-PAYLOAD", timestamp, scope, previous, hashHex(nil), hashHex(chunk)}, "\n")
			expected := hmacSHA256(key, toSign)
			if decodeErr != nil || !hmac.Equal(actual, expected) {
				return badSignature()
			}
			previous = hex.EncodeToString(expected)
		} else if hasExtension {
			return bad("Unexpected unsigned aws-chunked extension.")
		}
		if size == 0 {
			break
		}
		remaining = remaining[int(size):]
		if !bytes.HasPrefix(remaining, []byte("\r\n")) {
			return bad("Incomplete aws-chunked body.")
		}
		remaining = remaining[2:]
		decoded = append(decoded, chunk...)
	}
	if int64(len(decoded)) != decodedLength {
		return bad("Decoded content length does not match the body.")
	}
	declared := map[string]bool{}
	if withTrailers {
		for _, name := range strings.Split(r.Header.Get("X-Amz-Trailer"), ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if !strings.HasPrefix(name, "x-amz-checksum-") || declared[name] {
				return bad("Invalid checksum trailer declaration.")
			}
			declared[name] = true
		}
	}
	trailers := map[string]string{}
	trailerSignature := ""
	for {
		line, rest, found := bytes.Cut(remaining, []byte("\r\n"))
		if !found {
			return bad("Incomplete aws-chunked trailers.")
		}
		remaining = rest
		if len(line) == 0 {
			break
		}
		name, value, found := strings.Cut(string(line), ":")
		name = strings.ToLower(name)
		value = strings.TrimSpace(value)
		if !found || !withTrailers {
			return bad("Invalid aws-chunked trailer.")
		}
		if name == "x-amz-trailer-signature" && signed && trailerSignature == "" {
			trailerSignature = value
			continue
		}
		if !declared[name] || trailers[name] != "" || value == "" || r.Header.Get(name) != "" {
			return bad("Unexpected or duplicate checksum trailer.")
		}
		trailers[name] = value
	}
	if len(remaining) != 0 || len(trailers) != len(declared) {
		return bad("Incomplete or excess aws-chunked data.")
	}
	if signed && withTrailers {
		names := make([]string, 0, len(trailers))
		for name := range trailers {
			names = append(names, name)
		}
		slices.Sort(names)
		var canonical strings.Builder
		for _, name := range names {
			canonical.WriteString(name + ":" + trailers[name] + "\n")
		}
		toSign := strings.Join([]string{"AWS4-HMAC-SHA256-TRAILER", timestamp, scope, previous, hashHex([]byte(canonical.String()))}, "\n")
		actual, decodeErr := hex.DecodeString(trailerSignature)
		if decodeErr != nil || !hmac.Equal(actual, hmacSHA256(key, toSign)) {
			return badSignature()
		}
	}
	for name, value := range trailers {
		r.Header.Set(name, value)
	}
	encodings := []string{}
	for _, encoding := range strings.Split(r.Header.Get("Content-Encoding"), ",") {
		if encoding = strings.TrimSpace(encoding); encoding != "" && !strings.EqualFold(encoding, "aws-chunked") {
			encodings = append(encodings, encoding)
		}
	}
	if len(encodings) == 0 {
		r.Header.Del("Content-Encoding")
	} else {
		r.Header.Set("Content-Encoding", strings.Join(encodings, ","))
	}
	r.ContentLength = decodedLength
	r.Header.Set("Content-Length", strconv.FormatInt(decodedLength, 10))
	r.Body = io.NopCloser(bytes.NewReader(decoded))
	return nil
}

// ValidateS3DocumentChecksum verifies modeled document transfer checksums.
// Object/part payloads retain typed, source-owned checksum admission.
// An assembled-object digest on CompleteMultipartUpload is not a checksum of
// its XML manifest. Call after signature/framing verification, before decoding.
func ValidateS3DocumentChecksum(model *awscatalog.Service, operation awscatalog.Operation, header http.Header, body []byte) *awswire.Error {
	input, _ := model.Shape(operation.Input)
	for _, member := range input.Members {
		if member.HTTPPayload {
			payload, _ := model.Shape(member.Target)
			if payload.Kind == "blob" {
				return nil
			}
		}
	}
	hasChecksum, hasFlexibleChecksum := false, false
	for name, values := range header {
		algorithm := ""
		switch lower := strings.ToLower(name); {
		case lower == "content-md5":
			algorithm = "MD5"
		case operation.RequestChecksumAlgorithmMember != "" && strings.HasPrefix(lower, "x-amz-checksum-") && lower != "x-amz-checksum-algorithm" && lower != "x-amz-checksum-type" && lower != "x-amz-checksum-mode":
			algorithm = strings.ToUpper(strings.TrimPrefix(lower, "x-amz-checksum-"))
			hasFlexibleChecksum = true
		default:
			continue
		}
		hasChecksum = true
		if len(values) != 1 {
			return &awswire.Error{Code: "InvalidRequest", Message: "Duplicate payload checksum.", StatusCode: 400}
		}
		if algorithm == "MD5" {
			decoded, err := base64.StdEncoding.DecodeString(values[0])
			if err != nil || len(decoded) != md5.Size {
				return &awswire.Error{Code: "InvalidDigest", Message: "The Content-MD5 you specified was invalid.", StatusCode: 400, S3ErrorDetails: awswire.S3ErrorDetails{ContentMD5: values[0]}}
			}
		}
		expected, err := awschecksum.Sum(algorithm, body)
		if err != nil {
			return &awswire.Error{Code: "NotImplemented", Message: err.Error(), StatusCode: 501}
		}
		if values[0] != expected {
			failure := &awswire.Error{Code: "BadDigest", Message: "The provided checksum does not match the request body.", StatusCode: 400}
			if algorithm == "MD5" {
				failure.ExpectedDigest, failure.CalculatedDigest = values[0], expected
			}
			return failure
		}
	}
	if operation.RequestChecksumAlgorithmMember != "" && !hasFlexibleChecksum {
		for _, member := range input.Members {
			if member.Name == operation.RequestChecksumAlgorithmMember && len(header.Values(member.HTTPHeader)) > 0 && header.Get("X-Amz-Trailer") == "" {
				return &awswire.Error{Code: "InvalidRequest", Message: "x-amz-sdk-checksum-algorithm specified, but no corresponding x-amz-checksum-* or x-amz-trailer headers were found.", StatusCode: 400}
			}
		}
	}
	if operation.RequestChecksumRequired && len(body) != 0 && !hasChecksum {
		return &awswire.Error{Code: "InvalidRequest", Message: "Missing required header for this request: Content-MD5 OR x-amz-checksum-*", StatusCode: 400}
	}
	return nil
}
