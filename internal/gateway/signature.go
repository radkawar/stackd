package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// verifySignature authenticates the actual bytes before protocol decoding.
// Credentials come only from the local resolver; real AWS keys are never resolved.
func verifySignature(r *http.Request, scope credentialScope, credential identity.Credential, now time.Time, unsignedPayload bool) *awswire.Error {
	body, wire := readSignatureBody(r)
	if wire != nil {
		return wire
	}
	return verifySignaturePolicy(r, body, scope, credential, now, unsignedPayload, false)
}

// readSignatureBody consumes the caller-bounded transport before credential
// resolution can spend its read deadline. Verification and body replay share
// the same bytes; no second read or copy is needed during authentication.
func readSignatureBody(r *http.Request) ([]byte, *awswire.Error) {
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, &awswire.Error{Code: "RequestEntityTooLarge", Message: "Unable to read request within body limit", StatusCode: http.StatusRequestEntityTooLarge}
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// verifySignaturePolicy authenticates the already-consumed, caller-bounded body.
// eksToken selects the Kubernetes authenticator's fixed 15-minute token lifetime,
// not the STS URL's ordinary expiry. The signed bytes are never rewritten.
func verifySignaturePolicy(r *http.Request, body []byte, scope credentialScope, credential identity.Credential, now time.Time, unsignedPayload, eksToken bool) *awswire.Error {
	failure := func(message string) *awswire.Error {
		return &awswire.Error{Code: "SignatureDoesNotMatch", Message: message, StatusCode: http.StatusForbidden}
	}
	token := r.Header.Get("X-Amz-Security-Token")
	if r.Header.Get("Authorization") == "" {
		token = r.URL.Query().Get("X-Amz-Security-Token")
	}
	if !hmac.Equal([]byte(token), []byte(credential.SessionToken)) {
		return &awswire.Error{Code: "InvalidClientTokenId", Message: "The security token does not match the local session", StatusCode: http.StatusForbidden}
	}
	parameters := make(map[string]string)
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return failure("Invalid query encoding")
	}
	presigned := r.Header.Get("Authorization") == ""
	var timestamp string
	if presigned {
		if query.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
			return failure("Unsupported signature algorithm")
		}
		for _, key := range []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-SignedHeaders", "X-Amz-Signature", "X-Amz-Date", "X-Amz-Expires"} {
			if len(query[key]) != 1 {
				return failure("Missing or duplicate signature parameter")
			}
		}
		parameters["SignedHeaders"] = query.Get("X-Amz-SignedHeaders")
		parameters["Signature"] = query.Get("X-Amz-Signature")
		timestamp = query.Get("X-Amz-Date")
		query.Del("X-Amz-Signature")
	} else {
		if query.Has("X-Amz-Credential") {
			return failure("Ambiguous authentication")
		}
		for _, part := range strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 "), ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok || value == "" || parameters[key] != "" {
				return failure("Invalid authorization parameters")
			}
			parameters[key] = value
		}
		timestamp = r.Header.Get("X-Amz-Date")
	}
	signedAt, err := time.Parse("20060102T150405Z", timestamp)
	if err != nil || !strings.HasPrefix(timestamp, scope.date) {
		return failure("Invalid signature date")
	}
	validFor := 15 * time.Minute
	if presigned {
		expires, err := strconv.ParseInt(query.Get("X-Amz-Expires"), 10, 64)
		if err != nil || expires < 0 || (expires == 0 && !eksToken) || expires > 604800 {
			return failure("Invalid signature expiry")
		}
		validFor = time.Duration(expires) * time.Second
		if eksToken {
			if scope.service != "sts" || expires > 900 || query.Get("Action") != "GetCallerIdentity" || !slices.Contains(strings.Split(parameters["SignedHeaders"], ";"), "x-k8s-aws-id") {
				return failure("Invalid EKS token signature")
			}
			validFor = 15 * time.Minute
		}
	}
	if signedAt.After(now.Add(15*time.Minute)) || now.After(signedAt.Add(validFor)) {
		return &awswire.Error{Code: "RequestExpired", Message: "Request signature has expired or is not yet valid", StatusCode: http.StatusBadRequest}
	}
	signedHeaders := parameters["SignedHeaders"]
	headerNames := strings.Split(signedHeaders, ";")
	if !slices.IsSorted(headerNames) || !slices.Contains(headerNames, "host") {
		return failure("Invalid signed headers")
	}
	if !presigned && !slices.Contains(headerNames, "x-amz-date") {
		return failure("The request date must be signed")
	}
	if !presigned && token != "" && !slices.Contains(headerNames, "x-amz-security-token") {
		return failure("The security token must be signed")
	}
	if r.Header.Get("X-Amz-Target") != "" && !slices.Contains(headerNames, "x-amz-target") {
		return failure("The operation target must be signed")
	}
	var canonicalHeaders strings.Builder
	for i, name := range headerNames {
		if name == "" || name != strings.ToLower(name) || (i > 0 && headerNames[i-1] == name) {
			return failure("Invalid signed headers")
		}
		values := r.Header.Values(name)
		switch name {
		case "host":
			values = []string{r.Host}
		case "content-length":
			values = []string{strconv.FormatInt(r.ContentLength, 10)}
		}
		// S3 reconstructs signed x-amz headers from presigned query fields.
		// A separately supplied HTTP header cannot replace that signed value.
		if presigned && scope.service == "s3" && strings.HasPrefix(name, "x-amz-") {
			if hoisted, present := query[name]; present {
				values = hoisted
			}
		}
		if len(values) == 0 {
			return failure("A signed header is missing")
		}
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		for j, value := range values {
			if j > 0 {
				canonicalHeaders.WriteByte(',')
			}
			canonicalHeaders.WriteString(strings.Join(strings.Fields(value), " "))
		}
		canonicalHeaders.WriteByte('\n')
	}
	var payloadHash string
	suppliedHash := r.Header.Get("X-Amz-Content-Sha256")
	switch {
	case unsignedPayload && suppliedHash == "UNSIGNED-PAYLOAD":
		payloadHash = suppliedHash
	case scope.service == "s3" && (presigned && suppliedHash == "" || s3PayloadMarker(suppliedHash)):
		payloadHash = suppliedHash
		if payloadHash == "" {
			payloadHash = "UNSIGNED-PAYLOAD"
		}
	default:
		payloadHash = hashHex(body)
	}
	if suppliedHash != "" && suppliedHash != payloadHash {
		return failure("Payload hash does not match request body")
	}
	canonicalPath := r.URL.EscapedPath()
	if canonicalPath == "" {
		canonicalPath = "/"
	}
	// S3 signs the exact escaped object path, without normalization or the
	// additional URI escaping used by the other AWS protocols.
	if scope.service != "s3" {
		canonicalPath = strings.ReplaceAll(awsEscape(canonicalPath), "%2F", "/")
	}
	type queryParameter struct{ name, value string }
	queryParts := make([]queryParameter, 0, len(query))
	querySize := 0
	for name, values := range query {
		escapedName := awsEscape(name)
		for _, value := range values {
			escapedValue := awsEscape(value)
			queryParts = append(queryParts, queryParameter{escapedName, escapedValue})
			querySize += len(escapedName) + len(escapedValue) + 2
		}
	}
	slices.SortFunc(queryParts, func(a, b queryParameter) int {
		if order := strings.Compare(a.name, b.name); order != 0 {
			return order
		}
		return strings.Compare(a.value, b.value)
	})
	var canonicalQuery strings.Builder
	canonicalQuery.Grow(querySize)
	for i, parameter := range queryParts {
		if i != 0 {
			canonicalQuery.WriteByte('&')
		}
		canonicalQuery.WriteString(parameter.name)
		canonicalQuery.WriteByte('=')
		canonicalQuery.WriteString(parameter.value)
	}
	canonical := strings.Join([]string{r.Method, canonicalPath, canonicalQuery.String(), canonicalHeaders.String(), signedHeaders, payloadHash}, "\n")
	scopeString := strings.Join([]string{scope.date, scope.region, scope.service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", timestamp, scopeString, hashHex([]byte(canonical))}, "\n")
	key := hmacSHA256([]byte("AWS4"+credential.SecretAccessKey), scope.date)
	key = hmacSHA256(key, scope.region)
	key = hmacSHA256(key, scope.service)
	key = hmacSHA256(key, "aws4_request")
	expected := hmacSHA256(key, stringToSign)
	actual, err := hex.DecodeString(parameters["Signature"])
	if err != nil || !hmac.Equal(actual, expected) {
		return failure("The calculated signature does not match")
	}
	if scope.service == "s3" {
		if wire := bindS3QueryHeaders(r, query); wire != nil {
			return wire
		}
		return decodeS3Payload(r, body, suppliedHash, timestamp, scopeString, key, parameters["Signature"])
	}
	return nil
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprint(mac, value)
	return mac.Sum(nil)
}

func awsEscape(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }
