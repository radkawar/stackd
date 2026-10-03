package integrations

import (
	"context"
	"crypto/md5" // RFC 2617 Digest authentication uses MD5.
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/services/sns"
)

// SNSHTTP sends retained native SNS payloads to customer HTTP/S servers. The
// optional client permits operator-owned transport configuration; ordinary TLS
// verification remains enabled. Redirects never forward notifications or secrets.
type SNSHTTP struct{ Client *http.Client }

func (a SNSHTTP) Send(ctx context.Context, endpoint string, message sns.DeliveryMessage) sns.DeliveryResult {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	target, err := url.Parse(endpoint)
	if err != nil || target.Host == "" || target.Scheme != "http" && target.Scheme != "https" {
		return snsDeliveryError(&awswire.Error{Code: "InvalidParameter", Message: "Invalid HTTP subscription endpoint.", StatusCode: 400}, message.CaptureFeedback)
	}
	user := target.User
	target.User = nil
	client := http.Client{Timeout: 15 * time.Second}
	if a.Client != nil {
		client = *a.Client
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	send := func(authorization string) (*http.Response, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(message.Body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("User-Agent", "Amazon Simple Notification Service Agent")
		request.Header.Set("Accept-Encoding", "gzip,deflate")
		contentType := message.ContentType
		if contentType == "" {
			contentType = "text/plain; charset=UTF-8"
		}
		request.Header.Set("Content-Type", contentType)
		request.Header.Set("x-amz-sns-message-type", message.Type)
		request.Header.Set("x-amz-sns-message-id", message.MessageID)
		request.Header.Set("x-amz-sns-topic-arn", message.TopicARN)
		if message.Type == "Notification" {
			request.Header.Set("x-amz-sns-subscription-arn", message.SubscriptionARN)
		}
		if message.Raw {
			request.Header.Set("x-amz-sns-rawdelivery", "true")
		}
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		return client.Do(request)
	}
	response, err := send("")
	if err != nil {
		return snsDeliveryError(&awswire.Error{Code: "RequestTimeout", Message: "HTTP subscription endpoint request failed.", StatusCode: 503}, message.CaptureFeedback)
	}
	if response.StatusCode == http.StatusUnauthorized && user != nil && target.Scheme == "https" {
		challenge := response.Header.Get("WWW-Authenticate")
		authorization := snsHTTPAuthorization(challenge, target.RequestURI(), user)
		if authorization != "" {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			response, err = send(authorization)
			if err != nil {
				return snsDeliveryError(&awswire.Error{Code: "RequestTimeout", Message: "HTTP subscription endpoint authentication request failed.", StatusCode: 503}, message.CaptureFeedback)
			}
		}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	result := sns.DeliveryResult{StatusCode: response.StatusCode}
	if message.CaptureFeedback {
		_, result.ProviderResponse, _ = strings.Cut(response.Status, " ")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		result.Error = &awswire.Error{Code: "HTTPDeliveryFailed", Message: fmt.Sprintf("HTTP endpoint returned status %d.", response.StatusCode), StatusCode: response.StatusCode}
	}
	return result
}

var snsDigestParameter = regexp.MustCompile(`([A-Za-z]+)\s*=\s*(?:"([^"\\]*(?:\\.[^"\\]*)*)"|([^,\s]+))`)

func snsHTTPAuthorization(challenge, uri string, user *url.Userinfo) string {
	password, _ := user.Password()
	if strings.HasPrefix(strings.ToLower(challenge), "basic ") {
		request := &http.Request{Header: make(http.Header)}
		request.SetBasicAuth(user.Username(), password)
		return request.Header.Get("Authorization")
	}
	if !strings.HasPrefix(strings.ToLower(challenge), "digest ") {
		return ""
	}
	fields := map[string]string{}
	for _, part := range snsDigestParameter.FindAllStringSubmatch(challenge[7:], -1) {
		v := part[2]
		if v == "" {
			v = part[3]
		}
		fields[strings.ToLower(part[1])] = v
	}
	if fields["nonce"] == "" {
		return ""
	}
	algorithm := strings.ToLower(fields["algorithm"])
	if algorithm != "" && algorithm != "md5" && algorithm != "md5-sess" {
		return ""
	}
	qop := ""
	if fields["qop"] != "" {
		for _, v := range strings.Split(fields["qop"], ",") {
			if strings.TrimSpace(v) == "auth" {
				qop = "auth"
			}
		}
		if qop == "" {
			return ""
		}
	}
	hash := func(s string) string { sum := md5.Sum([]byte(s)); return hex.EncodeToString(sum[:]) }
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	cnonce := hex.EncodeToString(nonce[:])
	ha1 := hash(user.Username() + ":" + fields["realm"] + ":" + password)
	if algorithm == "md5-sess" {
		ha1 = hash(ha1 + ":" + fields["nonce"] + ":" + cnonce)
	}
	ha2 := hash("POST:" + uri)
	response := hash(ha1 + ":" + fields["nonce"] + ":" + ha2)
	if qop != "" {
		response = hash(ha1 + ":" + fields["nonce"] + ":00000001:" + cnonce + ":auth:" + ha2)
	}
	quote := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
	result := "Digest username=" + quote(user.Username()) + ", realm=" + quote(fields["realm"]) + ", nonce=" + quote(fields["nonce"]) + ", uri=" + quote(uri) + ", response=" + quote(response)
	if algorithm != "" {
		result += ", algorithm=" + fields["algorithm"]
	}
	if fields["opaque"] != "" {
		result += ", opaque=" + quote(fields["opaque"])
	}
	if qop != "" {
		result += ", qop=auth, nc=00000001, cnonce=" + quote(cnonce)
	} else if algorithm == "md5-sess" {
		result += ", cnonce=" + quote(cnonce)
	}
	return result
}
