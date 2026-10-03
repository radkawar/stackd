package stackd_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func snsVerifySignature(t *testing.T, notification map[string]any, endpoint, hostEndpoint string) {
	t.Helper()
	certificateValue, ok := notification["SigningCertURL"]
	if !ok {
		certificateValue = notification["SigningCertUrl"]
	}
	certificateURL, err := url.Parse(fmt.Sprint(certificateValue))
	if err != nil || certificateURL.Scheme+"://"+certificateURL.Host != endpoint || !strings.HasPrefix(certificateURL.Path, "/SimpleNotificationService-") || !strings.HasSuffix(certificateURL.Path, ".pem") || certificateURL.RawQuery != "" || certificateURL.Fragment != "" {
		t.Fatalf("certificate URL is not this instance's advertised SNS endpoint: %v", certificateValue)
	}
	host, err := url.Parse(hostEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	// The advertised origin is container-reachable. Resolve only that origin
	// to its host-side listener, retaining the real URL, Host and certificate
	// route. Never fetch native AWS certificates or accept a foreign origin.
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, host.Host)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, certificateURL.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("advertised certificate HTTP %d: %s, %v", response.StatusCode, body, err)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("SNS endpoint returned no PEM certificate: %s", body)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("SNS signing certificate must contain an RSA public key")
	}
	var canonical strings.Builder
	fields := []string{"Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"}
	if notification["Type"] == "SubscriptionConfirmation" || notification["Type"] == "UnsubscribeConfirmation" {
		fields = []string{"Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"}
	}
	for _, field := range fields {
		// AWS retains Subject:null in Lambda JSON but does not sign null.
		if field == "Subject" && notification[field] == nil {
			continue
		}
		value, ok := notification[field].(string)
		if field == "SubscribeURL" && !ok {
			value, ok = notification["SubscribeUrl"].(string)
		}
		if !ok {
			t.Fatalf("signed field %s is not a string: %v", field, notification[field])
		}
		fmt.Fprintf(&canonical, "%s\n%s\n", field, value)
	}
	signature, err := base64.StdEncoding.DecodeString(fmt.Sprint(notification["Signature"]))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(canonical.String())
	hash := crypto.SHA1
	var digest []byte
	switch notification["SignatureVersion"] {
	case "1":
		sum := sha1.Sum(data)
		digest = sum[:]
	case "2":
		hash = crypto.SHA256
		sum := sha256.Sum256(data)
		digest = sum[:]
	default:
		t.Fatalf("unsupported SNS SignatureVersion: %v", notification["SignatureVersion"])
	}
	if err := rsa.VerifyPKCS1v15(public, hash, digest, signature); err != nil {
		t.Fatalf("SNS notification signature failed advertised certificate verification: %v", err)
	}
}
