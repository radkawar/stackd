package iam_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"stackd/internal/services/iam"
)

func TestIAMServerCertificatesLifecycleTLS(t *testing.T) {
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	key := certificateTestECKey(t)
	body, cert := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	private := certificateTestPrivate(t, key)
	created, err := root.UploadServerCertificate(ctx, &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String("MyCert"), Path: aws.String("/tls/"), CertificateBody: aws.String(body), PrivateKey: aws.String(private), Tags: []types.Tag{{Key: aws.String("Team"), Value: aws.String("one")}, {Key: aws.String("team"), Value: aws.String("two")}}})
	if err != nil {
		t.Fatal(err)
	}
	metadata := created.ServerCertificateMetadata
	arn := aws.ToString(metadata.Arn)
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	if arn != "arn:aws:iam::123456789012:server-certificate/tls/MyCert" || !metadata.Expiration.Equal(cert.NotAfter) || len(aws.ToString(metadata.ServerCertificateId)) != 21 || len(created.Tags) != 2 {
		t.Fatal("server metadata does not match actual material")
	}
	pair, err := s.ServerCertificateForTLS(ctx, scope, arn)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "authenticated TLS") }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	trust := x509.NewCertPool()
	trust.AddCert(cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trust, ServerName: "stackd.test", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport}
	response, err := httpClient.Get(server.URL)
	if err != nil {
		t.Fatal("stored material cannot perform TLS handshake", err)
	}
	response.Body.Close()
	get, err := root.GetServerCertificate(ctx, &sdkiam.GetServerCertificateInput{ServerCertificateName: aws.String("mycert")})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(get.ServerCertificate.CertificateBody) != strings.TrimSpace(body) || get.ServerCertificate.CertificateChain != nil || len(get.ServerCertificate.Tags) != 2 {
		t.Fatal("incorrect public certificate response")
	}
	_, err = root.UploadServerCertificate(ctx, &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String("MYCERT"), CertificateBody: aws.String(body), PrivateKey: aws.String(private)})
	requireCode(t, err, "EntityAlreadyExists")
	_, err = root.UpdateServerCertificate(ctx, &sdkiam.UpdateServerCertificateInput{ServerCertificateName: aws.String("MyCert"), NewServerCertificateName: aws.String("Renamed"), NewPath: aws.String("/other/")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.GetServerCertificate(ctx, &sdkiam.GetServerCertificateInput{ServerCertificateName: aws.String("MyCert")})
	requireCode(t, err, "NoSuchEntity")
	renamed, err := root.GetServerCertificate(ctx, &sdkiam.GetServerCertificateInput{ServerCertificateName: aws.String("renamed")})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(renamed.ServerCertificate.ServerCertificateMetadata.ServerCertificateId) != aws.ToString(metadata.ServerCertificateId) || len(renamed.ServerCertificate.Tags) != 2 {
		t.Fatal("rename must preserve ID and tags")
	}
	if _, err := s.ServerCertificateForTLS(ctx, scope, arn); !errors.Is(err, iam.ErrInvalidServerCertificate) {
		t.Fatal("old ARN still resolves after rename")
	}
	arn = aws.ToString(renamed.ServerCertificate.ServerCertificateMetadata.Arn)
	if _, err := s.ServerCertificateForTLS(ctx, scope, arn); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ServerCertificateForTLS(ctx, iam.Scope{Partition: "aws-cn", AccountID: scope.AccountID}, arn); !errors.Is(err, iam.ErrInvalidServerCertificate) {
		t.Fatal("partition isolation violated")
	}
	_, err = root.DeleteServerCertificate(ctx, &sdkiam.DeleteServerCertificateInput{ServerCertificateName: aws.String("Renamed")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ServerCertificateForTLS(ctx, scope, arn); !errors.Is(err, iam.ErrInvalidServerCertificate) {
		t.Fatal("deleted certificate still resolves")
	}
	list, err := root.ListServerCertificates(ctx, &sdkiam.ListServerCertificatesInput{})
	if err != nil || len(list.ServerCertificateMetadataList) != 0 {
		t.Fatalf("empty list: %+v %v", list, err)
	}
}

func TestIAMServerCertificateCryptoValidation(t *testing.T) {
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	key := certificateTestECKey(t)
	otherKey := certificateTestECKey(t)
	ca, caCert := certificateTestMaterial(t, key, nil, nil, true, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	leaf, _ := certificateTestMaterial(t, otherKey, caCert, key, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	expired, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	future, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
	for _, test := range []struct{ name, body, private, chain, code string }{
		{"malformed", "bad", certificateTestPrivate(t, key), "", "MalformedCertificate"},
		{"mismatch", ca, certificateTestPrivate(t, otherKey), "", "KeyPairMismatch"},
		{"private", ca, "not private", "", "MalformedCertificate"},
		{"expired", expired, certificateTestPrivate(t, key), "", "MalformedCertificate"},
		{"future", future, certificateTestPrivate(t, key), "", "MalformedCertificate"},
		{"chain-malformed", leaf, certificateTestPrivate(t, otherKey), "bad", "MalformedCertificate"},
		{"chain-leaf", leaf, certificateTestPrivate(t, otherKey), leaf + ca, "MalformedCertificate"},
		{"chain-valid", leaf, certificateTestPrivate(t, otherKey), ca, ""},
		{"chain-duplicate-root", leaf, certificateTestPrivate(t, otherKey), ca + ca, ""},
		{"chain-missing", leaf, certificateTestPrivate(t, otherKey), "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String(test.name), CertificateBody: aws.String(test.body), PrivateKey: aws.String(test.private)}
			if test.chain != "" {
				input.CertificateChain = aws.String(test.chain)
			}
			_, err := root.UploadServerCertificate(ctx, input)
			if test.code != "" {
				requireCode(t, err, test.code)
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	list, err := root.ListServerCertificates(ctx, &sdkiam.ListServerCertificatesInput{})
	if err != nil || len(list.ServerCertificateMetadataList) != 3 {
		t.Fatalf("failed validation left state: %+v %v", list, err)
	}
}

func TestIAMServerCertificateTagsAndPagination(t *testing.T) {
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	key := certificateTestECKey(t)
	body, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	private := certificateTestPrivate(t, key)
	for _, name := range []string{"a", "b", "c"} {
		_, err := root.UploadServerCertificate(ctx, &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String(name), Path: aws.String("/test/"), CertificateBody: aws.String(body), PrivateKey: aws.String(private)})
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := root.TagServerCertificate(ctx, &sdkiam.TagServerCertificateInput{ServerCertificateName: aws.String("a"), Tags: []types.Tag{}})
	requireCode(t, err, "InvalidInput")
	_, err = root.UntagServerCertificate(ctx, &sdkiam.UntagServerCertificateInput{ServerCertificateName: aws.String("a"), TagKeys: []string{}})
	requireCode(t, err, "InvalidInput")
	_, err = root.TagServerCertificate(ctx, &sdkiam.TagServerCertificateInput{ServerCertificateName: aws.String("a"), Tags: []types.Tag{{Key: aws.String("aws:reserved"), Value: aws.String("value")}}})
	requireCode(t, err, "InvalidInput")
	_, err = root.TagServerCertificate(ctx, &sdkiam.TagServerCertificateInput{ServerCertificateName: aws.String("a"), Tags: []types.Tag{{Key: aws.String("Team"), Value: aws.String("aws:value")}, {Key: aws.String("team"), Value: aws.String("two")}}})
	if err != nil {
		t.Fatal(err)
	}
	tags, err := root.ListServerCertificateTags(ctx, &sdkiam.ListServerCertificateTagsInput{ServerCertificateName: aws.String("a"), MaxItems: aws.Int32(1)})
	if err != nil || len(tags.Tags) != 1 || !tags.IsTruncated {
		t.Fatalf("tag page: %+v %v", tags, err)
	}
	_, err = root.UntagServerCertificate(ctx, &sdkiam.UntagServerCertificateInput{ServerCertificateName: aws.String("a"), TagKeys: []string{"Team"}})
	if err != nil {
		t.Fatal(err)
	}
	tags, err = root.ListServerCertificateTags(ctx, &sdkiam.ListServerCertificateTagsInput{ServerCertificateName: aws.String("a")})
	if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].Key) != "team" {
		t.Fatalf("case sensitive tags: %+v %v", tags, err)
	}
	_, err = root.UpdateServerCertificate(ctx, &sdkiam.UpdateServerCertificateInput{ServerCertificateName: aws.String("a")})
	if err != nil {
		t.Fatal(err)
	}
	tags, err = root.ListServerCertificateTags(ctx, &sdkiam.ListServerCertificateTagsInput{ServerCertificateName: aws.String("a")})
	if err != nil || len(tags.Tags) != 0 {
		t.Fatalf("AWS empty update clears tags: %+v %v", tags, err)
	}
	_, err = root.TagServerCertificate(ctx, &sdkiam.TagServerCertificateInput{ServerCertificateName: aws.String("a"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("value")}}})
	requireCode(t, err, "InvalidInput")
	_, err = root.UntagServerCertificate(ctx, &sdkiam.UntagServerCertificateInput{ServerCertificateName: aws.String("a"), TagKeys: []string{"team"}})
	requireCode(t, err, "InvalidInput")
	_, err = root.UpdateServerCertificate(ctx, &sdkiam.UpdateServerCertificateInput{ServerCertificateName: aws.String("a"), NewServerCertificateName: aws.String("b")})
	requireCode(t, err, "EntityAlreadyExists")
	page, err := root.ListServerCertificates(ctx, &sdkiam.ListServerCertificatesInput{PathPrefix: aws.String("/test/"), MaxItems: aws.Int32(2)})
	if err != nil || len(page.ServerCertificateMetadataList) != 2 || !page.IsTruncated {
		t.Fatalf("certificate page: %+v %v", page, err)
	}
	last, err := root.ListServerCertificates(ctx, &sdkiam.ListServerCertificatesInput{PathPrefix: aws.String("/test/"), MaxItems: aws.Int32(2), Marker: page.Marker})
	if err != nil || len(last.ServerCertificateMetadataList) != 1 || last.IsTruncated {
		t.Fatalf("last certificate page: %+v %v", last, err)
	}
}

func TestIAMServerCertificateQuotaAndExpiry(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	s := iam.NewWithRepository(nil, repository)
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	key := certificateTestECKey(t)
	body, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	private := certificateTestPrivate(t, key)
	for i := 0; i < 21; i++ {
		name := fmt.Sprintf("cert-%02d", i)
		_, err := root.UploadServerCertificate(ctx, &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String(name), CertificateBody: aws.String(body), PrivateKey: aws.String(private)})
		if i == 20 {
			requireCode(t, err, "LimitExceeded")
		} else if err != nil {
			t.Fatal(err)
		}
	}
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	var arn string
	if err := repository.Update(ctx, func(tx iam.WriteTx) error {
		r, err := tx.ServerCertificate(scope, "cert-00")
		if err != nil {
			return err
		}
		arn = r.ARN
		r.Expiration = time.Now().Add(-time.Second)
		return tx.PutServerCertificate(scope, r)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ServerCertificateForTLS(ctx, scope, arn); !errors.Is(err, iam.ErrInvalidServerCertificate) {
		t.Fatal("expired deployment certificate accepted")
	}
}
