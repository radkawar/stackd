package awscatalog

import (
	"net/http"
	"net/url"
	"testing"
)

func TestHTTPRouteSpecificityAndEscapedLabels(t *testing.T) {
	service := newService(ServiceInfo{}, []Operation{
		{Name: "Fallback", HTTPMethod: "GET", HTTPURI: "/{rest+}"},
		{Name: "Item", HTTPMethod: "GET", HTTPURI: "/items/{name}"},
		{Name: "List", HTTPMethod: "GET", HTTPURI: "/items"},
		{Name: "Find", HTTPMethod: "GET", HTTPURI: "/items?find=Version"},
		{Name: "Empty", HTTPMethod: "GET", HTTPURI: "/empty?value="},
		{Name: "Present", HTTPMethod: "GET", HTTPURI: "/present?value"},
		{Name: "Suffix", HTTPMethod: "GET", HTTPURI: "/prefix/{rest+}/suffix"},
	}, nil)
	for _, fixture := range []struct {
		uri          string
		operation    OperationName
		label, value string
	}{
		{"/items/arn%3Aaws%3Alambda%3Aus-east-1%3A123456789012%3Afunction%3Ademo", "Item", "name", "arn:aws:lambda:us-east-1:123456789012:function:demo"},
		{"/items/a%2Fb%252Fc/", "Item", "name", "a/b%2Fc"},
		{"/items?find=Version&other=ignored", "Find", "", ""},
		{"/items?find=Other", "List", "", ""},
		{"/items/one?find=Version", "Item", "name", "one"},
		{"/empty?value=nonempty", "Fallback", "rest", "empty"},
		{"/empty?value=", "Empty", "", ""},
		{"/present?value=anything", "Present", "", ""},
		{"/prefix/a/suffix/b/suffix", "Suffix", "rest", "a/suffix/b"},
	} {
		t.Run(fixture.uri, func(t *testing.T) {
			uri, err := url.Parse(fixture.uri)
			if err != nil {
				t.Fatal(err)
			}
			op, labels, ok := service.MatchHTTPOperation("GET", uri.EscapedPath(), uri.Query(), nil)
			if !ok || op.Name != fixture.operation || labels[fixture.label] != fixture.value {
				t.Fatalf("route = %s, labels = %v, matched = %v", op.Name, labels, ok)
			}
		})
	}
	if _, _, ok := service.MatchHTTPOperation("DELETE", "/items/one", nil, nil); ok {
		t.Fatal("matched an unmodeled HTTP method")
	}
}

func TestS3HTTPConfigurationRouteSelectors(t *testing.T) {
	service, ok := LookupService("s3")
	if !ok {
		t.Fatal("S3 model not found")
	}
	for _, fixture := range []struct {
		method    string
		uri       string
		operation OperationName
	}{
		{"DELETE", "/bucket?intelligent-tiering", S3OpDeleteBucketIntelligentTieringConfiguration},
		{"DELETE", "/bucket?intelligent-tiering&id=", S3OpDeleteBucketIntelligentTieringConfiguration},
		{"PUT", "/bucket?intelligent-tiering", S3OpPutBucketIntelligentTieringConfiguration},
		{"PUT", "/bucket?intelligent-tiering&id=", S3OpPutBucketIntelligentTieringConfiguration},
		{"GET", "/bucket?intelligent-tiering", S3OpListBucketIntelligentTieringConfigurations},
		{"GET", "/bucket?intelligent-tiering&id=", S3OpListBucketIntelligentTieringConfigurations},
		{"GET", "/bucket?intelligent-tiering&id=archive", S3OpGetBucketIntelligentTieringConfiguration},
		{"GET", "/bucket?intelligent-tiering&id=&x-id=GetBucketIntelligentTieringConfiguration", S3OpListBucketIntelligentTieringConfigurations},
		{"GET", "/bucket?intelligent-tiering&id=archive&x-id=ListBucketIntelligentTieringConfigurations", S3OpGetBucketIntelligentTieringConfiguration},
		{"DELETE", "/bucket?inventory", S3OpDeleteBucketInventoryConfiguration},
		{"PUT", "/bucket?analytics&id=", S3OpPutBucketAnalyticsConfiguration},
		{"GET", "/bucket?metrics&id=", S3OpListBucketMetricsConfigurations},
		{"DELETE", "/bucket", S3OpDeleteBucket},
		{"PUT", "/bucket", S3OpCreateBucket},
	} {
		t.Run(fixture.method+" "+fixture.uri, func(t *testing.T) {
			uri, err := url.Parse(fixture.uri)
			if err != nil {
				t.Fatal(err)
			}
			op, _, ok := service.MatchHTTPOperation(fixture.method, uri.EscapedPath(), uri.Query(), nil)
			if !ok || op.Name != fixture.operation {
				t.Fatalf("route = %s, matched = %v; want %s", op.Name, ok, fixture.operation)
			}
		})
	}
}

func TestS3HTTPObjectRouteSelectors(t *testing.T) {
	service, ok := LookupService("s3")
	if !ok {
		t.Fatal("S3 model not found")
	}
	for _, fixture := range []struct {
		method     string
		uri        string
		copySource string
		operation  OperationName
	}{
		{"GET", "/bucket/key?uploadId=upload", "", S3OpListParts},
		{"GET", "/bucket/key?uploadId=", "", S3OpGetObject},
		{"PUT", "/bucket/key", "", S3OpPutObject},
		{"PUT", "/bucket/key", "/source/key", S3OpCopyObject},
		{"PUT", "/bucket/key?uploadId=upload&partNumber=1", "", S3OpUploadPart},
		{"PUT", "/bucket/key?uploadId=upload&partNumber=1", "/source/key", S3OpUploadPartCopy},
		{"DELETE", "/bucket/key?uploadId=upload", "", S3OpAbortMultipartUpload},
		{"POST", "/bucket/key?uploadId=upload", "", S3OpCompleteMultipartUpload},
		{"POST", "/bucket/key?uploads", "", S3OpCreateMultipartUpload},
		{"GET", "/bucket?uploads", "", S3OpListMultipartUploads},
		{"GET", "/bucket?versions", "", S3OpListObjectVersions},
		{"GET", "/bucket/key?versionId=version", "", S3OpGetObject},
		{"GET", "/bucket/key?attributes&uploadId=upload", "", S3OpGetObjectAttributes},
		{"PUT", "/bucket/key?tagging&uploadId=upload&partNumber=1", "/source/key", S3OpPutObjectTagging},
		{"DELETE", "/bucket/key?annotation", "", S3OpDeleteObjectAnnotation},
	} {
		t.Run(fixture.method+" "+fixture.uri+" "+fixture.copySource, func(t *testing.T) {
			uri, err := url.Parse(fixture.uri)
			if err != nil {
				t.Fatal(err)
			}
			var headers http.Header
			if fixture.copySource != "" {
				headers = http.Header{"X-Amz-Copy-Source": {fixture.copySource}}
			}
			op, _, ok := service.MatchHTTPOperation(fixture.method, uri.EscapedPath(), uri.Query(), headers)
			if !ok || op.Name != fixture.operation {
				t.Fatalf("route = %s, matched = %v; want %s", op.Name, ok, fixture.operation)
			}
		})
	}
}
