package s3

import (
	"net/url"
	"testing"
)

func TestParseCopySourceEncoding(t *testing.T) {
	for _, test := range []struct {
		name, header, bucket, key, version string
		hasVersion                         bool
	}{
		{name: "SDK path", header: "bucket/key%20with%20space", bucket: "bucket", key: "key with space"},
		{name: "SDK literal delimiters", header: "bucket/question%3FversionId%3Dliteral+plus%25percent", bucket: "bucket", key: "question?versionId=literal+plus%percent"},
		{name: "SDK percent text", header: "bucket/literal%253F%252F", bucket: "bucket", key: "literal%3F%2F"},
		{name: "SDK version", header: "/bucket/key%3Fpart?versionId=a%2Bb%25c%3Fd", bucket: "bucket", key: "key?part", version: "a+b%c?d", hasVersion: true},
		{name: "SDK null version", header: "bucket/key?versionId=null", bucket: "bucket", key: "key", version: "null", hasVersion: true},
		{name: "SDK empty version", header: "bucket/key?versionId=", bucket: "bucket", key: "key", hasVersion: true},
		{name: "whole source", header: url.QueryEscape("bucket/key with space+plus%percent"), bucket: "bucket", key: "key with space+plus%percent"},
		{name: "whole source percent text", header: url.QueryEscape("bucket/literal%3F%2F"), bucket: "bucket", key: "literal%3F%2F"},
		{name: "whole source version", header: url.QueryEscape("bucket/key?versionId=sv1_original"), bucket: "bucket", key: "key", version: "sv1_original", hasVersion: true},
		{name: "whole source escaped version", header: url.QueryEscape("bucket/key?versionId=a%2Bb%25c%3Fd"), bucket: "bucket", key: "key", version: "a+b%c?d", hasVersion: true},
		{name: "escaped separator with explicit query", header: "bucket%2Fkey?versionId=a%2Bb%25c%3Fd", bucket: "bucket", key: "key", version: "a+b%c?d", hasVersion: true},
		{name: "access point path", header: "arn:aws:s3:us-east-1:123456789012:accesspoint/source/object/key%3Fpart+plus", bucket: "arn:aws:s3:us-east-1:123456789012:accesspoint/source", key: "key?part+plus"},
		{name: "access point whole source", header: url.QueryEscape("arn:aws:s3:us-east-1:123456789012:accesspoint/source/object/key?versionId=null"), bucket: "arn:aws:s3:us-east-1:123456789012:accesspoint/source", key: "key", version: "null", hasVersion: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, wire := parseCopySource(test.header)
			if wire != nil {
				t.Fatalf("parseCopySource: %v", wire)
			}
			if got.bucket != test.bucket || got.key != test.key || (got.version != nil) != test.hasVersion {
				t.Fatalf("got bucket=%q key=%q version=%v", got.bucket, got.key, got.version)
			}
			if test.hasVersion && string(*got.version) != test.version {
				t.Fatalf("version=%q, want %q", *got.version, test.version)
			}
		})
	}
}

func TestParseCopySourceRejectsInvalidEncodingAndQuery(t *testing.T) {
	for _, header := range []string{
		"bucket/key%zz", "bucket%2Fkey%zz", "bucket/key?versionId=%zz",
		"bucket/key?versionId=one&versionId=two", "bucket/key?other=value",
		url.QueryEscape("bucket/key?versionId=one&versionId=two"), "bucket/", "/key", "bucket",
	} {
		t.Run(header, func(t *testing.T) {
			if _, wire := parseCopySource(header); wire == nil {
				t.Fatal("invalid copy source was accepted")
			}
		})
	}
}
