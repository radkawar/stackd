package awsapi_test

import (
	"bytes"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"stackd/internal/awsapi"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
)

func TestRESTXMLPayloadNamespacesAndAttributes(t *testing.T) {
	labels := map[string]string{"Bucket": "trail-bucket"}
	decoded, err := s3api.DecodeRequest("CreateBucket", awsapi.Request{Labels: labels, Body: []byte(`<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>us-west-2</LocationConstraint></CreateBucketConfiguration>`)})
	if err != nil {
		t.Fatal(err)
	}
	input := decoded.Input.(*s3api.CreateBucketInput)
	if input.CreateBucketConfiguration == nil || input.CreateBucketConfiguration.LocationConstraint == nil || string(*input.CreateBucketConfiguration.LocationConstraint) != "us-west-2" {
		t.Fatalf("XML configuration not bound: %+v", input)
	}
	decoded, err = s3api.DecodeRequest("CreateBucket", awsapi.Request{Labels: labels})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Input.(*s3api.CreateBucketInput).CreateBucketConfiguration != nil {
		t.Fatal("absent optional XML payload became a present configuration")
	}
	decoded, err = s3api.DecodeRequest("PutBucketAcl", awsapi.Request{Labels: labels, Body: []byte(`<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>owner&lt;&amp;</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`)})
	if err != nil {
		t.Fatal(err)
	}
	acl := decoded.Input.(*s3api.PutBucketAclInput).AccessControlPolicy
	if acl == nil || len(acl.Grants) != 1 || acl.Grants[0].Grantee == nil || acl.Grants[0].Grantee.Type == nil || string(*acl.Grants[0].Grantee.Type) != "CanonicalUser" || string(*acl.Grants[0].Grantee.ID) != "owner<&" {
		t.Fatalf("ACL XML attribute or escaping lost: %+v", acl)
	}
	body, err := s3api.EncodeResponse("GetBucketAcl", &s3api.GetBucketAclOutput{Grants: acl.Grants})
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		XMLName xml.Name
		Grants  []struct {
			Grantee struct {
				Type string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
				ID   string
			}
			Permission string
		} `xml:"AccessControlList>Grant"`
	}
	if err := xml.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.XMLName.Local != "AccessControlPolicy" || wire.XMLName.Space != "http://s3.amazonaws.com/doc/2006-03-01/" || len(wire.Grants) != 1 || wire.Grants[0].Grantee.Type != "CanonicalUser" || wire.Grants[0].Grantee.ID != "owner<&" || wire.Grants[0].Permission != "FULL_CONTROL" {
		t.Fatalf("XML consumer lost namespaced ACL: %s", body)
	}
}

func TestRESTXMLFlattenedListsAndUnwrappedOutput(t *testing.T) {
	stamp := time.Date(2026, 9, 13, 10, 11, 12, 0, time.UTC)
	body, err := s3api.EncodeResponse("ListObjectsV2", &s3api.ListObjectsV2Output{
		Contents:       s3api.ObjectList{{Key: awsapiPtr(s3api.ObjectKey("a<&")), LastModified: &stamp, Size: awsapiPtr(s3api.Size(17))}, {Key: awsapiPtr(s3api.ObjectKey("b")), Size: awsapiPtr(s3api.Size(0))}},
		CommonPrefixes: s3api.CommonPrefixList{{Prefix: awsapiPtr(s3api.Prefix("logs/"))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		XMLName  xml.Name
		Contents []struct {
			Key          string
			LastModified time.Time
			Size         int64
		}
		CommonPrefixes []struct{ Prefix string }
	}
	if err := xml.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.XMLName.Local != "ListBucketResult" || len(wire.Contents) != 2 || wire.Contents[0].Key != "a<&" || wire.Contents[0].Size != 17 || !wire.Contents[0].LastModified.Equal(stamp) || wire.Contents[1].Key != "b" || len(wire.CommonPrefixes) != 1 || wire.CommonPrefixes[0].Prefix != "logs/" {
		t.Fatalf("flattened XML collections changed: %s", body)
	}
	body, err = s3api.EncodeResponse("GetBucketLocation", &s3api.GetBucketLocationOutput{LocationConstraint: awsapiPtr(s3api.BucketLocationConstraint("us-west-2"))})
	if err != nil {
		t.Fatal(err)
	}
	var location struct {
		XMLName  xml.Name
		Value    string     `xml:",chardata"`
		Children []struct{} `xml:",any"`
	}
	if err := xml.Unmarshal(body, &location); err != nil {
		t.Fatal(err)
	}
	if location.XMLName.Local != "LocationConstraint" || location.Value != "us-west-2" || len(location.Children) != 0 {
		t.Fatalf("unwrapped location output changed: %s", body)
	}
}

func TestRESTXMLRawPayloadMetadataAndValidation(t *testing.T) {
	payload := []byte{0, 255, '<', '&', 128}
	labels := map[string]string{"Bucket": "trail-bucket", "Key": "logs/event.json.gz"}
	decoded, err := s3api.DecodeRequest("PutObject", awsapi.Request{Labels: labels, Body: payload, Header: http.Header{"X-Amz-Meta-Origin": {"trail"}, "Content-Length": {"5"}}})
	if err != nil {
		t.Fatal(err)
	}
	input := decoded.Input.(*s3api.PutObjectInput)
	if !bytes.Equal(input.Body, payload) || input.Metadata["origin"] != "trail" || input.ContentLength == nil || *input.ContentLength != 5 {
		t.Fatalf("raw object binding changed: %+v", input)
	}
	service, _ := awscatalog.LookupService("s3")
	operation, _ := service.Operation("GetObject")
	response, err := awsapi.EncodeHTTPResponse(service, operation, &s3api.GetObjectOutput{Body: payload, Metadata: input.Metadata, ContentLength: input.ContentLength, ContentType: awsapiPtr(s3api.ContentType("application/gzip"))})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Body, payload) || response.Header.Get("Content-Length") != "5" || response.Header.Get("Content-Type") != "application/gzip" {
		t.Fatalf("raw object response binding changed: %+v", response)
	}
	// Metadata map keys are visible to clients that preserve HTTP/1 header case.
	var headers bytes.Buffer
	if err := response.Header.Write(&headers); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(headers.Bytes(), []byte("x-amz-meta-origin: trail\r\n")) {
		t.Fatalf("metadata key changed on the wire: %s", headers.Bytes())
	}
	_, err = s3api.DecodeRequest("ListObjectsV2", awsapi.Request{Labels: labels, Query: url.Values{"max-keys": {"2147483648"}}})
	var invalid *awsapi.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("out-of-width query number accepted: %v", err)
	}
	_, err = s3api.DecodeRequest("SelectObjectContent", awsapi.Request{Labels: labels})
	if !errors.Is(err, awsapi.ErrUnsupportedBinding) {
		t.Fatalf("eventstream did not fail explicitly: %v", err)
	}
	operation, _ = service.Operation("DeleteObject")
	response, err = awsapi.EncodeHTTPResponse(service, operation, &s3api.DeleteObjectOutput{})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNoContent || len(response.Body) != 0 {
		t.Fatalf("delete body/status changed: %+v", response)
	}
}
