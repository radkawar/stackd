package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"stackd/clock"
	"stackd/storage"
)

type s3HTTPFixture struct {
	Objects  map[string]string
	Requests []struct {
		Name, Method, Target, Body string
		VirtualHost                bool `json:"virtual_host"`
		Headers                    map[string]string
		Status                     int
		ErrorCode                  string   `json:"error_code"`
		ResponseBody               *string  `json:"response_body"`
		ListedKeys                 []string `json:"listed_keys"`
		Readback                   map[string]string
		Missing                    []string
	}
	Integrity []struct {
		Name, Encoding string
		Status         int
		ErrorCode      string `json:"error_code"`
	}
	PresignedReads []struct {
		Name      string
		Input     s3.GetObjectInput
		Status    int
		ErrorCode string `json:"error_code"`
	} `json:"presigned_reads"`
}

func s3HTTPLoad(t *testing.T) s3HTTPFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/s3/http_requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture s3HTTPFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// These are derived transport regressions, not captured native AWS outcomes.
// Multipart and copy routes must not silently execute ordinary object writes.
func TestS3RawHTTPRouting(t *testing.T) {
	fixture := s3HTTPLoad(t)
	_, clients, _ := startEventDeliveryCloud(t, storage.NewMemory(), clock.NewManual(time.Now().UTC()))
	client := s3NativeClient(clients, "test", "test")
	bucket := "s3-http-regression"
	if _, err := client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Requests {
		t.Run(row.Name, func(t *testing.T) {
			for key, body := range fixture.Objects {
				if _, err := client.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: strings.NewReader(body)}); err != nil {
					t.Fatal(err)
				}
			}
			endpoint := clients.server.URL + "/" + bucket
			if row.VirtualHost {
				endpoint = clients.server.URL
			}
			request, err := http.NewRequestWithContext(t.Context(), row.Method, endpoint+row.Target, strings.NewReader(row.Body))
			if err != nil {
				t.Fatal(err)
			}
			if row.VirtualHost {
				request.Host = bucket + ".s3.us-east-1.amazonaws.com"
			}
			for name, value := range row.Headers {
				request.Header.Set(name, value)
			}
			digest := sha256.Sum256([]byte(row.Body))
			request.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(digest[:]))
			if err := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true }).SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, request, hex.EncodeToString(digest[:]), "s3", "us-east-1", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			body := s3HTTPResponse(t, clients.server.Client(), request, row.Status, row.ErrorCode)
			if row.ResponseBody != nil && string(body) != *row.ResponseBody {
				t.Fatalf("response body = %q, want %q", body, *row.ResponseBody)
			}
			if row.ListedKeys != nil {
				var listing struct {
					Contents []struct{ Key string }
				}
				if err := xml.Unmarshal(body, &listing); err != nil {
					t.Fatal(err)
				}
				keys := make([]string, 0, len(listing.Contents))
				for _, object := range listing.Contents {
					keys = append(keys, object.Key)
				}
				if !slices.Equal(keys, row.ListedKeys) {
					t.Fatalf("listed keys = %q, want %q", keys, row.ListedKeys)
				}
			}
			for key, want := range row.Readback {
				s3HTTPObjectBytes(t, client, bucket, key, []byte(want))
			}
			for _, key := range row.Missing {
				output, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
				if output != nil && output.Body != nil {
					output.Body.Close()
				}
				assertAPIError(t, err, "NoSuchKey")
			}
		})
	}
}

func TestS3HTTPPayloadIntegrityRejectsTamperingWithoutOverwrite(t *testing.T) {
	fixture := s3HTTPLoad(t)
	_, clients, _ := startEventDeliveryCloud(t, storage.NewMemory(), clock.NewManual(time.Now().UTC()))
	client := s3NativeClient(clients, "test", "test")
	bucket := "s3-http-integrity"
	if _, err := client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	payload := []byte{'a', 0, 255, '/', '+', ' ', 'z'}
	changed := bytes.Clone(payload)
	changed[0] = 'b'
	digest := sha256.Sum256(payload)
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	credential := aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}
	for _, row := range fixture.Integrity {
		t.Run(row.Name, func(t *testing.T) {
			key := row.Encoding + " space/+"
			var request *http.Request
			var framed []byte
			if row.Encoding == "presigned-sha256" {
				signed, err := s3.NewPresignClient(client).PresignPutObject(t.Context(), &s3.PutObjectInput{
					Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload),
					ChecksumSHA256: &checksum, ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
				})
				if err != nil {
					t.Fatal(err)
				}
				request, err = http.NewRequestWithContext(t.Context(), http.MethodPut, signed.URL, bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				request.Header = signed.SignedHeader.Clone()
				framed = payload
			} else {
				var err error
				request, err = http.NewRequestWithContext(t.Context(), http.MethodPut, clients.server.URL+"/"+bucket+"/"+key, nil)
				if err != nil {
					t.Fatal(err)
				}
				marker := "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
				switch row.Encoding {
				case "unsigned-trailer":
					request.Header.Set("X-Amz-Trailer", "x-amz-checksum-sha256")
					request.Header.Set("X-Amz-Sdk-Checksum-Algorithm", "SHA256")
					framed = []byte(fmt.Sprintf("%x\r\n%s\r\n0\r\nx-amz-checksum-sha256:%s\r\n\r\n", len(payload), payload, checksum))
				case "signed-chunks":
					marker = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
					// Fixed-width placeholders establish the framed length before
					// signing the seed request; SDK StreamSigner supplies signatures.
					framed = []byte(fmt.Sprintf("%x;chunk-signature=%s\r\n%s\r\n0;chunk-signature=%s\r\n\r\n", len(payload), strings.Repeat("0", 64), payload, strings.Repeat("0", 64)))
				default:
					t.Fatalf("unknown fixture encoding %q", row.Encoding)
				}
				request.Header.Set("Content-Encoding", "aws-chunked")
				request.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(payload)))
				request.Header.Set("X-Amz-Content-Sha256", marker)
				request.ContentLength = int64(len(framed))
				now := time.Now().UTC()
				if err := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true }).SignHTTP(t.Context(), credential, request, marker, "s3", "us-east-1", now); err != nil {
					t.Fatal(err)
				}
				if row.Encoding == "signed-chunks" {
					_, seed, found := strings.Cut(request.Header.Get("Authorization"), "Signature=")
					if !found {
						t.Fatal("SDK signer did not produce a seed signature")
					}
					seedBytes, err := hex.DecodeString(seed)
					if err != nil {
						t.Fatal(err)
					}
					signer := v4.NewStreamSigner(credential, "s3", "us-east-1", seedBytes)
					chunk, err := signer.GetSignature(t.Context(), nil, payload, now)
					if err != nil {
						t.Fatal(err)
					}
					zero, err := signer.GetSignature(t.Context(), nil, nil, now)
					if err != nil {
						t.Fatal(err)
					}
					framed = []byte(fmt.Sprintf("%x;chunk-signature=%x\r\n%s\r\n0;chunk-signature=%x\r\n\r\n", len(payload), chunk, payload, zero))
				}
				request.Body = io.NopCloser(bytes.NewReader(framed))
			}
			s3HTTPResponse(t, clients.server.Client(), request, http.StatusOK, "")
			s3HTTPObjectBytes(t, client, bucket, key, payload)

			// Reuse the valid authorization/checksum and alter only payload bytes,
			// preserving framing and length. Rejection must not replace the object.
			tampered := request.Clone(t.Context())
			tampered.Body = io.NopCloser(bytes.NewReader(bytes.Replace(framed, payload, changed, 1)))
			tampered.GetBody = nil
			s3HTTPResponse(t, clients.server.Client(), tampered, row.Status, row.ErrorCode)
			s3HTTPObjectBytes(t, client, bucket, key, payload)
		})
	}
}

func TestS3PresignedReadBindings(t *testing.T) {
	fixture := s3HTTPLoad(t)
	_, clients, _ := startEventDeliveryCloud(t, storage.NewMemory(), clock.NewManual(time.Now().UTC()))
	client := s3NativeClient(clients, "test", "test")
	bucket, key := "s3-presigned-read", "binary"
	payload := []byte{'a', 0, 255, '/', '+', ' ', 'z'}
	digest := sha256.Sum256(payload)
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	if _, err := client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload), ChecksumSHA256: &checksum}); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.PresignedReads {
		t.Run(row.Name, func(t *testing.T) {
			input := row.Input
			input.Bucket, input.Key = &bucket, &key
			signed, err := s3.NewPresignClient(client).PresignGetObject(t.Context(), &input)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, signed.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header = signed.SignedHeader.Clone()
			body := s3HTTPResponse(t, clients.server.Client(), request, row.Status, row.ErrorCode, http.Header{"X-Amz-Checksum-Sha256": {""}})
			if row.Status == http.StatusOK && !bytes.Equal(body, payload) {
				t.Fatalf("presigned binary body = %v, want %v", body, payload)
			}
		})
	}
}

func s3HTTPResponse(t *testing.T, client s3.HTTPClient, request *http.Request, status int, code string, headers ...http.Header) []byte {
	t.Helper()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != status {
		t.Fatalf("%s %s: HTTP %d, want %d; body %q", request.Method, request.URL, response.StatusCode, status, body)
	}
	for _, expected := range headers {
		for name, values := range expected {
			if got := response.Header.Get(name); got != values[0] {
				t.Fatalf("%s = %q, want %q", name, got, values[0])
			}
		}
	}
	if code != "" {
		var failure struct {
			XMLName xml.Name `xml:"Error"`
			Code    string
		}
		if err := xml.Unmarshal(body, &failure); err != nil {
			t.Fatalf("invalid S3 error body %q: %v", body, err)
		}
		if failure.Code != code {
			t.Fatalf("S3 error = %q, want %q; body %q", failure.Code, code, body)
		}
	}
	return body
}

func s3HTTPObjectBytes(t *testing.T, client *s3.Client, bucket, key string, want []byte) {
	t.Helper()
	output, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	defer output.Body.Close()
	body, err := io.ReadAll(output.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, want) {
		t.Fatalf("SDK readback %q = %x, want %x", key, body, want)
	}
}
