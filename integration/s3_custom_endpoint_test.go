package stackd_test

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/smithy-go"

	"stackd"
	"stackd/clock"
)

func TestS3AccessPointCustomIPEndpoint(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			const account, region = "123456789012", "us-west-2"
			const bucket, point, key = "custom-ap-data", "custom-route", "nested/a b%2Fc"
			at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: clock.NewManual(at)})
			configuration := func() aws.Config {
				endpoint, err := url.Parse(clients.server.URL)
				if err != nil {
					t.Fatal(err)
				}
				transport := &http.Transport{Proxy: http.ProxyURL(endpoint)}
				t.Cleanup(transport.CloseIdleConnections)
				return aws.Config{Region: region, BaseEndpoint: aws.String(clients.server.URL),
					Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
					HTTPClient:  &http.Client{Transport: transport}, RetryMaxAttempts: 1,
					RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
					ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired}
			}
			config := configuration()
			data := s3.NewFromConfig(config)
			control := s3control.NewFromConfig(config)
			if _, err := data.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket), CreateBucketConfiguration: &s3types.CreateBucketConfiguration{LocationConstraint: s3types.BucketLocationConstraint(region)}}); err != nil {
				t.Fatal(err)
			}
			created, err := control.CreateAccessPoint(ctx, &s3control.CreateAccessPointInput{AccountId: aws.String(account), Name: aws.String(point), Bucket: aws.String(bucket)})
			if err != nil {
				t.Fatal(err)
			}
			arn := aws.ToString(created.AccessPointArn)
			if arn != "arn:aws:s3:"+region+":"+account+":accesspoint/"+point {
				t.Fatalf("access point scope: %q", arn)
			}
			if _, err := data.PutBucketMetricsConfiguration(ctx, &s3.PutBucketMetricsConfigurationInput{Bucket: aws.String(bucket), Id: aws.String("access-point"), MetricsConfiguration: &s3types.MetricsConfiguration{Id: aws.String("access-point"), Filter: &s3types.MetricsFilterMemberAccessPointArn{Value: arn}}}); err != nil {
				t.Fatal(err)
			}
			payload := []byte{0, 255, 1, 'a', 'p', '/', '%', 0}
			if _, err := data.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(arn), Key: aws.String(key), Body: bytes.NewReader(payload)}); err != nil {
				t.Fatal(err)
			}
			read := func() {
				t.Helper()
				output, err := data.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(arn), Key: aws.String(key)})
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(output.Body)
				if err := errors.Join(readErr, output.Body.Close()); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(body, payload) {
					t.Fatalf("access-point bytes = %q; want %q", body, payload)
				}
			}
			read()
			metrics, err := cloudwatch.NewFromConfig(config).GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace: aws.String("AWS/S3"), MetricName: aws.String("GetRequests"),
				Dimensions: []cwtypes.Dimension{{Name: aws.String("BucketName"), Value: aws.String(bucket)}, {Name: aws.String("FilterId"), Value: aws.String("access-point")}},
				StartTime:  aws.Time(at.Add(-time.Minute)), EndTime: aws.Time(at.Add(time.Minute)), Period: aws.Int32(60), Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})
			if err != nil {
				t.Fatal(err)
			}
			var sum float64
			for _, sample := range metrics.Datapoints {
				sum += aws.ToFloat64(sample.Sum)
			}
			if sum != 1 {
				t.Fatalf("authenticated regional access-point GetRequests = %v; want 1", sum)
			}
			clients = reopen()
			config = configuration()
			data = s3.NewFromConfig(config)
			control = s3control.NewFromConfig(config)
			read()

			presigned, err := s3.NewPresignClient(data).PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(arn), Key: aws.String(key)})
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, presigned.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.URL.Host = strings.Replace(request.URL.Host, account, "222222222222", 1)
			request.Host = request.URL.Host
			response, err := config.HTTPClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct{ Code string }
			decodeErr := xml.NewDecoder(response.Body).Decode(&wire)
			if err := errors.Join(decodeErr, response.Body.Close()); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusForbidden || wire.Code != "SignatureDoesNotMatch" {
				t.Fatalf("changed signed account host: status=%d code=%s", response.StatusCode, wire.Code)
			}
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":%q}]}`, arn+"/object/*")
			if _, err := control.PutAccessPointPolicy(ctx, &s3control.PutAccessPointPolicyInput{AccountId: aws.String(account), Name: aws.String(point), Policy: aws.String(policy)}); err != nil {
				t.Fatal(err)
			}
			_, err = data.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(arn), Key: aws.String(key)})
			var denied smithy.APIError
			if !errors.As(err, &denied) || denied.ErrorCode() != "AccessDenied" {
				t.Fatalf("current access-point denial was not enforced: %v", err)
			}
			if _, err := data.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(arn), Key: aws.String(key)}); err != nil {
				t.Fatal(err)
			}
			if _, err := control.DeleteAccessPoint(ctx, &s3control.DeleteAccessPointInput{AccountId: aws.String(account), Name: aws.String(point)}); err != nil {
				t.Fatal(err)
			}
			if _, err := data.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
