package stackd_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"stackd"
)

func TestS3RangeUsesCurrentIdentityPolicySnapshot(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			clients, reopen := retainedCloud(t, backend, stackd.Config{})
			rootIAM := clients.iam("test", "test", "")
			rootS3 := s3NativeClient(clients, "test", "test")
			const bucket = "current-policy-ranges"
			const key = "allowed"
			payload := []byte{0x00, 0x81, 0x02, 0xff, 0x19, 0xa4, 0x00, 0x7f, 0xe3, 0x00, 0x0d, 0x0a, 0x2a, 0xc8, 0x04, 0x10}
			if _, err := rootS3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
				t.Fatal(err)
			}
			put, err := rootS3.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(payload), ServerSideEncryption: s3types.ServerSideEncryptionAes256})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rootS3.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String("blocked"), Body: bytes.NewReader(payload)}); err != nil {
				t.Fatal(err)
			}
			_, accessKey, secret := clients.user(t, "test", "Reader")
			if _, err := rootIAM.CreateGroup(ctx, &iam.CreateGroupInput{GroupName: aws.String("Readers")}); err != nil {
				t.Fatal(err)
			}
			if _, err := rootIAM.AddUserToGroup(ctx, &iam.AddUserToGroupInput{GroupName: aws.String("Readers"), UserName: aws.String("Reader")}); err != nil {
				t.Fatal(err)
			}
			allowRead := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"},{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::%s"}]}`, bucket, bucket)
			if _, err := rootIAM.PutGroupPolicy(ctx, &iam.PutGroupPolicyInput{GroupName: aws.String("Readers"), PolicyName: aws.String("read"), PolicyDocument: aws.String(allowRead)}); err != nil {
				t.Fatal(err)
			}
			guard, err := rootIAM.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyName: aws.String("guard"), PolicyDocument: aws.String(allowRead)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rootIAM.AttachGroupPolicy(ctx, &iam.AttachGroupPolicyInput{GroupName: aws.String("Readers"), PolicyArn: guard.Policy.Arn}); err != nil {
				t.Fatal(err)
			}
			boundaryDocument := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/allowed"},{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::%s"}]}`, bucket, bucket)
			boundary, err := rootIAM.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyName: aws.String("boundary"), PolicyDocument: aws.String(boundaryDocument)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rootIAM.PutUserPermissionsBoundary(ctx, &iam.PutUserPermissionsBoundaryInput{UserName: aws.String("Reader"), PermissionsBoundary: boundary.Policy.Arn}); err != nil {
				t.Fatal(err)
			}
			reader := s3NativeClient(clients, accessKey, secret)
			rangeRead := func() {
				t.Helper()
				out, err := reader.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Range: aws.String("bytes=3-7"), IfMatch: put.ETag})
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(out.Body)
				closeErr := out.Body.Close()
				if readErr != nil || closeErr != nil || !bytes.Equal(body, payload[3:8]) || aws.ToString(out.ContentRange) != "bytes 3-7/16" || aws.ToInt64(out.ContentLength) != 5 || aws.ToString(out.ETag) != aws.ToString(put.ETag) || out.ServerSideEncryption != s3types.ServerSideEncryptionAes256 {
					t.Fatalf("range/body/encryption metadata changed: %+v body=%x read=%v close=%v", out, body, readErr, closeErr)
				}
			}
			reject := func(input *s3.GetObjectInput, code string) {
				t.Helper()
				out, err := reader.GetObject(ctx, input)
				if out != nil && out.Body != nil {
					out.Body.Close()
				}
				var api smithy.APIError
				if !errors.As(err, &api) || api.ErrorCode() != code {
					t.Fatalf("GetObject wanted %s, got %v", code, err)
				}
			}
			rangeRead()
			reject(&s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("blocked"), Range: aws.String("bytes=0-1")}, "AccessDenied")
			reject(&s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("missing")}, "NoSuchKey")
			reject(&s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Range: aws.String("bytes=99-100")}, "InvalidRange")
			reject(&s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), IfMatch: aws.String(`"not-the-etag"`)}, "PreconditionFailed")
			denyRead := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}}`, bucket)
			if _, err := rootIAM.CreatePolicyVersion(ctx, &iam.CreatePolicyVersionInput{PolicyArn: guard.Policy.Arn, PolicyDocument: aws.String(denyRead), SetAsDefault: true}); err != nil {
				t.Fatal(err)
			}
			reject(&s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Range: aws.String("bytes=3-7")}, "AccessDenied")
			if _, err := rootIAM.SetDefaultPolicyVersion(ctx, &iam.SetDefaultPolicyVersionInput{PolicyArn: guard.Policy.Arn, VersionId: aws.String("v1")}); err != nil {
				t.Fatal(err)
			}
			rangeRead()
			if _, err := rootIAM.RemoveUserFromGroup(ctx, &iam.RemoveUserFromGroupInput{GroupName: aws.String("Readers"), UserName: aws.String("Reader")}); err != nil {
				t.Fatal(err)
			}
			reject(&s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Range: aws.String("bytes=3-7")}, "AccessDenied")
			if _, err := rootIAM.AddUserToGroup(ctx, &iam.AddUserToGroupInput{GroupName: aws.String("Readers"), UserName: aws.String("Reader")}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			reader = s3NativeClient(clients, accessKey, secret)
			rangeRead()
		})
	}
}
