package integrations

import (
	"bytes"
	"errors"
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/iam"
	"stackd/internal/services/s3"
	"stackd/storage/memory"
)

func TestResourceTaggingReportCallerAuthority(t *testing.T) {
	const accountID = "123456789012"
	domain := memory.NewDomain()
	identities := iam.NewMemoryRepository(domain)
	user := iam.User{Arn: "arn:aws:iam::" + accountID + ":user/reporter", UserId: "AIDAREPORTER", UserName: "reporter",
		IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"reports": `{"Statement":{"Effect":"Allow","Action":["s3:GetBucketAcl","s3:GetBucketLocation","s3:PutObject"],"Resource":"*","Condition":{"StringEquals":{"aws:CalledViaLast":"tagpolicies.tag.amazonaws.com"},"Bool":{"aws:PrincipalIsAWSService":"false"}}}}`}}}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: accountID, Region: "us-east-1", PrincipalARN: user.Arn, PrincipalID: user.UserId, UserName: user.UserName})
	if err := identities.Update(ctx, func(tx iam.WriteTx) error { return tx.PutUser(iam.Scope{Partition: "aws", AccountID: accountID}, user) }); err != nil {
		t.Fatal(err)
	}
	identityOwner := iam.NewWithConfig(iam.Config{Repository: identities})
	authorizer := authorization.New(identityOwner, nil)
	repository := s3.NewMemoryRepository(domain)
	bucket := s3.BucketRecord{Key: s3.BucketKey{Partition: "aws", Name: "tag-policy-reports"}, AccountID: accountID, Region: "us-east-1", Ownership: "BucketOwnerEnforced", EncryptionAlgorithm: "AES256"}
	putBucket := func() {
		t.Helper()
		if err := repository.Update(ctx, func(tx s3.Transaction) error { return tx.PutBucket(bucket) }); err != nil {
			t.Fatal(err)
		}
	}
	putBucket()
	owner := s3.New(s3.Config{Repository: repository, Authorizer: authorizer})
	adapter := ResourceTaggingReports{S3: owner}
	key := "AwsTagPolicies/o-example/2026-09-27T00:00:00Z/report.csv"
	body := []byte("ResourceArn,ComplianceStatus\narn:aws:s3:::tag-policy-reports,COMPLIANT\n")
	if _, rejected := owner.PutObject(ctx, &api.PutObjectInput{Bucket: new(api.BucketName(bucket.Key.Name)), Key: new(api.ObjectKey(key)), Body: body}); rejected == nil || rejected.Code != "AccessDenied" {
		t.Fatalf("direct write without the required forward-access chain: %v", rejected)
	}
	if err := adapter.Deliver(ctx, bucket.Key.Name, key, "o-example", body); err != nil {
		t.Fatal(err)
	}
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: accountID, Region: "us-east-1", PrincipalARN: "arn:aws:iam::" + accountID + ":root", PrincipalID: accountID})
	read, rejected := owner.GetObject(root, &api.GetObjectInput{Bucket: new(api.BucketName(bucket.Key.Name)), Key: new(api.ObjectKey(key))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if !bytes.Equal(read.Output.Body, body) {
		t.Fatalf("delivered report = %q, want %q", read.Output.Body, body)
	}

	// A service-principal replacement would lose this caller ARN condition; a
	// direct repository write would lose the native bucket explicit denial.
	bucket.Policy = authorization.BoundPolicy{Document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::tag-policy-reports/*","Condition":{"ArnEquals":{"aws:PrincipalArn":"` + user.Arn + `"}}}}`}
	putBucket()
	err := adapter.Deliver(ctx, bucket.Key.Name, key, "o-example", []byte("replaced"))
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.Code != "AccessDenied" {
		t.Fatalf("caller-specific bucket deny = %v", err)
	}
	read, rejected = owner.GetObject(root, &api.GetObjectInput{Bucket: new(api.BucketName(bucket.Key.Name)), Key: new(api.ObjectKey(key))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if !bytes.Equal(read.Output.Body, body) {
		t.Fatalf("denied delivery replaced report with %q", read.Output.Body)
	}
}
