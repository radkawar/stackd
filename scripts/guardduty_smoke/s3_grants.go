package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	st "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func s3GrantDetection(ctx context.Context, endpoint string, c *gd.Client, detector *string) func() {
	objects := s3.NewFromConfig(config("123456789012", "us-east-1"), func(o *s3.Options) { o.BaseEndpoint = &endpoint; o.UsePathStyle = true })
	bucket := "guardduty-bucket-grants"
	_, err := objects.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	must(err)
	_, err = objects.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{Bucket: &bucket})
	must(err)
	acl, err := objects.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
	must(err)
	finding := func(kind string) []gt.Finding {
		out, e := c.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: detector, FindingCriteria: &gt.FindingCriteria{Criterion: map[string]gt.Condition{"type": {Equals: []string{kind}}, "service.action.awsApiCallAction.api": {Equals: []string{"PutBucketAcl"}}}}})
		must(e)
		if len(out.FindingIds) == 0 {
			return nil
		}
		got, e := c.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: detector, FindingIds: out.FindingIds})
		must(e)
		return got.Findings
	}
	const anonymous = "Policy:S3/BucketAnonymousAccessGranted"
	const authenticated = "Policy:S3/BucketPublicAccessGranted"
	checkCounts := func(anon, auth int32) {
		for kind, want := range map[string]int32{anonymous: anon, authenticated: auth} {
			got := finding(kind)
			if want == 0 {
				check(len(got) == 0, "nonpublic/denied ACL generated "+kind)
				continue
			}
			check(len(got) == 1 && aws.ToInt32(got[0].Service.Count) == want, "public ACL occurrence count changed for "+kind)
			check(got[0].Service.Action.AwsApiCallAction.AffectedResources["AWS::S3::Bucket"] == bucket && aws.ToString(got[0].Resource.ResourceType) == "AccessKey" && aws.ToFloat64(got[0].Severity) == 8, "bucket ACL finding lost actual management resource/caller")
		}
	}
	_, err = objects.PutBucketAcl(ctx, &s3.PutBucketAclInput{Bucket: &bucket, ACL: st.BucketCannedACLPublicRead})
	code(err, "AccessDenied")
	checkCounts(0, 0)
	_, err = objects.DeletePublicAccessBlock(ctx, &s3.DeletePublicAccessBlockInput{Bucket: &bucket})
	must(err)
	putCanned := func(value st.BucketCannedACL) {
		_, e := objects.PutBucketAcl(ctx, &s3.PutBucketAclInput{Bucket: &bucket, ACL: value})
		must(e)
	}
	putCanned(st.BucketCannedACLPrivate)
	checkCounts(0, 0)
	putCanned(st.BucketCannedACLPublicRead)
	checkCounts(1, 0)
	putCanned(st.BucketCannedACLAuthenticatedRead)
	checkCounts(1, 1)
	_, err = objects.PutBucketAcl(ctx, &s3.PutBucketAclInput{Bucket: &bucket, GrantRead: aws.String(`uri="http://acs.amazonaws.com/groups/global/AllUsers"`)})
	must(err)
	checkCounts(2, 1)
	group := func(name string) st.Grant {
		return st.Grant{Grantee: &st.Grantee{Type: st.TypeGroup, URI: aws.String("http://acs.amazonaws.com/groups/global/" + name)}, Permission: st.PermissionRead}
	}
	putBody := func(groups ...string) {
		grants := []st.Grant{{Grantee: &st.Grantee{Type: st.TypeCanonicalUser, ID: acl.Owner.ID}, Permission: st.PermissionFullControl}}
		for _, name := range groups {
			grants = append(grants, group(name))
		}
		_, e := objects.PutBucketAcl(ctx, &s3.PutBucketAclInput{Bucket: &bucket, AccessControlPolicy: &st.AccessControlPolicy{Owner: acl.Owner, Grants: grants}})
		must(e)
	}
	putBody("AuthenticatedUsers")
	checkCounts(2, 2)
	putBody("AllUsers", "AuthenticatedUsers")
	checkCounts(3, 3)
	putCanned(st.BucketCannedACLPrivate)
	checkCounts(3, 3)
	_, err = objects.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
	must(err)
	return func() {
		checkCounts(3, 3)
		fmt.Println("GuardDuty actual S3 canned/header/XML public ACL grants, denied/private exclusions, anonymous/authenticated separation and retained restart evidence: PASS")
	}
}
