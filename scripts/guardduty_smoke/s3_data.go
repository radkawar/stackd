package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func s3DataDetection(ctx context.Context, endpoint string, detectorClient *gd.Client, detector *string) func() {
	client := s3.NewFromConfig(config("123456789012", "us-east-1"), func(o *s3.Options) { o.BaseEndpoint = &endpoint; o.UsePathStyle = true })
	bucket, key, body := "guardduty-data-source", "observed-object", "actual S3 data-plane bytes"
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	must(err)
	_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: strings.NewReader(body)})
	must(err)
	readObject := func() {
		out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
		must(err)
		actual, err := io.ReadAll(out.Body)
		must(err)
		must(out.Body.Close())
		check(string(actual) == body, "S3 data request did not return stored bytes")
	}
	findings := func() []gt.Finding {
		page, err := detectorClient.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: detector, FindingCriteria: &gt.FindingCriteria{Criterion: map[string]gt.Condition{
			"type":                                {Equals: []string{"Policy:IAMUser/RootCredentialUsage"}},
			"service.action.awsApiCallAction.api": {Equals: []string{"GetObject"}},
		}}})
		must(err)
		if len(page.FindingIds) == 0 {
			return nil
		}
		out, err := detectorClient.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: detector, FindingIds: page.FindingIds})
		must(err)
		return out.Findings
	}
	setFeature := func(status gt.FeatureStatus) {
		_, err := detectorClient.UpdateDetector(ctx, &gd.UpdateDetectorInput{DetectorId: detector, Features: []gt.DetectorFeatureConfiguration{{Name: gt.DetectorFeatureS3DataEvents, Status: status}}})
		must(err)
	}
	verifyFeature := func(enabled bool) {
		out, err := detectorClient.GetDetector(ctx, &gd.GetDetectorInput{DetectorId: detector})
		must(err)
		want := gt.FeatureStatusDisabled
		if enabled {
			want = gt.FeatureStatusEnabled
		}
		for _, feature := range out.Features {
			if feature.Name == gt.DetectorFeatureResultS3DataEvents {
				check(feature.Status == want, "S3 source state was not retained")
				return
			}
		}
		check(false, "S3 source configuration was missing")
	}
	readObject()
	check(len(findings()) == 0, "disabled S3 protection consumed data activity")
	setFeature(gt.FeatureStatusEnabled)
	verifyFeature(true)
	readObject()
	got := findings()
	check(len(got) == 1 && aws.ToInt32(got[0].Service.Count) == 1 && aws.ToString(got[0].Service.FeatureName) == "S3DataEvent" && aws.ToString(got[0].Service.Action.AwsApiCallAction.ServiceName) == "s3.amazonaws.com", "enabled S3 protection did not observe actual data request")
	id := aws.ToString(got[0].Id)
	// Rejecting mutually exclusive runtime features must not undo S3 protection.
	// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_UpdateDetector.html
	_, err = detectorClient.UpdateDetector(ctx, &gd.UpdateDetectorInput{DetectorId: detector, Features: []gt.DetectorFeatureConfiguration{
		{Name: gt.DetectorFeatureS3DataEvents, Status: gt.FeatureStatusDisabled},
		{Name: gt.DetectorFeatureEksRuntimeMonitoring, Status: gt.FeatureStatusDisabled},
		{Name: gt.DetectorFeatureRuntimeMonitoring, Status: gt.FeatureStatusDisabled},
	}})
	code(err, "BadRequestException")
	verifyFeature(true)
	setFeature(gt.FeatureStatusDisabled)
	verifyFeature(false)
	readObject()
	check(aws.ToInt32(findings()[0].Service.Count) == 1, "disabled-period S3 activity was observed")
	setFeature(gt.FeatureStatusEnabled)
	check(aws.ToInt32(findings()[0].Service.Count) == 1, "enabling S3 protection replayed prior activity")
	return func() {
		verifyFeature(true)
		retained := findings()
		check(len(retained) == 1 && aws.ToString(retained[0].Id) == id && aws.ToInt32(retained[0].Service.Count) == 1, "S3 finding was lost or replayed on restart")
		readObject()
		retained = findings()
		check(len(retained) == 1 && aws.ToString(retained[0].Id) == id && aws.ToInt32(retained[0].Service.Count) == 2, "S3 source did not resume after restart")
		setFeature(gt.FeatureStatusDisabled)
		_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
		must(err)
		_, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
		must(err)
		fmt.Println("GuardDuty real S3 data events: feature enable/disable, rejected-update rollback, no replay and SQLite restart aggregation: PASS")
	}
}
