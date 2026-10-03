package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Both legacy kinds share the lifecycle assertions, but use their actual SDK APIs.
type ipListSmoke struct {
	ctx      context.Context
	client   *gd.Client
	detector *string
	threat   bool
}

type ipListSmokeState struct {
	name, location, owner, status, format string
	tags                                  map[string]string
}

func (s ipListSmoke) kind() string {
	if s.threat {
		return "threatintelset"
	}
	return "ipset"
}

func (s ipListSmoke) create(name, location string, activate bool) (string, error) {
	if s.threat {
		out, err := s.client.CreateThreatIntelSet(s.ctx, &gd.CreateThreatIntelSetInput{DetectorId: s.detector, Name: &name, Location: &location, Format: gt.ThreatIntelSetFormatTxt, Activate: &activate, ExpectedBucketOwner: aws.String("123456789012"), Tags: map[string]string{"owner": "ip-list-reader"}})
		if err != nil {
			return "", err
		}
		return aws.ToString(out.ThreatIntelSetId), nil
	}
	out, err := s.client.CreateIPSet(s.ctx, &gd.CreateIPSetInput{DetectorId: s.detector, Name: &name, Location: &location, Format: gt.IpSetFormatTxt, Activate: &activate, ExpectedBucketOwner: aws.String("123456789012"), Tags: map[string]string{"owner": "ip-list-reader"}})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.IpSetId), nil
}

func (s ipListSmoke) get(id string) (ipListSmokeState, error) {
	if s.threat {
		out, err := s.client.GetThreatIntelSet(s.ctx, &gd.GetThreatIntelSetInput{DetectorId: s.detector, ThreatIntelSetId: &id})
		if err != nil {
			return ipListSmokeState{}, err
		}
		return ipListSmokeState{aws.ToString(out.Name), aws.ToString(out.Location), aws.ToString(out.ExpectedBucketOwner), string(out.Status), string(out.Format), out.Tags}, nil
	}
	out, err := s.client.GetIPSet(s.ctx, &gd.GetIPSetInput{DetectorId: s.detector, IpSetId: &id})
	if err != nil {
		return ipListSmokeState{}, err
	}
	return ipListSmokeState{aws.ToString(out.Name), aws.ToString(out.Location), aws.ToString(out.ExpectedBucketOwner), string(out.Status), string(out.Format), out.Tags}, nil
}

func (s ipListSmoke) update(id string, name, location, owner *string, activate *bool) error {
	if s.threat {
		_, err := s.client.UpdateThreatIntelSet(s.ctx, &gd.UpdateThreatIntelSetInput{DetectorId: s.detector, ThreatIntelSetId: &id, Name: name, Location: location, ExpectedBucketOwner: owner, Activate: activate})
		return err
	}
	_, err := s.client.UpdateIPSet(s.ctx, &gd.UpdateIPSetInput{DetectorId: s.detector, IpSetId: &id, Name: name, Location: location, ExpectedBucketOwner: owner, Activate: activate})
	return err
}

func (s ipListSmoke) remove(id string) error {
	if s.threat {
		_, err := s.client.DeleteThreatIntelSet(s.ctx, &gd.DeleteThreatIntelSetInput{DetectorId: s.detector, ThreatIntelSetId: &id})
		return err
	}
	_, err := s.client.DeleteIPSet(s.ctx, &gd.DeleteIPSetInput{DetectorId: s.detector, IpSetId: &id})
	return err
}

func (s ipListSmoke) page(max int32, token *string) ([]string, *string, error) {
	if s.threat {
		out, err := s.client.ListThreatIntelSets(s.ctx, &gd.ListThreatIntelSetsInput{DetectorId: s.detector, MaxResults: &max, NextToken: token})
		if err != nil {
			return nil, nil, err
		}
		return out.ThreatIntelSetIds, out.NextToken, nil
	}
	out, err := s.client.ListIPSets(s.ctx, &gd.ListIPSetsInput{DetectorId: s.detector, MaxResults: &max, NextToken: token})
	if err != nil {
		return nil, nil, err
	}
	return out.IpSetIds, out.NextToken, nil
}

func ipListError(err error, want string) {
	code(err, want)
	var response *smithyhttp.ResponseError
	check(errors.As(err, &response) && response.HTTPStatusCode() == 400, fmt.Sprintf("%s must retain native HTTP 400: %v", want, err))
}

// ipLists leaves both kinds ACTIVE. Invoke its callback after restarting the
// executable and before deleting the detector; the callback also cleans up.
// The public Get APIs expose lifecycle metadata, not ingested address membership.
func ipLists(ctx context.Context, endpoint string, detector *string) func() {
	const account = "123456789012"
	c := client(endpoint, account, "us-east-1")
	roles := iam.NewFromConfig(config(account, "us-east-1"), func(o *iam.Options) { o.BaseEndpoint = &endpoint })
	objects := s3.NewFromConfig(config(account, "us-east-1"), func(o *s3.Options) { o.BaseEndpoint = &endpoint; o.UsePathStyle = true })
	bucket := "guardduty-ip-list-smoke"
	roleName := aws.String("AWSServiceRoleForAmazonGuardDuty")
	role, err := roles.GetRole(ctx, &iam.GetRoleInput{RoleName: roleName})
	must(err)
	rolePolicies := func() map[string]bool {
		names := map[string]bool{}
		var marker *string
		for {
			out, e := roles.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: roleName, Marker: marker})
			must(e)
			for _, name := range out.PolicyNames {
				names[name] = true
			}
			if !out.IsTruncated {
				return names
			}
			marker = out.Marker
		}
	}
	originalPolicies := rolePolicies()
	_, err = objects.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	must(err)
	put := func(key, body string) {
		_, e := objects.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: strings.NewReader(body)})
		must(e)
	}
	name := aws.String("guardduty-ip-list-reader")
	_, err = roles.CreateUser(ctx, &iam.CreateUserInput{UserName: name})
	must(err)
	key, err := roles.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: name})
	must(err)
	policyName := aws.String("guardduty-ip-list-read")
	setCallerPolicy := func(document string) {
		_, e := roles.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: name, PolicyName: policyName, PolicyDocument: &document})
		must(e)
	}
	cfg := config(account, "us-east-1")
	cfg.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey), "")
	caller := gd.NewFromConfig(cfg, func(o *gd.Options) { o.BaseEndpoint = &endpoint })
	type retainedList struct {
		api                 ipListSmoke
		ids                 []string
		location, key, name string
	}
	var retained []retainedList
	for _, threat := range []bool{false, true} {
		api := ipListSmoke{ctx, c, detector, threat}
		objectKey := api.kind() + ".txt"
		location := "https://s3.us-east-1.amazonaws.com/" + bucket + "/" + objectKey
		missing := "https://s3.us-east-1.amazonaws.com/" + bucket + "/missing.txt"
		put(objectKey, "198.51.100.10\n203.0.113.0/24\n")
		reader := api
		reader.client = caller
		setCallerPolicy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"guardduty:*","Resource":"*"}]}`)
		_, err = reader.create(api.kind()+"-denied", location, true)
		code(err, "AccessDenied")
		listed, _, e := api.page(50, nil)
		must(e)
		check(len(listed) == 0, "denied role-policy admission orphaned "+api.kind())
		_, err = api.create(api.kind()+"-failed", missing, true)
		ipListError(err, "InternalServerErrorException")
		listed, _, e = api.page(50, nil)
		must(e)
		check(len(listed) == 1, "failed ingestion did not retain its ERROR child")
		failed, e := api.get(listed[0])
		must(e)
		check(failed.status == "ERROR" && failed.location == missing, "failed ingestion retained active or incorrect source state")
		must(api.remove(listed[0]))
		id, e := api.create(api.kind()+"-source", missing, false)
		must(e)
		state, e := api.get(id)
		must(e)
		check(state.status == "INACTIVE" && state.format == "TXT" && state.owner == account, "inactive list metadata mismatch")
		ipListError(api.update(id, nil, nil, nil, aws.Bool(true)), "InternalServerErrorException")
		state, e = api.get(id)
		must(e)
		check(state.status == "ERROR" && state.location == missing, "missing-source activation must retain ERROR metadata")
		ipListError(api.update(id, nil, &location, aws.String("000000000000"), aws.Bool(true)), "BadRequestException")
		state, e = api.get(id)
		must(e)
		check(state.status == "ERROR" && state.owner == "000000000000" && state.location == location, "owner mismatch lost attempted metadata")
		renamed := api.kind() + "-renamed"
		must(api.update(id, &renamed, &location, aws.String(account), aws.Bool(true)))
		state, e = api.get(id)
		must(e)
		check(state.status == "ACTIVE" && state.name == renamed, "owned source did not activate")

		arn := "arn:aws:guardduty:us-east-1:" + account + ":detector/" + aws.ToString(detector) + "/" + api.kind() + "/" + id
		_, e = c.TagResource(ctx, &gd.TagResourceInput{ResourceArn: &arn, Tags: map[string]string{"extra": "remove"}})
		must(e)
		tags, e := c.ListTagsForResource(ctx, &gd.ListTagsForResourceInput{ResourceArn: &arn})
		must(e)
		check(tags.Tags["owner"] == "ip-list-reader" && tags.Tags["extra"] == "remove", "child tag merge failed")
		_, e = c.UntagResource(ctx, &gd.UntagResourceInput{ResourceArn: &arn, TagKeys: []string{"extra"}})
		must(e)
		setCallerPolicy(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["guardduty:GetIPSet","guardduty:GetThreatIntelSet"],"Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/owner":"ip-list-reader"}}}]}`, arn))
		_, e = reader.get(id)
		must(e)
		_, e = c.TagResource(ctx, &gd.TagResourceInput{ResourceArn: &arn, Tags: map[string]string{"owner": "revoked"}})
		must(e)
		_, e = reader.get(id)
		code(e, "AccessDenied")
		_, e = c.TagResource(ctx, &gd.TagResourceInput{ResourceArn: &arn, Tags: map[string]string{"owner": "ip-list-reader"}})
		must(e)
		_, e = reader.get(id)
		must(e)
		setCallerPolicy(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"guardduty:*","Resource":%q}]}`, "arn:aws:guardduty:us-east-1:"+account+":detector/"+aws.ToString(detector)))
		_, e = reader.get(id)
		code(e, "AccessDenied")

		// An explicit bucket deny exercises the current role authorization even
		// though activation maintains its own exact-object inline allow policy.
		deny := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":%q},"Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":%q}]}`, aws.ToString(role.Role.Arn), "arn:aws:s3:::"+bucket+"/"+objectKey)
		_, e = objects.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &deny})
		must(e)
		ipListError(api.update(id, nil, nil, nil, aws.Bool(true)), "InternalServerErrorException")
		state, e = api.get(id)
		must(e)
		check(state.status == "ERROR", "current S3 role denial left list active")
		_, e = objects.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
		must(e)
		must(api.update(id, nil, nil, nil, aws.Bool(true)))
		put(objectKey, "192.0.2.20\n")
		state, e = api.get(id)
		must(e)
		check(state.status == "ACTIVE", "source overwrite changed activation without update")
		must(api.update(id, nil, nil, nil, aws.Bool(false)))
		state, e = api.get(id)
		must(e)
		check(state.status == "INACTIVE", "list did not deactivate")
		must(api.update(id, nil, nil, nil, aws.Bool(true)))

		ids := []string{id}
		quota := 1
		if threat {
			quota = 6
		}
		for n := 1; n < quota; n++ {
			extra, e := api.create(fmt.Sprintf("%s-extra-%d", api.kind(), n), location, false)
			must(e)
			ids = append(ids, extra)
		}
		_, e = api.create(api.kind()+"-over-quota", location, false)
		ipListError(e, "InternalServerErrorException")
		for _, max := range []int32{0, 51} {
			_, _, e = api.page(max, nil)
			ipListError(e, "BadRequestException")
		}
		_, _, e = api.page(1, aws.String("invalid-token"))
		ipListError(e, "InternalServerErrorException")
		retained = append(retained, retainedList{api, ids, location, objectKey, renamed})
	}
	verifyPages := func(list retainedList) {
		seen := map[string]bool{}
		tokens := map[string]bool{}
		var token *string
		for {
			ids, next, e := list.api.page(1, token)
			must(e)
			check(len(ids) <= 1, "IP list pagination ignored maximum")
			for _, id := range ids {
				check(!seen[id], "IP list pagination duplicated child")
				seen[id] = true
			}
			if next == nil || aws.ToString(next) == "" {
				break
			}
			check(!tokens[*next], "IP list pagination repeated token")
			tokens[*next] = true
			token = next
		}
		check(len(seen) == len(list.ids), "IP list inventory count changed")
		for _, id := range list.ids {
			check(seen[id], "IP list inventory lost child")
		}
	}
	for _, list := range retained {
		verifyPages(list)
		foundPolicy := false
		for policy := range rolePolicies() {
			out, e := roles.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: roleName, PolicyName: &policy})
			must(e)
			document, e := url.QueryUnescape(aws.ToString(out.PolicyDocument))
			must(e)
			if strings.Contains(document, "arn:aws:s3:::"+bucket+"/"+list.key) && strings.Contains(document, "s3:GetObject") {
				foundPolicy = true
			}
		}
		check(foundPolicy, "activation did not persist real SLR object-read policy")
	}
	return func() {
		for _, list := range retained {
			verifyPages(list)
			state, e := list.api.get(list.ids[0])
			must(e)
			check(state.status == "ACTIVE" && state.name == list.name && state.location == list.location && state.owner == account && state.tags["owner"] == "ip-list-reader", "restart lost active IP list state")
			_, extra := state.tags["extra"]
			check(!extra, "restart restored removed child tag")
			must(list.api.update(list.ids[0], nil, nil, nil, aws.Bool(true)))
			for _, id := range list.ids {
				must(list.api.remove(id))
				deleted, e := list.api.get(id)
				must(e)
				check(deleted.status == "DELETED" && len(deleted.tags) == 0, "list deletion did not retain a cleared tombstone")
				ipListError(list.api.remove(id), "BadRequestException")
			}
			left, _, e := list.api.page(50, nil)
			must(e)
			check(len(left) == 0, "IP list cleanup left child resources")
			_, e = objects.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &list.key})
			must(e)
		}
		policies := rolePolicies()
		check(len(policies) == len(originalPolicies), "IP list cleanup leaked owned role policies")
		for policy := range originalPolicies {
			check(policies[policy], "IP list cleanup removed unrelated role policy")
		}
		_, e := objects.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
		must(e)
		_, e = roles.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: name, PolicyName: policyName})
		must(e)
		_, e = roles.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: name, AccessKeyId: key.AccessKey.AccessKeyId})
		must(e)
		_, e = roles.DeleteUser(ctx, &iam.DeleteUserInput{UserName: name})
		must(e)
		fmt.Println("GuardDuty signed IP/threat list S3 activation, current IAM denial, child tags, quotas/pagination, SQLite restart and cleanup: PASS (address membership is not exposed by Get APIs)")
	}
}
