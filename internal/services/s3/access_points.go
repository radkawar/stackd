package s3

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/s3control"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func accessPointName(name string) *awswire.Error {
	if len(name) < 3 || len(name) > 50 {
		return failure("InvalidURI", "Couldn't parse the specified URI.", 400)
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return failure("InvalidURI", "Couldn't parse the specified URI.", 400)
		}
	}
	if strings.Contains(name, ".") || name[0] == '-' || name[len(name)-1] == '-' || strings.HasSuffix(name, "-s3alias") {
		return failure("InvalidRequest", "Your Amazon S3 AccessPoint name is invalid", 400)
	}
	return nil
}

func accessPointNetworkOrigin(point AccessPointRecord) string {
	if point.VPCID != "" {
		return "VPC"
	}
	return "Internet"
}

func (p *Control) authorizeAccessPoint(reader Reader, point AccessPointRecord, action string, requested []Tag, tagKeys []string) error {
	m := awsctx.FromContext(reader.Context())
	if point.Key.AccountID != m.AccountID {
		return denied()
	}
	conditions := map[string][]string{
		"s3:ResourceAccount":          {point.Key.AccountID},
		"s3:AccessPointNetworkOrigin": {accessPointNetworkOrigin(point)},
		"s3:DataAccessPointArn":       {point.Key.ARN()},
		"s3:DataAccessPointAccount":   {point.Key.AccountID},
	}
	if action != "CreateAccessPoint" && point.Alias != "" {
		tags, err := reader.AccessPointTags(point.Key)
		if err != nil {
			return err
		}
		for _, tag := range tags {
			conditions["aws:ResourceTag/"+tag.Key] = []string{tag.Value}
			conditions["s3:AccessPointTag/"+tag.Key] = []string{tag.Value}
		}
	}
	addRequestTagConditions(conditions, requested, tagKeys)
	if action == "CreateAccessPoint" {
		conditions["s3:locationconstraint"] = []string{point.Key.Region}
	}
	resource := point.Key.ARN()
	// GetAccessPoint is account-scoped in the IAM action catalog, unlike
	// the policy, tagging, create and delete controls.
	if action == "GetAccessPoint" {
		resource = "*"
	}
	if wire := p.s.authorizer.Authorize(reader.Context(), authorization.Request{
		Action: "s3:" + action, ResourceARN: resource, ResourceAccountID: point.Key.AccountID, Context: conditions,
	}); wire != nil {
		return wire
	}
	return nil
}

func (p *Control) controlAccessPoint(reader Reader, account, name string, alias bool) (AccessPointRecord, error) {
	m := awsctx.FromContext(reader.Context())
	if !alias || !strings.HasSuffix(name, "-s3alias") {
		if wire := accessPointName(name); wire != nil {
			return AccessPointRecord{}, wire
		}
	}
	if account != m.AccountID {
		return AccessPointRecord{}, denied()
	}
	var point AccessPointRecord
	var err error
	if alias && strings.HasSuffix(name, "-s3alias") {
		point, err = reader.AccessPointAlias(m.Partition, name)
		if err == nil && (point.Key.AccountID != account || point.Key.Region != m.Region) {
			err = ErrNotFound
		}
	} else {
		point, err = reader.AccessPoint(AccessPointKey{Partition: m.Partition, AccountID: account, Region: m.Region, Name: name})
	}
	if errors.Is(err, ErrNotFound) {
		return AccessPointRecord{}, failure("NoSuchAccessPoint", "The specified accesspoint does not exist", 404)
	}
	if err != nil {
		return point, err
	}
	if wire := checkAccessPointOwner(reader.Context(), point); wire != nil {
		return AccessPointRecord{}, wire
	}
	return point, nil
}

func (p *Control) createAccessPoint(ctx context.Context, in *api.CreateAccessPointInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "CreateAccessPoint")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		m := awsctx.FromContext(tx.Context())
		point := AccessPointRecord{Key: AccessPointKey{Partition: m.Partition, AccountID: value(in.AccountId), Region: m.Region, Name: value(in.Name)}, PublicAccess: PublicAccessBlock{true, true, true, true}}
		if w := accessPointName(point.Key.Name); w != nil {
			return w
		}
		if in.Scope != nil {
			return failure("InvalidRequest", "Scope is only supported for access points attached to directory buckets.", 400)
		}
		if in.VpcConfiguration != nil {
			point.VPCID = value(in.VpcConfiguration.VpcId)
			if point.VPCID == "" {
				return failure("InvalidRequest", "Request invalid", 400)
			}
		}
		tags, err := controlTags(in.Tags)
		if err != nil {
			return err
		}
		if err := p.authorizeAccessPoint(tx, point, "CreateAccessPoint", tags, nil); err != nil {
			return err
		}
		if len(tags) != 0 {
			if err := p.authorizeAccessPoint(tx, point, "TagResource", tags, nil); err != nil {
				return err
			}
		}
		claim, claimed := cloudFormationOwner(tx.Context(), cloudFormationAccessPoint)
		if claimed {
			// The exact incarnation that committed this access point recovers
			// it unchanged, even if its bucket changed since; names and tags
			// never prove ownership.
			if existing, err := tx.AccessPoint(point.Key); err == nil && existing.CloudFormationOwner == claim {
				return response.prepare(c, &api.CreateAccessPointOutput{AccessPointArn: new(api.S3AccessPointArn(existing.Key.ARN())), Alias: new(api.Alias(existing.Alias))})
			} else if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		point.Bucket = BucketKey{Partition: m.Partition, Name: value(in.Bucket)}
		bucket, err := tx.Bucket(point.Bucket)
		if errors.Is(err, ErrNotFound) {
			return failure("InvalidRequest", "Amazon S3 AccessPoint can only be created for existing bucket", 400)
		}
		if err != nil {
			return err
		}
		if bucket.Region != point.Key.Region {
			return failure("InvalidRequest", "Amazon S3 AccessPoint can only be created for bucket in the same region", 400)
		}
		owner := value(in.BucketAccountId)
		if owner == "" {
			owner = point.Key.AccountID
		}
		if !publicPolicyFixedAccount(owner) {
			return failure("InvalidRequest", "Request invalid", 400)
		}
		if owner != bucket.AccountID {
			return failure("InvalidRequest", "BucketAccountId parameter should be same as the AWS Account Id of bucket owner", 400)
		}
		point.BucketAccountID = owner
		if _, err := tx.AccessPoint(point.Key); err == nil {
			return failure("AccessPointAlreadyOwnedByYou", "Your previous request to create the named accesspoint succeeded and you already own it.", 409)
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		point.CloudFormationOwner = claim
		count, err := tx.AccessPointCount(m.Partition, point.Key.AccountID, m.Region)
		if err != nil {
			return err
		}
		if count >= 10000 {
			return failure("TooManyAccessPoints", "You have attempted to create more access points than allowed.", 400)
		}
		if block := in.PublicAccessBlockConfiguration; block != nil {
			point.PublicAccess = PublicAccessBlock{BlockPublicACLs: publicAccessSetting(block.BlockPublicAcls), IgnorePublicACLs: publicAccessSetting(block.IgnorePublicAcls), BlockPublicPolicy: publicAccessSetting(block.BlockPublicPolicy), RestrictPublicBuckets: publicAccessSetting(block.RestrictPublicBuckets)}
		}
		var nonce [20]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		point.Alias = point.Key.Name[:min(len(point.Key.Name), 22)] + "-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(nonce[:])) + "-s3alias"
		point.Created = p.s.clock.Now().UTC().Truncate(time.Second)
		if err := tx.PutAccessPoint(point); err != nil {
			return err
		}
		if err := tx.PutAccessPointTags(point.Key, tags); err != nil {
			return err
		}
		return response.prepare(c, &api.CreateAccessPointOutput{AccessPointArn: new(api.S3AccessPointArn(point.Key.ARN())), Alias: new(api.Alias(point.Alias))})
	})
	return response, wire
}

func accessPointSummary(point AccessPointRecord) api.AccessPoint {
	out := api.AccessPoint{Name: new(api.AccessPointName(point.Key.Name)), AccessPointArn: new(api.S3AccessPointArn(point.Key.ARN())), Alias: new(api.Alias(point.Alias)), Bucket: new(api.AccessPointBucketName(point.Bucket.Name)), BucketAccountId: new(api.AccountId(point.BucketAccountID)), NetworkOrigin: new(api.NetworkOrigin(accessPointNetworkOrigin(point)))}
	if point.VPCID != "" {
		out.VpcConfiguration = &api.VpcConfiguration{VpcId: new(api.VpcId(point.VPCID))}
	}
	return out
}

func (p *Control) getAccessPoint(ctx context.Context, in *api.GetAccessPointInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "GetAccessPoint")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		point, err := p.controlAccessPoint(tx, value(in.AccountId), value(in.Name), true)
		if err != nil {
			return err
		}
		if err := p.authorizeAccessPoint(tx, point, "GetAccessPoint", nil, nil); err != nil {
			return err
		}
		summary := accessPointSummary(point)
		domain := s3RegionDomain(point.Key.Partition, point.Key.Region)
		return response.prepare(c, &api.GetAccessPointOutput{Name: summary.Name, AccessPointArn: summary.AccessPointArn, Alias: summary.Alias, Bucket: summary.Bucket, BucketAccountId: summary.BucketAccountId, NetworkOrigin: summary.NetworkOrigin, VpcConfiguration: summary.VpcConfiguration, CreationDate: &point.Created,
			PublicAccessBlockConfiguration: &api.PublicAccessBlockConfiguration{BlockPublicAcls: new(api.Setting(point.PublicAccess.BlockPublicACLs)), IgnorePublicAcls: new(api.Setting(point.PublicAccess.IgnorePublicACLs)), BlockPublicPolicy: new(api.Setting(point.PublicAccess.BlockPublicPolicy)), RestrictPublicBuckets: new(api.Setting(point.PublicAccess.RestrictPublicBuckets))},
			Endpoints:                      api.Endpoints{"ipv4": api.NonEmptyMaxLength1024String("s3-accesspoint." + domain), "fips": api.NonEmptyMaxLength1024String("s3-accesspoint-fips." + domain), "dualstack": api.NonEmptyMaxLength1024String("s3-accesspoint.dualstack." + domain), "fips_dualstack": api.NonEmptyMaxLength1024String("s3-accesspoint-fips.dualstack." + domain)},
		})
	})
	return response, wire
}

func (p *Control) deleteAccessPoint(ctx context.Context, in *api.DeleteAccessPointInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "DeleteAccessPoint")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		point, err := p.controlAccessPoint(tx, value(in.AccountId), value(in.Name), false)
		if err != nil {
			return err
		}
		if err := p.authorizeAccessPoint(tx, point, "DeleteAccessPoint", nil, nil); err != nil {
			return err
		}
		if err := tx.DeleteAccessPoint(point.Key); err != nil {
			return err
		}
		return response.prepare(c, &api.DeleteAccessPointOutput{})
	})
	return response, wire
}

type accessPointCursor struct{ Partition, AccountID, Region, Bucket, DataSourceType, After string }

func (p *Control) listAccessPoints(ctx context.Context, in *api.ListAccessPointsInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "ListAccessPoints")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		account := value(in.AccountId)
		m := awsctx.FromContext(tx.Context())
		if account != m.AccountID {
			return denied()
		}
		if w := p.s.authorizer.Authorize(tx.Context(), authorization.Request{
			Action: "s3:ListAccessPoints", ResourceARN: "*", ResourceAccountID: account,
			Context: map[string][]string{"s3:ResourceAccount": {account}},
		}); w != nil {
			return w
		}
		kind := value(in.DataSourceType)
		if in.DataSourceId != nil {
			if kind == "S3" {
				return failure("InvalidRequest", "DataSourceType must not be S3 if DataSourceId is provided", 400)
			}
			return unsupported("Non-S3 access point data sources are not implemented.")
		}
		if kind != "" && kind != "S3" && kind != "ALL" {
			return unsupported("Non-S3 access point data sources are not implemented.")
		}
		bucketName := value(in.Bucket)
		if bucketName != "" {
			bucket, err := tx.Bucket(BucketKey{Partition: m.Partition, Name: bucketName})
			if errors.Is(err, ErrNotFound) {
				return failure("InvalidRequest", "No access point attached to this bucket", 400)
			}
			if err != nil {
				return err
			}
			if bucket.Region != m.Region {
				return failure("InvalidRequest", "Amazon S3 AccessPoint can only be listed for bucket in the same region", 400)
			}
		}
		limit := 1000
		if in.MaxResults != nil {
			if *in.MaxResults > 0 {
				limit = int(*in.MaxResults)
			}
		}
		cursor := accessPointCursor{Partition: m.Partition, AccountID: account, Region: m.Region, Bucket: bucketName, DataSourceType: kind}
		if token := value(in.NextToken); token != "" {
			data, err := base64.RawURLEncoding.DecodeString(token)
			var previous accessPointCursor
			if err != nil || json.Unmarshal(data, &previous) != nil || previous.After == "" {
				return failure("InvalidRequest", "Invalid nextToken", 400)
			}
			cursor.After = previous.After
			if previous != cursor {
				return failure("InvalidRequest", "Invalid nextToken", 400)
			}
		}
		points, err := tx.AccessPoints(AccessPointQuery{Partition: m.Partition, AccountID: account, Region: m.Region, Bucket: bucketName, After: cursor.After, Limit: limit + 1})
		if err != nil {
			return err
		}
		out := &api.ListAccessPointsOutput{AccessPointList: make(api.AccessPointList, 0, min(len(points), limit))}
		if len(points) > limit {
			points = points[:limit]
			cursor.After = points[len(points)-1].Key.Name
			data, err := json.Marshal(cursor)
			if err != nil {
				return err
			}
			out.NextToken = new(api.NonEmptyMaxLength1024String(base64.RawURLEncoding.EncodeToString(data)))
		}
		for _, point := range points {
			summary := accessPointSummary(point)
			if kind != "" {
				summary.DataSourceType = new(api.DataSourceType("S3"))
			}
			out.AccessPointList = append(out.AccessPointList, summary)
		}
		return response.prepare(c, out)
	})
	return response, wire
}
