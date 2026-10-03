package integrations

import (
	"context"
	"errors"
	"math"

	"stackd/internal/services/athena"
	"stackd/internal/services/cloudtrail"
	"stackd/internal/services/cloudwatch"
	"stackd/internal/services/codebuild"
	"stackd/internal/services/dynamodb"
	"stackd/internal/services/ecr"
	"stackd/internal/services/firehose"
	"stackd/internal/services/kinesis"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
	"stackd/internal/services/xray"
)

func (r ResourceTaggingResources) listTaggingDynamoDB(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.DynamoDB.View(ctx, func(tx dynamodb.Reader) error {
		rows, err := tx.Tables(dynamodb.TableQuery{Scope: dynamodb.Scope(scope), Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, row := range rows {
			record, err := tx.Tags(row.Key)
			if err != nil && !errors.Is(err, dynamodb.ErrNotFound) {
				return err
			}
			var tags map[string]string
			if len(record.Tags) != 0 {
				tags = make(map[string]string, len(record.Tags))
				for _, tag := range record.Tags {
					tags[resourceTaggingText(tag.Key)] = resourceTaggingText(tag.Value)
				}
			}
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "dynamodb:table", Tags: tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingKinesis(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.Kinesis.View(ctx, func(tx kinesis.Reader) error {
		sc := kinesis.Scope(scope)
		appendResource := func(arn, kind string) error {
			record, err := tx.Tags(kinesis.ResourceKey{Scope: sc, ARN: arn})
			if err != nil && !errors.Is(err, kinesis.ErrNotFound) {
				return err
			}
			var tags map[string]string
			if len(record.Tags) != 0 {
				tags = make(map[string]string, len(record.Tags))
				for _, tag := range record.Tags {
					tags[resourceTaggingText(tag.Key)] = resourceTaggingText(tag.Value)
				}
			}
			out = append(out, tagging.Resource{ARN: arn, ResourceType: "kinesis:" + kind, Tags: tags})
			return nil
		}
		streams, err := tx.Streams(kinesis.StreamQuery{Scope: sc, Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, row := range streams {
			if err := appendResource(row.Key.ARN(), "stream"); err != nil {
				return err
			}
			consumers, err := tx.Consumers(row.Key)
			if err != nil {
				return err
			}
			for _, consumer := range consumers {
				if err := appendResource(consumer.Key.ARN(), "stream/consumer"); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingFirehose(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.Firehose.View(ctx, func(tx firehose.Reader) error {
		rows, err := tx.Streams(firehose.StreamQuery{Scope: firehose.Scope(scope), Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "firehose:deliverystream", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingCloudWatch(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.CloudWatch.View(ctx, func(tx cloudwatch.Reader) error {
		rows, err := tx.Alarms(cloudwatch.AlarmQuery{Scope: cloudwatch.Scope(scope), Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "cloudwatch:alarm", Tags: row.Tags})
		}
		dashboards, err := tx.Dashboards(cloudwatch.DashboardQuery{Partition: scope.Partition, AccountID: scope.AccountID, Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, entry := range dashboards {
			row, err := tx.Dashboard(entry.Key)
			if err != nil {
				return err
			}
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "cloudwatch:dashboard", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingCloudTrail(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.CloudTrail.View(ctx, func(tx cloudtrail.Reader) error {
		rows, err := tx.Trails(scope.Partition, scope.AccountID)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Key.Region != scope.Region {
				continue
			}
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "cloudtrail:trail", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingXRay(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.XRay.View(ctx, func(tx xray.Reader) error {
		groups, err := tx.Groups(xray.Scope(scope))
		if err != nil {
			return err
		}
		hasDefaultGroup := false
		for _, row := range groups {
			hasDefaultGroup = hasDefaultGroup || row.Key.Name == "Default"
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "xray:group", Tags: row.Tags})
		}
		if !hasDefaultGroup {
			out = append(out, tagging.Resource{ARN: (xray.GroupKey{Scope: xray.Scope(scope), Name: "Default"}).ARN(), ResourceType: "xray:group"})
		}
		rules, err := tx.SamplingRules(xray.Scope(scope))
		if err != nil {
			return err
		}
		hasDefaultRule := false
		for _, row := range rules {
			hasDefaultRule = hasDefaultRule || row.Key.Name == "Default"
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "xray:sampling-rule", Tags: row.Tags})
		}
		if !hasDefaultRule {
			out = append(out, tagging.Resource{ARN: (xray.SamplingRuleKey{Scope: xray.Scope(scope), Name: "Default"}).ARN(), ResourceType: "xray:sampling-rule"})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingECR(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.ECR.View(ctx, func(tx ecr.Reader) error {
		rows, err := tx.Repositories(ecr.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, tagging.Resource{ARN: row.ARN, ResourceType: "ecr:repository", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingCodeBuild(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.CodeBuild.View(ctx, func(tx codebuild.Reader) error {
		projects, err := tx.Projects(codebuild.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range projects {
			var tags map[string]string
			if len(row.Data.Tags) != 0 {
				tags = make(map[string]string, len(row.Data.Tags))
				for _, tag := range row.Data.Tags {
					tags[resourceTaggingText(tag.Key)] = resourceTaggingText(tag.Value)
				}
			}
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "codebuild:project", Tags: tags})
		}
		fleets, err := tx.Fleets(codebuild.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range fleets {
			var tags map[string]string
			if len(row.Data.Tags) != 0 {
				tags = make(map[string]string, len(row.Data.Tags))
				for _, tag := range row.Data.Tags {
					tags[resourceTaggingText(tag.Key)] = resourceTaggingText(tag.Value)
				}
			}
			out = append(out, tagging.Resource{ARN: resourceTaggingText(row.Data.Arn), ResourceType: "codebuild:fleet", Tags: tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingAthena(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.Athena.View(ctx, func(tx athena.Reader) error {
		query := athena.ResourceQuery{Scope: athena.Scope(scope), Limit: math.MaxInt}
		groups, err := tx.WorkGroups(query)
		if err != nil {
			return err
		}
		hasPrimary := false
		for _, row := range groups {
			hasPrimary = hasPrimary || row.Key.Name == "primary"
			out = append(out, tagging.Resource{ARN: row.Key.ARN("workgroup"), ResourceType: "athena:workgroup", Tags: row.Tags})
		}
		if !hasPrimary {
			out = append(out, tagging.Resource{ARN: (athena.ResourceKey{Scope: athena.Scope(scope), Name: "primary"}).ARN("workgroup"), ResourceType: "athena:workgroup"})
		}
		catalogs, err := tx.Catalogs(query)
		if err != nil {
			return err
		}
		hasDefaultCatalog := false
		for _, row := range catalogs {
			hasDefaultCatalog = hasDefaultCatalog || row.Key.Name == "AwsDataCatalog"
			out = append(out, tagging.Resource{ARN: row.Key.ARN("datacatalog"), ResourceType: "athena:datacatalog", Tags: row.Tags})
		}
		if !hasDefaultCatalog {
			out = append(out, tagging.Resource{ARN: (athena.ResourceKey{Scope: athena.Scope(scope), Name: "AwsDataCatalog"}).ARN("datacatalog"), ResourceType: "athena:datacatalog"})
		}
		return nil
	})
	return
}
