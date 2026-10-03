package integrations

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/resourcegroups"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
	"stackd/internal/services/s3"
	"stackd/internal/services/sqs"
	"stackd/internal/services/ssm"
	"stackd/storage"
)

// AppRegistryResources admits only live S3 buckets, SQS queues, SSM parameters
// and CloudFormation stacks. Identity and tags remain authoritative at the owner.
// Tagging is the existing command adapter, using these same coordinated Backends.
type AppRegistryResources struct {
	Backends *storage.Backends
	Tagging  *ResourceTaggingResources
}

var _ resourcegroups.ApplicationResources = AppRegistryResources{}

func (r AppRegistryResources) ready() error {
	if r.Backends == nil || r.Backends.Read == nil || r.Backends.S3 == nil || r.Backends.SQS == nil || r.Backends.SSM == nil || r.Backends.CloudFormation == nil {
		return fmt.Errorf("application resources require coordinated owner storage")
	}
	return nil
}

func applicationBucket(v s3.BucketRecord, tags []s3.Tag) resourcegroups.ApplicationResource {
	return resourcegroups.ApplicationResource{ARN: v.Key.ARN(), Type: "AWS::S3::Bucket", Name: v.Key.Name, Incarnation: v.Incarnation, Tags: resourceTaggingS3Tags(tags)}
}
func applicationQueue(v sqs.QueueRecord) resourcegroups.ApplicationResource {
	var tags map[string]string
	if len(v.Tags) != 0 {
		tags = make(map[string]string, len(v.Tags))
		for _, tag := range v.Tags {
			tags[tag.Key] = tag.Value
		}
	}
	return resourcegroups.ApplicationResource{ARN: "arn:" + v.Key.Partition + ":sqs:" + v.Key.Region + ":" + v.Key.Account + ":" + v.Key.Name, Type: "AWS::SQS::Queue", Name: v.Key.Name, Incarnation: v.ID, Tags: tags}
}
func applicationParameter(v ssm.ParameterRecord) resourcegroups.ApplicationResource {
	return resourcegroups.ApplicationResource{ARN: v.ARN, Type: "AWS::SSM::Parameter", Name: v.Key.Name, Incarnation: v.Incarnation, Tags: v.Tags}
}
func applicationStack(v cloudformation.StackRecord) resourcegroups.ApplicationResource {
	return resourcegroups.ApplicationResource{ARN: v.ID, Type: "AWS::CloudFormation::Stack", Name: v.Name, Incarnation: v.ID, Tags: v.Tags, TaggingPending: strings.HasSuffix(v.Status, "_IN_PROGRESS")}
}

func (r AppRegistryResources) Resolve(ctx context.Context, identifier string) (resourcegroups.ApplicationResource, bool, error) {
	if err := r.ready(); err != nil {
		return resourcegroups.ApplicationResource{}, false, err
	}
	var result resourcegroups.ApplicationResource
	err := r.Backends.Read(ctx, func(ctx context.Context) error {
		var err error
		result, err = r.resolve(ctx, identifier)
		return err
	})
	if errors.Is(err, s3.ErrNotFound) || errors.Is(err, sqs.ErrNotFound) || errors.Is(err, ssm.ErrNotFound) || errors.Is(err, cloudformation.ErrNotFound) {
		return resourcegroups.ApplicationResource{}, false, nil
	}
	return result, err == nil && result.ARN != "" && result.Incarnation != "", err
}

func (r AppRegistryResources) resolve(ctx context.Context, identifier string) (resourcegroups.ApplicationResource, error) {
	m := awsctx.FromContext(ctx)
	var out resourcegroups.ApplicationResource
	parsed, err := arn.Parse(identifier)
	if err != nil {
		if identifier == "" || strings.Contains(identifier, ":") {
			return out, nil
		}
		err = r.Backends.CloudFormation.View(ctx, func(tx cloudformation.Reader) error {
			rows, err := tx.Stacks(cloudformation.Scope{Partition: m.Partition, Account: m.AccountID, Region: m.Region})
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Name == identifier && row.Deleted == nil && row.Status != "DELETE_COMPLETE" {
					out = applicationStack(row)
					break
				}
			}
			return nil
		})
		return out, err
	}
	if parsed.Partition != m.Partition {
		return out, nil
	}
	if parsed.Service == "s3" {
		if parsed.Region != "" || parsed.AccountID != "" || parsed.Resource == "" || strings.ContainsAny(parsed.Resource, "/:") {
			return out, nil
		}
		err = r.Backends.S3.View(ctx, func(tx s3.Reader) error {
			row, err := tx.Bucket(s3.BucketKey{Partition: m.Partition, Name: parsed.Resource})
			if err != nil {
				return err
			}
			if row.AccountID != m.AccountID || row.Region != m.Region {
				return nil
			}
			tags, err := tx.BucketTags(row.Key)
			if err != nil {
				return err
			}
			out = applicationBucket(row, tags)
			return nil
		})
		return out, err
	}
	if parsed.AccountID != m.AccountID || parsed.Region != m.Region {
		return out, nil
	}
	switch parsed.Service {
	case "sqs":
		if parsed.Resource == "" || strings.ContainsAny(parsed.Resource, "/:") {
			return out, nil
		}
		err = r.Backends.SQS.View(ctx, func(tx sqs.Reader) error {
			row, err := tx.Queue(sqs.QueueKey{Partition: m.Partition, Account: m.AccountID, Region: m.Region, Name: parsed.Resource})
			if err == nil {
				out = applicationQueue(row)
			}
			return err
		})
	case "ssm":
		name, ok := strings.CutPrefix(parsed.Resource, "parameter/")
		if !ok || name == "" {
			return out, nil
		}
		err = r.Backends.SSM.View(ctx, func(tx ssm.Reader) error {
			key := ssm.ParameterKey{Scope: ssm.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, Name: "/" + name}
			row, err := tx.Parameter(key)
			if errors.Is(err, ssm.ErrNotFound) && !strings.Contains(name, "/") {
				key.Name = name
				row, err = tx.Parameter(key)
			}
			if err == nil && row.CurrentVersion > 0 && row.ARN == identifier {
				out = applicationParameter(row)
			}
			return err
		})
	case "cloudformation":
		if !strings.HasPrefix(parsed.Resource, "stack/") {
			return out, nil
		}
		err = r.Backends.CloudFormation.View(ctx, func(tx cloudformation.Reader) error {
			row, err := tx.Stack(identifier)
			if err == nil && row.Scope == (cloudformation.Scope{Partition: m.Partition, Account: m.AccountID, Region: m.Region}) && row.Deleted == nil && row.Status != "DELETE_COMPLETE" {
				out = applicationStack(row)
			}
			return err
		})
	}
	return out, err
}

func (r AppRegistryResources) List(ctx context.Context) ([]resourcegroups.ApplicationResource, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	m := awsctx.FromContext(ctx)
	var out []resourcegroups.ApplicationResource
	appendLive := func(row resourcegroups.ApplicationResource) {
		if row.Incarnation != "" {
			out = append(out, row)
		}
	}
	err := r.Backends.Read(ctx, func(ctx context.Context) error {
		if err := r.Backends.S3.View(ctx, func(tx s3.Reader) error {
			rows, err := tx.Buckets(m.Partition, m.AccountID)
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Region != m.Region {
					continue
				}
				tags, err := tx.BucketTags(row.Key)
				if err != nil {
					return err
				}
				appendLive(applicationBucket(row, tags))
			}
			return nil
		}); err != nil {
			return err
		}
		if err := r.Backends.SQS.View(ctx, func(tx sqs.Reader) error {
			rows, err := tx.Queues()
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Key.Partition == m.Partition && row.Key.Account == m.AccountID && row.Key.Region == m.Region {
					appendLive(applicationQueue(row))
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if err := r.Backends.SSM.View(ctx, func(tx ssm.Reader) error {
			rows, err := tx.Parameters(ssm.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region})
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.CurrentVersion > 0 {
					appendLive(applicationParameter(row))
				}
			}
			return nil
		}); err != nil {
			return err
		}
		return r.Backends.CloudFormation.View(ctx, func(tx cloudformation.Reader) error {
			rows, err := tx.Stacks(cloudformation.Scope{Partition: m.Partition, Account: m.AccountID, Region: m.Region})
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Deleted == nil && row.Status != "DELETE_COMPLETE" {
					appendLive(applicationStack(row))
				}
			}
			return nil
		})
	})
	slices.SortFunc(out, func(a, b resourcegroups.ApplicationResource) int { return strings.Compare(a.ARN, b.ARN) })
	return out, err
}

func (r AppRegistryResources) StackResources(ctx context.Context, identifier string) (resourcegroups.ApplicationResource, []resourcegroups.ApplicationResource, error) {
	if err := r.ready(); err != nil {
		return resourcegroups.ApplicationResource{}, nil, err
	}
	var stack resourcegroups.ApplicationResource
	var resources []resourcegroups.ApplicationResource
	err := r.Backends.Read(ctx, func(ctx context.Context) error {
		var found bool
		var err error
		stack, found, err = r.Resolve(ctx, identifier)
		if err != nil {
			return err
		}
		if !found || stack.Type != "AWS::CloudFormation::Stack" {
			return &awswire.Error{Code: "ResourceNotFoundException", Message: "The live CloudFormation stack does not exist.", StatusCode: 404}
		}
		// Reuse the existing current/deployment-token ownership fence. Its broader
		// candidate inventory cannot admit an owner absent from Resolve's allowlist.
		inventory := ResourceTaggingResources{Backends: r.Backends}
		if r.Tagging != nil {
			inventory = *r.Tagging
			inventory.Backends = r.Backends
		}
		current, err := (ResourceGroupsResources{Tagging: inventory}).Stack(ctx, stack.ARN)
		if err != nil {
			return err
		}
		for _, candidate := range current.Resources {
			row, found, err := r.Resolve(ctx, candidate.ARN)
			if err != nil {
				return err
			}
			if !found {
				return &awswire.Error{Code: "NotImplementedException", Message: "Application tagging does not support this current stack resource owner: " + candidate.Type, StatusCode: 501}
			}
			resources = append(resources, row)
		}
		return nil
	})
	return stack, resources, err
}

func (r AppRegistryResources) Tag(ctx context.Context, resource resourcegroups.ApplicationResource, tags map[string]string) error {
	return r.mutate(ctx, resource, tags, nil, false)
}
func (r AppRegistryResources) Untag(ctx context.Context, resource resourcegroups.ApplicationResource, keys []string) error {
	return r.mutate(ctx, resource, nil, keys, true)
}
func (r AppRegistryResources) mutate(ctx context.Context, requested resourcegroups.ApplicationResource, tags map[string]string, keys []string, remove bool) error {
	if err := r.ready(); err != nil {
		return err
	}
	if r.Tagging == nil || r.Tagging.Backends != r.Backends {
		return fmt.Errorf("application tagging requires the existing coordinated tagging command adapter")
	}
	apply := func(ctx context.Context) error {
		current, found, err := r.Resolve(ctx, requested.ARN)
		if err != nil {
			return err
		}
		if !found || current.ARN != requested.ARN || current.Type != requested.Type || current.Incarnation != requested.Incarnation {
			return &awswire.Error{Code: "ResourceNotFoundException", Message: "The requested resource incarnation is no longer current.", StatusCode: 404}
		}
		native := tagging.Resource{ARN: current.ARN}
		if remove {
			return r.Tagging.Untag(ctx, native, keys)
		}
		return r.Tagging.Tag(ctx, native, tags)
	}
	// The fence and ordinary native command share the owner's write transaction.
	switch requested.Type {
	case "AWS::S3::Bucket":
		return r.Backends.S3.Update(ctx, func(tx s3.Transaction) error { return apply(tx.Context()) })
	case "AWS::SQS::Queue":
		return r.Backends.SQS.Update(ctx, func(tx sqs.Transaction) error { return apply(tx.Context()) })
	case "AWS::SSM::Parameter":
		return r.Backends.SSM.Update(ctx, func(tx ssm.Transaction) error { return apply(tx.Context()) })
	case "AWS::CloudFormation::Stack":
		return r.Backends.CloudFormation.Update(ctx, func(tx cloudformation.Transaction) error { return apply(tx.Context()) })
	default:
		return resourceTaggingUnsupported(tagging.Resource{ARN: requested.ARN})
	}
}
