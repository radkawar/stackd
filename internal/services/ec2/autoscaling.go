package ec2

import (
	"context"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const autoScalingGroupTag = "aws:autoscaling:groupName"

// SetAutoScalingGroup is an internal membership command, never a public tag
// exception. sourceGroupARN is the current immutable ASG incarnation. groupARN
// must equal that source to attach, or be empty to detach. The destination still
// checks the current linked role's ordinary CreateTags authority; invoking-service
// metadata and source routing do not replace IAM authorization.
func (s *Service) SetAutoScalingGroup(ctx context.Context, instanceID, sourceGroupARN, groupARN string) error {
	name, err := autoScalingGroupSource(ctx, sourceGroupARN)
	if err != nil {
		return err
	}
	if groupARN != "" && groupARN != sourceGroupARN {
		return failure("InvalidParameterValue", "The membership target must equal the current Auto Scaling group ARN.")
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		instance, err := loadInstance(ctx, tx, instanceID)
		if err != nil {
			return err
		}
		conditions := map[string][]string{"aws:TagKeys": {autoScalingGroupTag}}
		if groupARN != "" {
			conditions["aws:RequestTag/"+autoScalingGroupTag] = []string{name}
		}
		if err := s.authorizeWith(ctx, "CreateTags", "instance", instanceID, instance.Data.Tags, conditions); err != nil {
			return err
		}
		index := slices.IndexFunc(instance.Data.Tags, func(tag api.Tag) bool { return str(tag.Key) == autoScalingGroupTag })
		if index >= 0 && str(instance.Data.Tags[index].Value) != name {
			return failure("IncorrectState", "The instance belongs to a different Auto Scaling group.")
		}
		if groupARN == "" {
			if index < 0 {
				return nil
			}
			instance.Data.Tags = slices.Delete(instance.Data.Tags, index, index+1)
		} else {
			if index >= 0 {
				return nil
			}
			instance.Data.Tags = append(instance.Data.Tags, api.Tag{Key: new(api.String(autoScalingGroupTag)), Value: new(api.String(name))})
			slices.SortFunc(instance.Data.Tags, func(a, b api.Tag) int { return strings.Compare(str(a.Key), str(b.Key)) })
		}
		return tx.PutInstance(instance)
	})
}

func autoScalingGroupSource(ctx context.Context, sourceGroupARN string) (string, error) {
	m := awsctx.FromContext(ctx)
	role := "arn:" + m.Partition + ":iam::" + m.AccountID + ":role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
	if m.Partition == "" || m.AccountID == "" || m.Region == "" || m.InvokedBy != "autoscaling.amazonaws.com" || m.ServicePrincipal.Name != "" || (m.IssuerARN != role && !strings.HasPrefix(m.IssuerARN, role+"_")) {
		return "", failure("AuthFailure", "Auto Scaling membership requires the Auto Scaling service-linked role.")
	}
	source, err := arn.Parse(sourceGroupARN)
	if err != nil || source.Partition != m.Partition || source.AccountID != m.AccountID || source.Region != m.Region || source.Service != "autoscaling" {
		return "", failure("InvalidParameterValue", "The Auto Scaling group must belong to the current account and Region.")
	}
	resource, ok := strings.CutPrefix(source.Resource, "autoScalingGroup:")
	incarnation, name, valid := strings.Cut(resource, ":autoScalingGroupName/")
	if !ok || !valid || incarnation == "" || name == "" || strings.Contains(incarnation, ":") {
		return "", failure("InvalidParameterValue", "A current Auto Scaling group ARN is required.")
	}
	return name, nil
}

type autoScalingLaunchGroupKey struct{}

// RunAutoScalingInstance enters the ordinary native RunInstances command and
// audit boundary. Its owner-private marker adds the group tag before the first
// instance commit, so guest boot/IMDS cannot race a later membership tagging call.
func (s *Service) RunAutoScalingInstance(ctx context.Context, sourceGroupARN string, input *api.RunInstancesRequest) (*api.Reservation, *awswire.Error) {
	model, _ := awscatalog.LookupService("ec2")
	op, _ := model.Operation("RunInstances")
	request := awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input}
	name, err := autoScalingGroupSource(ctx, sourceGroupARN)
	if err != nil {
		rejected := wireError(err)
		if err := s.RecordRequestError(ctx, request, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
	out, rejected := s.ExecuteCommand(context.WithValue(ctx, autoScalingLaunchGroupKey{}, name), request)
	if rejected != nil {
		return nil, rejected
	}
	result, ok := out.(*api.Reservation)
	if !ok {
		return nil, failure("InternalError", "Invalid EC2 RunInstances result.")
	}
	return result, nil
}

// ValidateAutoScalingWarmPool is a trusted configuration read after the ASG
// owner has authorized PutWarmPool. It does not launch, reserve, assume a role,
// or manufacture a RunInstances request/audit event for a zero-sized pool.
func (s *Service) ValidateAutoScalingWarmPool(ctx context.Context, spec *api.LaunchTemplateSpecification) *awswire.Error {
	if spec == nil {
		return failure("MissingParameter", "A launch template is required for a hibernated warm pool.")
	}
	if s.instanceVolumes == nil || s.instanceTypes == nil {
		return unsupported("An EBS owner and instance-type catalog are required.")
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		template, err := selectLaunchTemplate(ctx, tx, str(spec.LaunchTemplateId), str(spec.LaunchTemplateName))
		if err != nil {
			return err
		}
		version, err := selectLaunchTemplateVersion(tx, template, str(spec.Version))
		if err != nil {
			return err
		}
		launch := api.LaunchTemplateConvertRequestLaunchTemplateDataToRunInstancesRequest(version.Data)
		image, err := resolveLaunchImage(ctx, tx, str(launch.ImageId))
		if err != nil {
			return err
		}
		typ, err := s.instanceTypes.ResolveInstanceType(ctx, api.InstanceType(str(launch.InstanceType)))
		if err != nil {
			return err
		}
		// Launch-template EBS mappings have no AvailabilityZone fields. This
		// read resolves snapshot/default encryption without network admission.
		plan, err := s.instanceVolumes.PlanInstanceVolumes(ctx, image.Data, launch.BlockDeviceMappings, AvailabilityZone{})
		if err != nil {
			return err
		}
		return admitInstanceHibernation(image.Data, typ, plan)
	})
	if err != nil {
		return wireError(err)
	}
	return nil
}

type autoScalingTerminationGroupKey struct{}

// TerminateAutoScalingInstance uses the ordinary EC2 command and audit boundary.
// Its private marker exempts only this group's instances from API termination
// protection; current TerminateInstances IAM authorization still applies.
func (s *Service) TerminateAutoScalingInstance(ctx context.Context, sourceGroupARN string, input *api.TerminateInstancesRequest) (*api.TerminateInstancesResult, *awswire.Error) {
	model, _ := awscatalog.LookupService("ec2")
	op, _ := model.Operation("TerminateInstances")
	request := awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input}
	name, err := autoScalingGroupSource(ctx, sourceGroupARN)
	if err != nil {
		rejected := wireError(err)
		if err := s.RecordRequestError(ctx, request, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
	out, rejected := s.ExecuteCommand(context.WithValue(ctx, autoScalingTerminationGroupKey{}, name), request)
	if rejected != nil {
		return nil, rejected
	}
	result, ok := out.(*api.TerminateInstancesResult)
	if !ok {
		return nil, failure("InternalError", "Invalid EC2 TerminateInstances result.")
	}
	return result, nil
}

func (s *Service) autoScalingInstanceTags(ctx context.Context, id string, tags api.TagList) (api.TagList, error) {
	name, managed := ctx.Value(autoScalingLaunchGroupKey{}).(string)
	if !managed {
		return tags, nil
	}
	if err := s.authorizeWith(ctx, "CreateTags", "instance", id, tags, map[string][]string{
		"aws:TagKeys": {autoScalingGroupTag}, "aws:RequestTag/" + autoScalingGroupTag: {name},
	}); err != nil {
		return nil, err
	}
	return append(tags, api.Tag{Key: new(api.String(autoScalingGroupTag)), Value: new(api.String(name))}), nil
}
