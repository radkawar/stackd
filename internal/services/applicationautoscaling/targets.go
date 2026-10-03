package applicationautoscaling

import (
	"context"
	"errors"
	"maps"
	"time"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/applicationautoscaling"
)

func (s *Service) registerScalableTarget(ctx context.Context, tx Transaction, in *api.RegisterScalableTargetInput) (*api.RegisterScalableTargetOutput, error) {
	key, err := keyFor(ctx, value(in.ServiceNamespace), value(in.ResourceId), value(in.ScalableDimension))
	if err != nil {
		return nil, err
	}
	if err := validateRoleARN(in.RoleARN); err != nil {
		return nil, err
	}
	if in.Tags != nil {
		if err := validateTags(in.Tags); err != nil {
			return nil, err
		}
	}
	principal, roleARN := LinkedRole(key)
	target, err := tx.Target(key)
	creating := errors.Is(err, ErrNotFound)
	if err != nil && !creating {
		return nil, err
	}
	if creating {
		if in.MinCapacity == nil {
			return nil, invalid("Minimum capacity must be specified")
		}
		if in.MaxCapacity == nil {
			return nil, invalid("Maximum capacity must be specified")
		}
		target = TargetRecord{ID: uuid.NewString(), Key: key}
		target.Data = api.ScalableTarget{
			CreationTime:      new(s.clock.Now().UTC().Truncate(time.Millisecond)),
			ResourceId:        new(api.ResourceIdMaxLen1600(key.ResourceID)),
			ServiceNamespace:  new(api.ServiceNamespace(key.Namespace)),
			ScalableDimension: new(api.ScalableDimension(key.Dimension)),
			ScalableTargetARN: new(api.XmlString(targetARN(key, target.ID))),
			RoleARN:           new(api.ResourceIdMaxLen1600(roleARN)),
			SuspendedState: &api.SuspendedState{
				DynamicScalingInSuspended:  new(api.ScalingSuspended(false)),
				DynamicScalingOutSuspended: new(api.ScalingSuspended(false)),
				ScheduledScalingSuspended:  new(api.ScalingSuspended(false)),
			},
		}
	} else {
		target.Data = api.CloneScalableTarget(target.Data)
	}
	conditions := targetConditions(key, target.Tags)
	if in.Tags != nil {
		requestTagConditions(conditions, in.Tags)
	}
	if err := s.authorize(ctx, "RegisterScalableTarget", value(target.Data.ScalableTargetARN), conditions); err != nil {
		return nil, err
	}
	// The service uses its own linked role without iam:PassRole. Supplying
	// another DynamoDB role still requires the caller's pass-role authority.
	if key.Namespace == "dynamodb" && in.RoleARN != nil && value(in.RoleARN) != roleARN {
		now := s.clock.Now()
		if err := s.authorizer.Authorize(ctx, authorization.Request{
			Action: "iam:PassRole", ResourceARN: value(in.RoleARN),
			Context: map[string][]string{"iam:PassedToService": {"application-autoscaling.amazonaws.com"}}, EvaluationTime: &now,
		}); err != nil {
			return nil, err
		}
	}
	if !creating && in.Tags != nil {
		return nil, invalid("The scalable target that you tried to tag already exists. To update tags on an existing scalable target, use the TagResource API.")
	}
	if creating && in.Tags != nil {
		target.Tags = maps.Clone(in.Tags)
	}
	if in.MinCapacity != nil {
		target.Data.MinCapacity = new(*in.MinCapacity)
	}
	if in.MaxCapacity != nil {
		target.Data.MaxCapacity = new(*in.MaxCapacity)
	}
	if *target.Data.MinCapacity < 0 {
		return nil, invalid("Minimum capacity cannot be less than 0")
	}
	if key.Namespace == "dynamodb" && *target.Data.MinCapacity < 1 {
		return nil, invalid("Minimum capacity must be at least 1 for DynamoDB")
	}
	if *target.Data.MaxCapacity < *target.Data.MinCapacity {
		return nil, invalid("Maximum capacity cannot be less than minimum capacity")
	}
	if s.resources == nil || s.roles == nil {
		return nil, unsupported("Scalable targets require resources and service-linked role integration")
	}
	if err := s.roles.EnsureServiceLinkedRole(ctx, principal); err != nil {
		return nil, err
	}
	capacity, err := s.resources.Admit(forwardedCaller(ctx), key)
	if errors.Is(err, ErrNotFound) {
		return nil, missingResource(key)
	}
	if err != nil {
		return nil, err
	}
	if in.SuspendedState != nil {
		current := target.Data.SuspendedState
		if current.ScheduledScalingSuspended != nil && bool(*current.ScheduledScalingSuspended) &&
			in.SuspendedState.ScheduledScalingSuspended != nil && !bool(*in.SuspendedState.ScheduledScalingSuspended) {
			if err := s.skipSuspendedSchedules(tx, key, s.clock.Now()); err != nil {
				return nil, err
			}
		}
		mergeSuspendedState(current, in.SuspendedState)
	}
	// The request accepts bounds; only the asynchronous reconciler changes resource
	// capacity. One local clock tick exposes the accepted state, not a claim
	// about AWS's nondeterministic reconciliation latency.
	target.ReconcileAt = time.Time{}
	if capacity.Desired < int32(*target.Data.MinCapacity) || capacity.Desired > int32(*target.Data.MaxCapacity) {
		target.ReconcileAt = s.clock.Now().Add(time.Second)
		target.OriginEventID = apievents.EventID(ctx)
	}
	if err := tx.PutTarget(target); err != nil {
		return nil, err
	}
	return &api.RegisterScalableTargetOutput{ScalableTargetARN: new(*target.Data.ScalableTargetARN)}, nil
}

func mergeSuspendedState(current, update *api.SuspendedState) {
	if update.DynamicScalingInSuspended != nil {
		current.DynamicScalingInSuspended = new(*update.DynamicScalingInSuspended)
	}
	if update.DynamicScalingOutSuspended != nil {
		current.DynamicScalingOutSuspended = new(*update.DynamicScalingOutSuspended)
	}
	if update.ScheduledScalingSuspended != nil {
		current.ScheduledScalingSuspended = new(*update.ScheduledScalingSuspended)
	}
}

func (s *Service) describeScalableTargets(ctx context.Context, tx Transaction, in *api.DescribeScalableTargetsInput) (*api.DescribeScalableTargetsOutput, error) {
	namespace, dimension := value(in.ServiceNamespace), value(in.ScalableDimension)
	if err := validateTargetFilter(namespace, dimension); err != nil {
		return nil, err
	}
	query := TargetQuery{Scope: scopeFor(ctx), Namespace: namespace, Dimension: dimension}
	if dimension != "" && len(in.ResourceIds) == 0 {
		return nil, invalid("ResourceIds must be specified when ScalableDimension is specified")
	}
	for _, resource := range in.ResourceIds {
		if !validResource(namespace, string(resource), dimension) {
			return nil, invalid("Unsupported service namespace, resource type or scalable dimension")
		}
		query.ResourceIDs = append(query.ResourceIDs, string(resource))
	}
	page, err := newListPage[ListCursor](listPageQuery{Operation: "DescribeScalableTargets", Key: TargetKey{Scope: query.Scope, Namespace: namespace, Dimension: dimension}, Resources: query.ResourceIDs}, in.MaxResults, in.NextToken)
	if err != nil {
		return nil, err
	}
	query.Limit, query.From = page.readLimit, page.token.Cursor
	// Describe actions support neither resource ARNs nor service-specific IAM
	// condition keys in the AWS service authorization reference.
	if err := s.authorize(ctx, "DescribeScalableTargets", "*", nil); err != nil {
		return nil, err
	}
	out := &api.DescribeScalableTargetsOutput{ScalableTargets: api.ScalableTargets{}}
	if page.limit == 0 {
		return out, nil
	}
	// Repositories filter and order by resource ID, then scalable dimension.
	targets, err := tx.Targets(query)
	if err != nil {
		return nil, err
	}
	if len(targets) > page.limit {
		out.NextToken = page.next(listCursor(targets[page.limit].Key, ""))
		targets = targets[:page.limit]
	}
	for _, target := range targets {
		out.ScalableTargets = append(out.ScalableTargets, target.Data)
	}
	return out, nil
}

func (s *Service) deregisterScalableTarget(ctx context.Context, tx Transaction, in *api.DeregisterScalableTargetInput) (*api.DeregisterScalableTargetOutput, error) {
	key, err := keyFor(ctx, value(in.ServiceNamespace), value(in.ResourceId), value(in.ScalableDimension))
	if err != nil {
		return nil, err
	}
	target, err := s.requireTarget(ctx, tx, key, "DeregisterScalableTarget")
	if err != nil {
		return nil, err
	}
	if err := s.removeTarget(ctx, tx, target); err != nil {
		return nil, err
	}
	return &api.DeregisterScalableTargetOutput{}, nil
}
