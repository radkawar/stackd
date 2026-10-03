package stepfunctions

import (
	"errors"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/stepfunctions"
)

func (s *Service) createActivity(tx Transaction, in *api.CreateActivityInput) (*api.CreateActivityOutput, error) {
	name := value(in.Name)
	if !validResourceName(name) {
		return nil, failure("InvalidName", "Invalid activity name.", 400)
	}
	key := ActivityKey{Scope: scopeFor(tx.Context()), Name: name}
	tags, err := admitControlTags(in.Tags)
	if err != nil {
		return nil, err
	}
	previous, lookupErr := tx.Activity(key)
	if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		return nil, lookupErr
	}
	if denied := s.authorize(tx, "CreateActivity", key.ARN(), previous.Tags, requestTagConditions(tags, nil)); denied != nil {
		return nil, denied
	}
	config := EncryptionConfig{EncryptionType: "AWS_OWNED_KEY"}
	if err := s.admitEncryption(tx.Context(), &config, in.EncryptionConfiguration); err != nil {
		return nil, err
	}
	if lookupErr == nil {
		if previous.EncryptionConfig != config {
			return nil, failure("ActivityAlreadyExists", "Activity Already Exists: '"+key.ARN()+"'", 400)
		}
		return &api.CreateActivityOutput{ActivityArn: new(api.Arn(key.ARN())), CreationDate: controlTimestamp(previous.Created)}, nil
	}
	if denied := s.createTagAuthority(tx, key.ARN(), tags); denied != nil {
		return nil, denied
	}
	count, err := tx.ActivityCount(key.Scope)
	if err != nil {
		return nil, err
	}
	if count >= maxRegisteredActivities {
		return nil, failure("ActivityLimitExceeded", "The maximum number of registered activities has been reached.", 400)
	}
	activity := ActivityRecord{Key: key, ID: uuid.NewString(), Created: s.clock.Now().UTC(), Tags: tags, EncryptionConfig: config}
	if err := tx.PutActivity(activity); err != nil {
		return nil, err
	}
	return &api.CreateActivityOutput{ActivityArn: new(api.Arn(key.ARN())), CreationDate: controlTimestamp(activity.Created)}, nil
}

func (s *Service) controlActivity(r Reader, raw, action string) (ActivityRecord, error) {
	key, err := activityReference(raw)
	if err != nil {
		return ActivityRecord{}, err
	}
	activity := ActivityRecord{Key: key}
	lookupErr := ErrNotFound
	if key.Scope == scopeFor(r.Context()) {
		activity, lookupErr = r.Activity(key)
		if errors.Is(lookupErr, ErrNotFound) {
			activity.Key = key
		}
	}
	if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		return ActivityRecord{}, lookupErr
	}
	if denied := s.authorize(r, action, raw, activity.Tags, nil); denied != nil {
		return ActivityRecord{}, denied
	}
	if errors.Is(lookupErr, ErrNotFound) {
		return activity, failure("ActivityDoesNotExist", "Activity Does Not Exist: '"+raw+"'", 400)
	}
	return activity, nil
}

func (s *Service) deleteActivity(tx Transaction, in *api.DeleteActivityInput) (*api.DeleteActivityOutput, error) {
	activity, err := s.controlActivity(tx, value(in.ActivityArn), "DeleteActivity")
	if err != nil {
		if wireError(err).Code == "ActivityDoesNotExist" {
			return &api.DeleteActivityOutput{}, nil
		}
		return nil, err
	}
	if err := tx.DeleteActivity(activity.Key); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return &api.DeleteActivityOutput{}, nil
}

func (s *Service) describeActivity(tx Transaction, in *api.DescribeActivityInput) (*api.DescribeActivityOutput, error) {
	activity, err := s.controlActivity(tx, value(in.ActivityArn), "DescribeActivity")
	if err != nil {
		return nil, err
	}
	return &api.DescribeActivityOutput{ActivityArn: new(api.Arn(activity.Key.ARN())), CreationDate: controlTimestamp(activity.Created), Name: new(api.Name(activity.Key.Name)), EncryptionConfiguration: encryptionOutput(activity.EncryptionConfig)}, nil
}

func (s *Service) listActivities(tx Transaction, in *api.ListActivitiesInput) (*api.ListActivitiesOutput, error) {
	if denied := s.authorize(tx, "ListActivities", "*", nil, nil); denied != nil {
		return nil, denied
	}
	collection := controlCollection(tx, "ListActivities", "", "")
	now := s.clock.Now()
	limit, after, err := controlPage(in.NextToken, in.MaxResults, collection, now)
	if err != nil {
		return nil, err
	}
	activities, err := tx.Activities(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	out := &api.ListActivitiesOutput{Activities: api.ActivityList{}}
	for _, activity := range activities {
		if activity.Key.Name <= after {
			continue
		}
		if len(out.Activities) == limit {
			out.NextToken = controlNext(collection, after, now)
			break
		}
		out.Activities = append(out.Activities, api.ActivityListItem{ActivityArn: new(api.Arn(activity.Key.ARN())), CreationDate: controlTimestamp(activity.Created), Name: new(api.Name(activity.Key.Name))})
		after = activity.Key.Name
	}
	return out, nil
}
