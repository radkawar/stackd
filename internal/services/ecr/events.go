package ecr

import (
	"context"
	"encoding/json"
	"time"
)

// Event is a native aws.ecr EventBridge notification. The publisher admits it
// in the same transaction as the corresponding image state change.
type Event struct {
	ID         string
	Scope      Scope
	DetailType string
	Resources  []string
	Detail     []byte
	At         time.Time
}

// EventPublisher joins the repository transaction carried by ctx. It must not
// perform external delivery before that transaction commits.
type EventPublisher interface {
	PublishEvent(context.Context, Event) error
}

func (s *Service) publishEvent(ctx context.Context, scope Scope, detailType string, resources []string, detail any) error {
	if s.events == nil {
		return nil
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	return s.events.PublishEvent(ctx, Event{ID: identifier(), Scope: scope, DetailType: detailType, Resources: resources, Detail: body, At: s.clock.Now()})
}

type imageActionDetail struct {
	Result         string `json:"result"`
	RepositoryName string `json:"repository-name"`
	ImageDigest    string `json:"image-digest"`
	ActionType     string `json:"action-type"`
	ImageTag       string `json:"image-tag,omitempty"`
}

func (s *Service) publishImageAction(ctx context.Context, key ImageKey, action, tag string) error {
	return s.publishEvent(ctx, key.Repository.Scope, "ECR Image Action", []string{}, imageActionDetail{
		Result: "SUCCESS", RepositoryName: key.Repository.Name, ImageDigest: key.Digest, ActionType: action, ImageTag: tag,
	})
}

type replicationActionDetail struct {
	Result         string `json:"result"`
	RepositoryName string `json:"repository-name"`
	ImageDigest    string `json:"image-digest"`
	SourceAccount  string `json:"source-account"`
	ActionType     string `json:"action-type"`
	SourceRegion   string `json:"source-region"`
	ImageTag       string `json:"image-tag,omitempty"`
}

func (s *Service) publishReplicationAction(ctx context.Context, source Scope, image ImageRecord, tag string) error {
	return s.publishEvent(ctx, image.Key.Repository.Scope, "ECR Replication Action", []string{repositoryARN(image.Key.Repository)}, replicationActionDetail{
		Result: "SUCCESS", RepositoryName: image.Key.Repository.Name, ImageDigest: image.Key.Digest,
		SourceAccount: source.AccountID, ActionType: "REPLICATE", SourceRegion: source.Region, ImageTag: tag,
	})
}
