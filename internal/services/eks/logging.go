package eks

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"time"

	native "stackd/compute/eks"
	api "stackd/internal/awsapi/eks"
	"stackd/internal/awsctx"
)

var controlPlaneLogTypes = []string{"api", "audit", "authenticator", "controllerManager", "scheduler"}

// ControlPlaneLogs delegates ingestion and current execution-role authorization to Logs.
type ControlPlaneLogs interface {
	WriteControlPlaneLogs(context.Context, Cluster, []native.LogRecord) error
}

func mergeLogging(current []string, in *api.Logging) ([]string, error) {
	enabled := make(map[string]bool, len(controlPlaneLogTypes))
	for _, category := range current {
		enabled[category] = true
	}
	if in != nil {
		seen := make(map[string]bool)
		for _, setup := range in.ClusterLogging {
			if setup.Enabled == nil || len(setup.Types) == 0 {
				return nil, invalid("Each clusterLogging entry requires enabled and types.")
			}
			for _, category := range setup.Types {
				name := string(category)
				if !slices.Contains(controlPlaneLogTypes, name) {
					return nil, invalid("Invalid control plane log type.")
				}
				if seen[name] {
					return nil, invalid("A control plane log type cannot occur more than once.")
				}
				seen[name] = true
				enabled[name] = bool(*setup.Enabled)
			}
		}
	}
	result := make([]string, 0, len(enabled))
	for _, category := range controlPlaneLogTypes {
		if enabled[category] {
			result = append(result, category)
		}
	}
	return result, nil
}

func loggingAPI(enabled []string) *api.Logging {
	result := &api.Logging{}
	for _, active := range []bool{true, false} {
		setup := api.LogSetup{Enabled: new(api.BoxedBoolean(active))}
		for _, category := range controlPlaneLogTypes {
			if slices.Contains(enabled, category) == active {
				setup.Types = append(setup.Types, api.LogType(category))
			}
		}
		if len(setup.Types) != 0 {
			result.ClusterLogging = append(result.ClusterLogging, setup)
		}
	}
	return result
}

type clusterLogSink struct {
	service *Service
	key     Key
	id      string
}

func (s *Service) runtimeLogSink(c Cluster) native.LogSink { return clusterLogSink{s, c.Key, c.ID} }

func (sink clusterLogSink) PutControlPlaneLogs(ctx context.Context, id string, records []native.LogRecord) error {
	if id != sink.id {
		return errors.New("EKS log source incarnation mismatch")
	}
	var cluster Cluster
	err := sink.service.repository.View(ctx, func(tx Reader) error {
		var err error
		cluster, err = tx.Cluster(sink.key)
		if err != nil {
			return err
		}
		if cluster.ID != id || cluster.Status == "DELETING" {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return err
	}
	if sink.service.logs == nil {
		return errors.New("EKS CloudWatch Logs owner unavailable")
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: sink.key.Partition, AccountID: sink.key.AccountID, Region: sink.key.Region, InvokedBy: "eks.amazonaws.com", ServicePrincipal: awsctx.ServicePrincipal{Name: "eks.amazonaws.com", SourceARN: sink.key.ARN(), Type: "AWSService"}})
	return sink.service.logs.WriteControlPlaneLogs(ctx, cluster, records)
}

// logAuthentication records the actual IAM authenticator decision, never an API-server surrogate.
// Tokens and signatures are deliberately excluded. Kubernetes records mapped users itself
// in audit Event.impersonatedUser; that original record is not rewritten here.
func (s *Service) logAuthentication(ctx context.Context, key Key, id, principal string, identity native.Identity, rejected error) {
	var enabled bool
	err := s.repository.View(ctx, func(tx Reader) error {
		c, err := tx.Cluster(key)
		if err != nil {
			return err
		}
		enabled = c.ID == id && slices.Contains(c.EnabledLogTypes, "authenticator")
		return nil
	})
	if err != nil || !enabled {
		return
	}
	logger, ok := s.runtime.(interface {
		RecordAuthentication(context.Context, string, native.LogRecord) error
	})
	if !ok {
		return
	}
	event := struct {
		Time     time.Time `json:"time"`
		Message  string    `json:"msg"`
		ARN      string    `json:"arn,omitempty"`
		Username string    `json:"username,omitempty"`
		Groups   []string  `json:"groups,omitempty"`
		Error    string    `json:"error,omitempty"`
	}{Time: s.clock.Now().UTC(), Message: "access granted", ARN: principal, Username: identity.Username, Groups: identity.Groups}
	if rejected != nil {
		event.Message = "access denied"
		event.Error = rejected.Error()
	}
	body, err := json.Marshal(event)
	if err == nil {
		err = logger.RecordAuthentication(ctx, id, native.LogRecord{Category: "authenticator", Timestamp: event.Time, Message: string(body)})
	}
	if err != nil {
		slog.ErrorContext(ctx, "EKS authenticator log capture failed", "cluster", key.ARN(), "error", err)
	}
}
