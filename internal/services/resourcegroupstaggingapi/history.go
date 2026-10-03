package resourcegroupstaggingapi

import (
	"context"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awsctx"
	"stackd/journal"
)

type membershipRecorder struct {
	next       apievents.Recorder
	repository Repository
	resources  Resources
}

// NewRecorder joins native resource writes and inventory membership in the same
// transaction. It inspects only the completed management command's service, not
// the entire cloud, and never stores tag values or interprets request parameters.
func NewRecorder(next apievents.Recorder, repository Repository, resources Resources) apievents.Recorder {
	return membershipRecorder{next: next, repository: repository, resources: resources}
}
func (r membershipRecorder) Record(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	service := strings.TrimSuffix(call.EventSource, ".amazonaws.com")
	service = canonicalService(service)
	if r.repository != nil && r.resources != nil && call.Category == journal.CategoryManagement && !call.ReadOnly && call.ErrorCode == "" && service != "tagging" {
		if err := r.repository.Update(ctx, func(tx Transaction) error {
			// Paired cross-account records retain the resource owner's envelope scope.
			metadata := awsctx.FromContext(tx.Context())
			metadata.Partition, metadata.AccountID, metadata.Region = envelope.Partition, envelope.AccountID, envelope.Region
			ownerContext := awsctx.WithMetadata(tx.Context(), metadata)
			resources, err := r.resources.List(ownerContext, service)
			if err != nil {
				return err
			}
			return reconcile(tx, Scope{envelope.Partition, envelope.AccountID, envelope.Region}, service, resources)
		}); err != nil {
			return err
		}
	}
	if r.next != nil {
		return r.next.Record(ctx, envelope, call)
	}
	return nil
}
func canonicalService(service string) string {
	switch service {
	case "ebs":
		return "ec2"
	case "s3control":
		return "s3"
	case "cloudwatch":
		return "monitoring"
	case "email":
		return "ses"
	default:
		return service
	}
}
func reconcile(tx Transaction, scope Scope, service string, resources []Resource) error {
	previous, err := inventoryMemberships(tx, scope, service)
	if err != nil {
		return err
	}
	live := make(map[Membership]bool, len(resources))
	for _, resource := range resources {
		m := Membership{Scope: membershipScope(scope, resource), Service: service, ARN: resource.ARN}
		live[m] = len(resource.Tags) > 0
	}
	known := make(map[Membership]bool, len(previous))
	for _, membership := range previous {
		known[membership] = true
		if _, exists := live[membership]; !exists {
			if err := tx.DeleteMembership(membership); err != nil {
				return err
			}
		}
	}
	for m, tagged := range live {
		if tagged && !known[m] {
			if err := tx.PutMembership(m); err != nil {
				return err
			}
		}
	}
	return nil
}

// These owners are global even when their mutation is sent to a regional
// endpoint. S3 bucket ARNs also omit Region, but their owner is regional.
func membershipScope(scope Scope, resource Resource) Scope {
	p, err := parseARN(resource.ARN)
	if err == nil && p[3] == "" && (p[2] == "iam" || p[2] == "organizations" || p[2] == "cloudwatch") {
		scope.Region = ""
	}
	return scope
}

func inventoryMemberships(reader Reader, scope Scope, service string) ([]Membership, error) {
	rows, err := reader.Memberships(scope, service)
	if err != nil || scope.Region == "" {
		return rows, err
	}
	scope.Region = ""
	global, err := reader.Memberships(scope, service)
	if err != nil {
		return nil, err
	}
	return append(rows, global...), nil
}
