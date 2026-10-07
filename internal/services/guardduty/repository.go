// Package guardduty owns regional detector intent and retained security findings.
package guardduty

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/guardduty"
	"stackd/journal"
)

var ErrNotFound = errors.New("GuardDuty resource not found")

type Scope struct{ Partition, AccountID, Region string }
type Detector struct {
	CFNOwnership CloudFormationOwnership
	Scope
	ID, ARN, Status, Frequency, ServiceRole string
	ClientToken                             string
	Created, Updated                        time.Time
	Features                                []Feature
	Tags                                    map[string]string
}
type Feature struct {
	Name, Status string
	Updated      time.Time
	Additional   []AdditionalFeature
}
type AdditionalFeature struct {
	Name, Status string
	Updated      time.Time
}

// Finding retains either immutable sample identity or typed observed evidence.
// Observations never use the fictional resource details in the sample corpus.
type Finding struct {
	Scope
	DetectorID, ID, SampleType, SampleRevision string
	Created, Updated                           time.Time
	Count                                      int64
	Archived                                   bool
	Feedback                                   string
	LastPublished, PublishDue                  time.Time
	Suppressed                                 bool
	Observation                                Observation
}

// Observation is evidence from an actual API outcome, not a sample template.
// Empty Type identifies a sample finding. No credentials or arbitrary API
// documents are retained here.
type Observation struct {
	Type, Title, Description                        string
	Severity                                        float64
	EventID, AccessKeyID, PrincipalID, UserName     string
	UserType, API, ServiceName, SourceIP, ErrorCode string
	FeatureName                                     string
	ResourceType, ResourceName, ResourceARN         string
	ThreatListNames                                 []string
	Kubernetes                                      *journal.KubernetesAuditObserved
}
type Filter struct {
	CFNOwnership CloudFormationOwnership
	Scope
	DetectorID, Name, ARN, Action, Description string
	ClientToken                                string
	DescriptionSet                             bool
	Rank, Version                              int32
	Created, Updated                           time.Time
	Criteria                                   api.FindingCriteria
	Tags                                       map[string]string
}

type Reader interface {
	Context() context.Context
	Detector(Scope, string) (Detector, error)
	AllDetectors() ([]Detector, error)
	Finding(Scope, string, string) (Finding, error)
	Findings(Scope, string) ([]Finding, error)
	Filter(Scope, string, string) (Filter, error)
	Filters(Scope, string) ([]Filter, error)
	IPList(Scope, string, IPListKind, string) (IPList, error)
	IPLists(Scope, string) ([]IPList, error)
	// MatchingIPLists returns ACTIVE lists whose retained ranges contain the
	// IPv4 address, without copying or loading every list's range snapshot.
	MatchingIPLists(Scope, string, uint32) ([]IPList, error)
	PublishingDestination(Scope, string, string) (PublishingDestination, error)
	PublishingDestinations(Scope, string) ([]PublishingDestination, error)
	FindingExport(Scope, string, string, string) (FindingExport, error)
	FindingExports(Scope, string, string) ([]FindingExport, error)
	// NextFindingExport returns the earliest nonzero deadline, ordered by finding
	// ID on ties, or ErrNotFound when no publication is pending.
	NextFindingExport(Scope, string, string) (FindingExportDeadline, error)
}
type Transaction interface {
	Reader
	PutDetector(Detector) error
	DeleteDetector(Scope, string) error
	PutFinding(Finding) error
	DeleteFinding(Scope, string, string) error
	PutFilter(Filter) error
	DeleteFilter(Scope, string, string) error
	PutIPList(IPList) error
	DeleteIPList(Scope, string, IPListKind, string) error
	ReplaceIPRanges(Scope, string, IPListKind, string, []IPRange) error
	PutPublishingDestination(PublishingDestination) error
	DeletePublishingDestination(Scope, string, string) error
	PutFindingExport(FindingExport) error
	DeleteFindingExport(Scope, string, string, string) error
	DeleteDestinationExports(Scope, string, string) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
