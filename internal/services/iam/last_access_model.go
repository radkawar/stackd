package iam

import "time"

// AccessReport freezes the accepted report snapshot. CompletedAt controls when
// the asynchronous result becomes available. Activity windows apply when the
// snapshot is created; later passage of time does not rewrite its contents.
// Owner is an IAM user ID or a temporary credential ID; assumed-role sessions
// with the same session name still own distinct jobs.
type AccessReport struct {
	ID           string
	Owner        string
	Granularity  string
	RequestedAt  time.Time
	CompletedAt  *time.Time
	Services     []ServiceAccess
	Organization *OrganizationAccessReport
}

// OrganizationAccessReport holds an SCP report's account-level aggregation.
// Its presence distinguishes Organizations jobs from identity-policy jobs.
type OrganizationAccessReport struct {
	EntityPath string
	PolicyID   string
	Services   []OrganizationServiceAccess
	Error      *AccessReportError
}

// AccessReportError is a completed job's failure, rather than an API error.
type AccessReportError struct {
	Code    string
	Message string
}

// OrganizationServiceAccess counts accounts, regardless of how many identities
// in each account attempted the service. No principal information is exposed.
type OrganizationServiceAccess struct {
	Namespace             string
	Name                  string
	AuthenticatedAccounts int
	LastActivity          *AccountActivity
}

type AccountActivity struct {
	EntityPath        string
	Region            string
	LastAuthenticated time.Time
}

// ServiceAccess freezes the report subject's permissions and the activity of
// its associated identities. LastActivity is absent for a never-used service.
type ServiceAccess struct {
	Namespace    string
	Name         string
	LastActivity *PrincipalActivity
	Actions      []ActionAccess
	Entities     []EntityAccess
}

type ActionAccess struct {
	Name         string
	LastActivity *PrincipalActivity
}

// EntityAccess freezes membership and usage. Entity names and paths are resolved
// from the current IAM identity when reading the report.
type EntityAccess struct {
	ID           string
	LastActivity *PrincipalActivity
}
