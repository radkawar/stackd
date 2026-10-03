// Package s3 exposes service-owned S3 storage contracts.
package s3

import (
	domain "stackd/internal/services/s3"
	"stackd/storage/memory"
)

type (
	Repository                    = domain.Repository
	Reader                        = domain.Reader
	Transaction                   = domain.Transaction
	BucketKey                     = domain.BucketKey
	BucketRecord                  = domain.BucketRecord
	AccessPointKey                = domain.AccessPointKey
	AccessPointRecord             = domain.AccessPointRecord
	AccessPointQuery              = domain.AccessPointQuery
	Tag                           = domain.Tag
	ACLGrant                      = domain.ACLGrant
	AccessControlList             = domain.AccessControlList
	PublicAccessBlock             = domain.PublicAccessBlock
	CORSRule                      = domain.CORSRule
	WebsiteConfiguration          = domain.WebsiteConfiguration
	LoggingConfiguration          = domain.LoggingConfiguration
	AccessLogDelivery             = domain.AccessLogDelivery
	LifecycleConfiguration        = domain.LifecycleConfiguration
	LifecycleRule                 = domain.LifecycleRule
	ObjectFilter                  = domain.ObjectFilter
	LifecycleWhen                 = domain.LifecycleWhen
	LifecycleExpiration           = domain.LifecycleExpiration
	LifecycleTransition           = domain.LifecycleTransition
	LifecycleNoncurrentExpiration = domain.LifecycleNoncurrentExpiration
	LifecycleNoncurrentTransition = domain.LifecycleNoncurrentTransition
	BucketScan                    = domain.BucketScan
	AccessTier                    = domain.AccessTier
	ObjectTiering                 = domain.ObjectTiering
	TieringRule                   = domain.TieringRule
	TieringConfiguration          = domain.TieringConfiguration
	BucketConfigurationQuery      = domain.BucketConfigurationQuery
	RequestMetricsConfiguration   = domain.RequestMetricsConfiguration
	RequestMetricsFilter          = domain.RequestMetricsFilter
	InventoryConfiguration        = domain.InventoryConfiguration
	InventoryDestination          = domain.InventoryDestination
	InventoryReader               = domain.InventoryReader
	InventoryWriter               = domain.InventoryWriter
	AnalyticsConfiguration        = domain.AnalyticsConfiguration
	AnalyticsDestination          = domain.AnalyticsDestination
	ReplicationConfiguration      = domain.ReplicationConfiguration
	ReplicationRule               = domain.ReplicationRule
	ReplicationFilter             = domain.ReplicationFilter
	ReplicationDestination        = domain.ReplicationDestination
	ReplicationOperation          = domain.ReplicationOperation
	ReplicationState              = domain.ReplicationState
	ReplicationJob                = domain.ReplicationJob
	ReplicationMetricKey          = domain.ReplicationMetricKey
	ReplicationMetricPublication  = domain.ReplicationMetricPublication
	ReplicationPending            = domain.ReplicationPending
	WebsiteRedirectAll            = domain.WebsiteRedirectAll
	WebsiteRoutingRule            = domain.WebsiteRoutingRule
	WebsiteCondition              = domain.WebsiteCondition
	WebsiteRedirect               = domain.WebsiteRedirect
	ObjectKey                     = domain.ObjectKey
	ObjectVersionKey              = domain.ObjectVersionKey
	ObjectRecord                  = domain.ObjectRecord
	CustomerKeyVerifier           = domain.CustomerKeyVerifier
	RetentionPeriod               = domain.RetentionPeriod
	DefaultRetention              = domain.DefaultRetention
	ObjectRetention               = domain.ObjectRetention
	ObjectRestore                 = domain.ObjectRestore
	ObjectQuery                   = domain.ObjectQuery
	VersionQuery                  = domain.VersionQuery
	MultipartUploadKey            = domain.MultipartUploadKey
	MultipartUploadRecord         = domain.MultipartUploadRecord
	MultipartQuery                = domain.MultipartQuery
	PartRecord                    = domain.PartRecord
	NotificationProtocol          = domain.NotificationProtocol
	NotificationFilter            = domain.NotificationFilter
	NotificationRule              = domain.NotificationRule
	NotificationConfiguration     = domain.NotificationConfiguration
	NotificationState             = domain.NotificationState
	NotificationDelivery          = domain.NotificationDelivery
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }

func DefaultACL(partition, account string) *AccessControlList {
	return domain.DefaultACL(partition, account)
}
