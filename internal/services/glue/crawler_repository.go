package glue

import (
	"context"
	"time"

	api "stackd/internal/awsapi/glue"
)

// CrawlerSource delegates execution-role admission and every data request to the
// current IAM/S3 owners. Implementations must not use the crawler creator's identity.
// Validate only enters metadata commands and joins control transactions. Actual
// source object reads and native connections run outside repository transactions.
type CrawlerSource interface {
	Validate(context.Context, Scope, string, string, api.CrawlerTargets) error
	RoleContext(context.Context, Scope, string, string) (context.Context, error)
	List(context.Context, string, string, string) (CrawlerObjectPage, error)
	Read(context.Context, string, string) ([]byte, error)
}

type CrawlerObject struct {
	Key  string
	Size int64
}

type CrawlerObjectPage struct {
	Objects   []CrawlerObject
	NextToken string
}

type CrawlerRecord struct {
	CFNOwner      string
	Key           ResourceKey
	Crawler       api.Crawler
	Tags          map[string]string
	RunID         string
	NextScheduled *time.Time
}

// CrawlRecord retains the execution claim separately from the AWS public state.
// A running claim is replayed after controller restart; publication is idempotent
// through ordinary catalog commands, not through an alternate catalog store.
type CrawlRecord struct {
	ID                string
	Crawler           ResourceKey
	State             string
	Phase             string
	Started           time.Time
	Completed         *time.Time
	ErrorMessage      string
	TablesCreated     int64
	TablesUpdated     int64
	PartitionsCreated int64
	ParentEventID     string
	TriggerName       string
	WorkflowName      string
	WorkflowRunID     string
}

type CrawlersReader interface {
	Crawler(ResourceKey) (CrawlerRecord, error)
	Crawlers(Scope) ([]CrawlerRecord, error)
	ScheduledCrawlers() ([]CrawlerRecord, error)
	Crawl(string) (CrawlRecord, error)
	Crawls(ResourceKey) ([]CrawlRecord, error)
	PendingCrawls() ([]CrawlRecord, error)
	Classifier(ResourceKey) (ClassifierRecord, error)
	Classifiers(Scope) ([]ClassifierRecord, error)
	Connection(ResourceKey) (ConnectionRecord, error)
	Connections(Scope) ([]ConnectionRecord, error)
	ConnectionEncryption(Scope) (ConnectionEncryptionRecord, error)
}

type CrawlersWriter interface {
	PutCrawler(CrawlerRecord) error
	DeleteCrawler(ResourceKey) error
	PutCrawl(CrawlRecord) error
	PutClassifier(ClassifierRecord) error
	DeleteClassifier(ResourceKey) error
	PutConnection(ConnectionRecord) error
	DeleteConnection(ResourceKey) error
	PutConnectionEncryption(ConnectionEncryptionRecord) error
	DeleteConnectionEncryption(Scope) error
}
