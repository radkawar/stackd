package glue

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// CloudFormationOwner is trusted controller context, never customer API input.
// Ownership is committed on the native resource record in the creation transaction.
type cloudFormationOwner struct{ Kind, Incarnation string }
type cloudFormationOwnerKey struct{}

func WithCloudFormationOwner(ctx context.Context, kind, incarnation string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{kind, incarnation})
}

type cloudFormationTx struct {
	Transaction
	owner cloudFormationOwner
}

func cloudFormationTransaction(tx Transaction, ctx context.Context) Transaction {
	owner, _ := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if owner.Kind == "" {
		return tx
	}
	return cloudFormationTx{tx, owner}
}
func (t cloudFormationTx) check(kind, owner string) error {
	if t.owner.Kind == kind && (t.owner.Incarnation == "" || owner != t.owner.Incarnation) {
		return failure("AlreadyExistsException", "Resource is not owned by this CloudFormation incarnation.")
	}
	return nil
}
func (t cloudFormationTx) Table(key TableKey) (TableRecord, error) {
	v, err := t.Transaction.Table(key)
	if err == nil {
		err = t.check("Table", v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutTable(v TableRecord) error {
	old, err := t.Transaction.Table(v.Key)
	if err == nil {
		v.CFNOwner = old.CFNOwner
	} else if !errors.Is(err, ErrNotFound) {
		return err
	} else if t.owner.Kind == "Table" {
		v.CFNOwner = t.owner.Incarnation
	}
	return t.Transaction.PutTable(v)
}
func (t cloudFormationTx) Partition(key PartitionKey) (PartitionRecord, error) {
	v, err := t.Transaction.Partition(key)
	if err == nil {
		err = t.check("Partition", v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutPartition(v PartitionRecord) error {
	old, err := t.Transaction.Partition(v.Key)
	if err == nil {
		v.CFNOwner = old.CFNOwner
	} else if !errors.Is(err, ErrNotFound) {
		return err
	} else if t.owner.Kind == "Partition" {
		v.CFNOwner = t.owner.Incarnation
	}
	return t.Transaction.PutPartition(v)
}
func (t cloudFormationTx) Classifier(key ResourceKey) (ClassifierRecord, error) {
	v, err := t.Transaction.Classifier(key)
	if err == nil {
		err = t.check("Classifier", v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutClassifier(v ClassifierRecord) error {
	old, err := t.Transaction.Classifier(v.Key)
	if err == nil {
		v.CFNOwner = old.CFNOwner
	} else if !errors.Is(err, ErrNotFound) {
		return err
	} else if t.owner.Kind == "Classifier" {
		v.CFNOwner = t.owner.Incarnation
	}
	return t.Transaction.PutClassifier(v)
}
func (t cloudFormationTx) SecurityConfiguration(key ResourceKey) (SecurityConfigurationRecord, error) {
	v, err := t.Transaction.SecurityConfiguration(key)
	if err == nil {
		err = t.check("SecurityConfiguration", v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutSecurityConfiguration(v SecurityConfigurationRecord) error {
	old, err := t.Transaction.SecurityConfiguration(v.Key)
	if err == nil {
		v.CFNOwner = old.CFNOwner
	} else if !errors.Is(err, ErrNotFound) {
		return err
	} else if t.owner.Kind == "SecurityConfiguration" {
		v.CFNOwner = t.owner.Incarnation
	}
	return t.Transaction.PutSecurityConfiguration(v)
}
func (t cloudFormationTx) SchemaVersion(key SchemaVersionKey) (SchemaVersionRecord, error) {
	v, err := t.Transaction.SchemaVersion(key)
	if err == nil {
		err = t.check("SchemaVersion", v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutSchemaVersion(v SchemaVersionRecord) error {
	old, err := t.Transaction.SchemaVersion(v.Key)
	if err == nil {
		v.CFNOwner = old.CFNOwner
	} else if !errors.Is(err, ErrNotFound) {
		return err
	} else if t.owner.Kind == "SchemaVersion" {
		v.CFNOwner = t.owner.Incarnation
	}
	return t.Transaction.PutSchemaVersion(v)
}
func (t cloudFormationTx) SchemaVersionByID(scope Scope, id string) (SchemaVersionRecord, error) {
	v, err := t.Transaction.SchemaVersionByID(scope, id)
	if err == nil {
		err = t.check("SchemaVersion", v.CFNOwner)
	}
	return v, err
}
func CloudFormationMetadataOwnerKind(version, key, value string) string {
	return "SchemaVersionMetadata:" + version + ":" + strconv.Itoa(len(key)) + ":" + key + value
}
func (t cloudFormationTx) SchemaMetadata(id string) ([]SchemaMetadataRecord, error) {
	rows, err := t.Transaction.SchemaMetadata(id)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		if t.owner.Kind == CloudFormationMetadataOwnerKind(v.VersionID, v.Key, v.Value) {
			if err = t.check(t.owner.Kind, v.CFNOwner); err != nil {
				return nil, err
			}
		}
	}
	return rows, nil
}
func (t cloudFormationTx) PutSchemaMetadata(v SchemaMetadataRecord) error {
	rows, err := t.Transaction.SchemaMetadata(v.VersionID)
	if err != nil {
		return err
	}
	for _, old := range rows {
		if old.Key == v.Key && old.Value == v.Value {
			v.CFNOwner = old.CFNOwner
			return t.Transaction.PutSchemaMetadata(v)
		}
	}
	if t.owner.Kind == CloudFormationMetadataOwnerKind(v.VersionID, v.Key, v.Value) {
		v.CFNOwner = t.owner.Incarnation
	}
	return t.Transaction.PutSchemaMetadata(v)
}
func (t cloudFormationTx) ConnectionEncryption(scope Scope) (ConnectionEncryptionRecord, error) {
	v, err := t.Transaction.ConnectionEncryption(scope)
	if err == nil {
		kind := "ConnectionEncryption"
		if t.owner.Kind == "ConnectionEncryptionRelease" {
			kind = t.owner.Kind
		}
		err = t.check(kind, v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutConnectionEncryption(v ConnectionEncryptionRecord) error {
	old, err := t.Transaction.ConnectionEncryption(v.Scope)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if t.owner.Kind == "ConnectionEncryptionRelease" || t.owner.Kind == "ConnectionEncryptionDirectRelease" {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if t.owner.Kind == "ConnectionEncryptionRelease" {
			if err = t.check(t.owner.Kind, old.CFNOwner); err != nil {
				return err
			}
		}
		return t.Transaction.DeleteConnectionEncryption(v.Scope)
	}
	if err == nil {
		v.CFNOwner = old.CFNOwner
	} else if t.owner.Kind == "ConnectionEncryption" {
		v.CFNOwner = t.owner.Incarnation
	}
	return t.Transaction.PutConnectionEncryption(v)
}

// Tagged resources claim one exact native ARN, so other same-kind rows read by
// the command (parents, link targets, defaults) stay ordinary IAM-authorized reads.
// Public tags never participate; the claim is retained privately on the row.
func CloudFormationResourceClaim(scope Scope, kind, name string) string {
	return ResourceKey{Scope: scope, Name: name}.ARN(kind)
}
func CloudFormationCatalogClaim(scope Scope, catalogID string) string {
	return catalogKeyIn(scope, catalogID).ARN()
}
func CloudFormationDatabaseClaim(scope Scope, catalogID, name string) string {
	return DatabaseKey{CatalogKey: catalogKeyIn(scope, catalogID), Name: strings.ToLower(name)}.ARN()
}

// stamp retains an existing row's claim and stamps only a new row of the exact claimed ARN.
func (t cloudFormationTx) stamp(claim, old string, err error) (string, error) {
	if err == nil {
		return old, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return "", err
	}
	if t.owner.Kind == claim {
		return t.owner.Incarnation, nil
	}
	return "", nil
}
func absentOr(err error) error {
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
func (t cloudFormationTx) Catalog(key CatalogKey) (CatalogRecord, error) {
	v, err := t.Transaction.Catalog(key)
	if err == nil {
		err = t.check(key.ARN(), v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutCatalog(v CatalogRecord) error {
	old, err := t.Transaction.Catalog(v.Key)
	if v.CFNOwner, err = t.stamp(v.Key.ARN(), old.CFNOwner, err); err != nil {
		return err
	}
	return t.Transaction.PutCatalog(v)
}
func (t cloudFormationTx) DeleteCatalog(key CatalogKey) error {
	if _, err := t.Catalog(key); absentOr(err) != nil {
		return err
	}
	return t.Transaction.DeleteCatalog(key)
}
func (t cloudFormationTx) Database(key DatabaseKey) (DatabaseRecord, error) {
	v, err := t.Transaction.Database(key)
	if err == nil {
		err = t.check(key.ARN(), v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutDatabase(v DatabaseRecord) error {
	old, err := t.Transaction.Database(v.Key)
	if v.CFNOwner, err = t.stamp(v.Key.ARN(), old.CFNOwner, err); err != nil {
		return err
	}
	return t.Transaction.PutDatabase(v)
}
func (t cloudFormationTx) DeleteDatabase(key DatabaseKey) error {
	if _, err := t.Database(key); absentOr(err) != nil {
		return err
	}
	return t.Transaction.DeleteDatabase(key)
}
func (t cloudFormationTx) Connection(key ResourceKey) (ConnectionRecord, error) {
	v, err := t.Transaction.Connection(key)
	if err == nil {
		err = t.check(key.ARN("connection"), v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutConnection(v ConnectionRecord) error {
	old, err := t.Transaction.Connection(v.Key)
	if v.CFNOwner, err = t.stamp(v.Key.ARN("connection"), old.CFNOwner, err); err != nil {
		return err
	}
	return t.Transaction.PutConnection(v)
}
func (t cloudFormationTx) DeleteConnection(key ResourceKey) error {
	if _, err := t.Connection(key); absentOr(err) != nil {
		return err
	}
	return t.Transaction.DeleteConnection(key)
}
func (t cloudFormationTx) GetJob(key ResourceKey) (JobRecord, error) {
	v, err := t.Transaction.GetJob(key)
	if err == nil {
		err = t.check(key.ARN("job"), v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutJob(v JobRecord) error {
	old, err := t.Transaction.GetJob(v.Key)
	if v.CFNOwner, err = t.stamp(v.Key.ARN("job"), old.CFNOwner, err); err != nil {
		return err
	}
	return t.Transaction.PutJob(v)
}
func (t cloudFormationTx) DeleteJob(key ResourceKey) error {
	if _, err := t.GetJob(key); absentOr(err) != nil {
		return err
	}
	return t.Transaction.DeleteJob(key)
}
func (t cloudFormationTx) Crawler(key ResourceKey) (CrawlerRecord, error) {
	v, err := t.Transaction.Crawler(key)
	if err == nil {
		err = t.check(key.ARN("crawler"), v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutCrawler(v CrawlerRecord) error {
	old, err := t.Transaction.Crawler(v.Key)
	if v.CFNOwner, err = t.stamp(v.Key.ARN("crawler"), old.CFNOwner, err); err != nil {
		return err
	}
	return t.Transaction.PutCrawler(v)
}
func (t cloudFormationTx) DeleteCrawler(key ResourceKey) error {
	if _, err := t.Crawler(key); absentOr(err) != nil {
		return err
	}
	return t.Transaction.DeleteCrawler(key)
}
func (t cloudFormationTx) Registry(key ResourceKey) (RegistryRecord, error) {
	v, err := t.Transaction.Registry(key)
	if err == nil {
		err = t.check(key.ARN("registry"), v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutRegistry(v RegistryRecord) error {
	old, err := t.Transaction.Registry(v.Key)
	if v.CFNOwner, err = t.stamp(v.Key.ARN("registry"), old.CFNOwner, err); err != nil {
		return err
	}
	return t.Transaction.PutRegistry(v)
}
func (t cloudFormationTx) DeleteRegistry(key ResourceKey) error {
	if _, err := t.Registry(key); absentOr(err) != nil {
		return err
	}
	return t.Transaction.DeleteRegistry(key)
}
func (t cloudFormationTx) Schema(key SchemaKey) (SchemaRecord, error) {
	v, err := t.Transaction.Schema(key)
	if err == nil {
		err = t.check(key.ARN(), v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutSchema(v SchemaRecord) error {
	old, err := t.Transaction.Schema(v.Key)
	if v.CFNOwner, err = t.stamp(v.Key.ARN(), old.CFNOwner, err); err != nil {
		return err
	}
	return t.Transaction.PutSchema(v)
}
func (t cloudFormationTx) DeleteSchema(key SchemaKey) error {
	if _, err := t.Schema(key); absentOr(err) != nil {
		return err
	}
	return t.Transaction.DeleteSchema(key)
}
func (t cloudFormationTx) Workflow(key ResourceKey) (WorkflowRecord, error) {
	v, err := t.Transaction.Workflow(key)
	if err == nil {
		err = t.check(key.ARN("workflow"), v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutWorkflow(v WorkflowRecord) error {
	old, err := t.Transaction.Workflow(v.Key)
	if v.CFNOwner, err = t.stamp(v.Key.ARN("workflow"), old.CFNOwner, err); err != nil {
		return err
	}
	return t.Transaction.PutWorkflow(v)
}
func (t cloudFormationTx) DeleteWorkflow(key ResourceKey) error {
	if _, err := t.Workflow(key); absentOr(err) != nil {
		return err
	}
	return t.Transaction.DeleteWorkflow(key)
}
func (t cloudFormationTx) Trigger(key ResourceKey) (TriggerRecord, error) {
	v, err := t.Transaction.Trigger(key)
	if err == nil {
		err = t.check(key.ARN("trigger"), v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutTrigger(v TriggerRecord) error {
	old, err := t.Transaction.Trigger(v.Key)
	if v.CFNOwner, err = t.stamp(v.Key.ARN("trigger"), old.CFNOwner, err); err != nil {
		return err
	}
	return t.Transaction.PutTrigger(v)
}
func (t cloudFormationTx) DeleteTrigger(key ResourceKey) error {
	if _, err := t.Trigger(key); absentOr(err) != nil {
		return err
	}
	return t.Transaction.DeleteTrigger(key)
}
