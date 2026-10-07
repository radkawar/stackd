package glue

import (
	"cmp"
	"context"
	"maps"
	"slices"
	api "stackd/internal/awsapi/glue"
	"stackd/storage/memory"
)

type memoryState struct {
	catalogs            map[CatalogKey]CatalogRecord
	databases           map[DatabaseKey]DatabaseRecord
	tables              map[TableKey]TableRecord
	tableVersions       map[TableVersionKey]TableVersionRecord
	partitions          map[PartitionKey]PartitionRecord
	functions           map[FunctionKey]FunctionRecord
	partitionIndexes    map[PartitionIndexKey]PartitionIndexRecord
	columnStatistics    map[ColumnStatisticsKey]ColumnStatisticsRecord
	partitionStatistics map[PartitionColumnStatisticsKey]PartitionColumnStatisticsRecord
	policies            map[Scope]ResourcePolicyRecord
	imports             map[CatalogKey]CatalogImportRecord
	jobsMemory
	crawlersMemory
	registryMemory
	workflowsMemory
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{catalogs: map[CatalogKey]CatalogRecord{}, databases: map[DatabaseKey]DatabaseRecord{}, tables: map[TableKey]TableRecord{}, tableVersions: map[TableVersionKey]TableVersionRecord{}, partitions: map[PartitionKey]PartitionRecord{}, functions: map[FunctionKey]FunctionRecord{}, partitionIndexes: map[PartitionIndexKey]PartitionIndexRecord{}, columnStatistics: map[ColumnStatisticsKey]ColumnStatisticsRecord{}, policies: map[Scope]ResourcePolicyRecord{}, imports: map[CatalogKey]CatalogImportRecord{}, jobsMemory: initJobsMemory(), crawlersMemory: initCrawlersMemory(), registryMemory: initRegistryMemory(), workflowsMemory: initWorkflowsMemory()}
	initial.partitionStatistics = map[PartitionColumnStatisticsKey]PartitionColumnStatisticsRecord{}
	return &MemoryRepository{memory.New(domain, initial, func(v memoryState) memoryState {
		v.catalogs = maps.Clone(v.catalogs)
		v.databases = maps.Clone(v.databases)
		v.tables = maps.Clone(v.tables)
		v.tableVersions = maps.Clone(v.tableVersions)
		v.partitions = maps.Clone(v.partitions)
		v.functions = maps.Clone(v.functions)
		v.partitionIndexes = maps.Clone(v.partitionIndexes)
		v.columnStatistics = maps.Clone(v.columnStatistics)
		v.partitionStatistics = maps.Clone(v.partitionStatistics)
		v.policies = maps.Clone(v.policies)
		v.imports = maps.Clone(v.imports)
		v.jobsMemory = cloneJobsMemory(v.jobsMemory)
		v.crawlersMemory = cloneCrawlersMemory(v.crawlersMemory)
		v.registryMemory = cloneRegistryMemory(v.registryMemory)
		v.workflowsMemory = cloneWorkflowsMemory(v.workflowsMemory)
		return v
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }
func cloneCatalogRecord(v CatalogRecord) CatalogRecord {
	v.Catalog = api.CloneCatalog(v.Catalog)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func (r memoryReader) Catalog(key CatalogKey) (CatalogRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return CatalogRecord{}, err
	}
	v, ok := r.s.catalogs[key]
	if !ok {
		return CatalogRecord{}, ErrNotFound
	}
	return cloneCatalogRecord(v), nil
}
func (w memoryWriter) PutCatalog(v CatalogRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	// Like the SQLite row, a private claim is immutable while its row exists.
	if old, ok := w.s.catalogs[v.Key]; ok {
		v.CFNOwner = old.CFNOwner
	}
	w.s.catalogs[v.Key] = cloneCatalogRecord(v)
	return nil
}
func (w memoryWriter) DeleteCatalog(key CatalogKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.catalogs, key)
	return nil
}
func (r memoryReader) Catalogs(key Scope) ([]CatalogRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []CatalogRecord{}
	for _, v := range r.s.catalogs {
		if v.Key.Scope == key {
			out = append(out, cloneCatalogRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b CatalogRecord) int { return cmp.Compare(a.Key.CatalogID, b.Key.CatalogID) })
	return out, nil
}
func cloneDatabaseRecord(v DatabaseRecord) DatabaseRecord {
	v.Database = api.CloneDatabase(v.Database)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func (r memoryReader) Database(key DatabaseKey) (DatabaseRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return DatabaseRecord{}, err
	}
	v, ok := r.s.databases[key]
	if !ok {
		return DatabaseRecord{}, ErrNotFound
	}
	return cloneDatabaseRecord(v), nil
}
func (w memoryWriter) PutDatabase(v DatabaseRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if old, ok := w.s.databases[v.Key]; ok {
		v.CFNOwner = old.CFNOwner
	}
	w.s.databases[v.Key] = cloneDatabaseRecord(v)
	return nil
}
func (w memoryWriter) DeleteDatabase(key DatabaseKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.databases, key)
	return nil
}
func (r memoryReader) Databases(key CatalogKey) ([]DatabaseRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []DatabaseRecord{}
	for _, v := range r.s.databases {
		if v.Key.CatalogKey == key {
			out = append(out, cloneDatabaseRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b DatabaseRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) ForeignDatabases(scope Scope) ([]DatabaseRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []DatabaseRecord{}
	for _, v := range r.s.databases {
		if v.Key.Partition == scope.Partition && v.Key.Region == scope.Region && v.Key.AccountID != scope.AccountID {
			out = append(out, cloneDatabaseRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b DatabaseRecord) int {
		return cmp.Or(cmp.Compare(a.Key.Name, b.Key.Name), cmp.Compare(a.Key.CatalogID, b.Key.CatalogID))
	})
	return out, nil
}
func cloneTableRecord(v TableRecord) TableRecord { v.Table = api.CloneTable(v.Table); return v }
func (r memoryReader) Table(key TableKey) (TableRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TableRecord{}, err
	}
	v, ok := r.s.tables[key]
	if !ok {
		return TableRecord{}, ErrNotFound
	}
	return cloneTableRecord(v), nil
}
func (w memoryWriter) PutTable(v TableRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.tables[v.Key] = cloneTableRecord(v)
	return nil
}
func (w memoryWriter) DeleteTable(key TableKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.tables, key)
	return nil
}
func (r memoryReader) Tables(key DatabaseKey) ([]TableRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TableRecord{}
	for _, v := range r.s.tables {
		if v.Key.DatabaseKey == key {
			out = append(out, cloneTableRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b TableRecord) int { return cmp.Compare(a.Key.TableName, b.Key.TableName) })
	return out, nil
}
func cloneTableVersionRecord(v TableVersionRecord) TableVersionRecord {
	v.Table = api.CloneTable(v.Table)
	return v
}
func (r memoryReader) TableVersion(key TableVersionKey) (TableVersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TableVersionRecord{}, err
	}
	v, ok := r.s.tableVersions[key]
	if !ok {
		return TableVersionRecord{}, ErrNotFound
	}
	return cloneTableVersionRecord(v), nil
}
func (w memoryWriter) PutTableVersion(v TableVersionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.tableVersions[v.Key] = cloneTableVersionRecord(v)
	return nil
}
func (w memoryWriter) DeleteTableVersion(key TableVersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.tableVersions, key)
	return nil
}
func (r memoryReader) TableVersions(key TableKey) ([]TableVersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TableVersionRecord{}
	for _, v := range r.s.tableVersions {
		if v.Key.TableKey == key {
			out = append(out, cloneTableVersionRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b TableVersionRecord) int { return cmp.Compare(a.Key.Version, b.Key.Version) })
	return out, nil
}
func clonePartitionRecord(v PartitionRecord) PartitionRecord {
	v.Partition = api.ClonePartition(v.Partition)
	return v
}
func (r memoryReader) Partition(key PartitionKey) (PartitionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return PartitionRecord{}, err
	}
	v, ok := r.s.partitions[key]
	if !ok {
		return PartitionRecord{}, ErrNotFound
	}
	return clonePartitionRecord(v), nil
}
func (w memoryWriter) PutPartition(v PartitionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.partitions[v.Key] = clonePartitionRecord(v)
	return nil
}
func (w memoryWriter) DeletePartition(key PartitionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.partitions, key)
	return nil
}
func (r memoryReader) Partitions(key TableKey) ([]PartitionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []PartitionRecord{}
	for _, v := range r.s.partitions {
		if v.Key.TableKey == key {
			out = append(out, clonePartitionRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b PartitionRecord) int { return cmp.Compare(a.Key.Values, b.Key.Values) })
	return out, nil
}
func cloneFunctionRecord(v FunctionRecord) FunctionRecord {
	v.Function = api.CloneUserDefinedFunction(v.Function)
	return v
}
func (r memoryReader) Function(key FunctionKey) (FunctionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return FunctionRecord{}, err
	}
	v, ok := r.s.functions[key]
	if !ok {
		return FunctionRecord{}, ErrNotFound
	}
	return cloneFunctionRecord(v), nil
}
func (w memoryWriter) PutFunction(v FunctionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.functions[v.Key] = cloneFunctionRecord(v)
	return nil
}
func (w memoryWriter) DeleteFunction(key FunctionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.functions, key)
	return nil
}
func (r memoryReader) Functions(key DatabaseKey) ([]FunctionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []FunctionRecord{}
	for _, v := range r.s.functions {
		if v.Key.DatabaseKey == key {
			out = append(out, cloneFunctionRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b FunctionRecord) int { return cmp.Compare(a.Key.FunctionName, b.Key.FunctionName) })
	return out, nil
}
func clonePartitionIndexRecord(v PartitionIndexRecord) PartitionIndexRecord {
	v.Index = api.ClonePartitionIndexDescriptor(v.Index)
	return v
}
func (r memoryReader) PartitionIndex(key PartitionIndexKey) (PartitionIndexRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return PartitionIndexRecord{}, err
	}
	v, ok := r.s.partitionIndexes[key]
	if !ok {
		return PartitionIndexRecord{}, ErrNotFound
	}
	return clonePartitionIndexRecord(v), nil
}
func (w memoryWriter) PutPartitionIndex(v PartitionIndexRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.partitionIndexes[v.Key] = clonePartitionIndexRecord(v)
	return nil
}
func (w memoryWriter) DeletePartitionIndex(key PartitionIndexKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.partitionIndexes, key)
	return nil
}
func (r memoryReader) PartitionIndexes(key TableKey) ([]PartitionIndexRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []PartitionIndexRecord{}
	for _, v := range r.s.partitionIndexes {
		if v.Key.TableKey == key {
			out = append(out, clonePartitionIndexRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b PartitionIndexRecord) int { return cmp.Compare(a.Key.IndexName, b.Key.IndexName) })
	return out, nil
}
func cloneColumnStatisticsRecord(v ColumnStatisticsRecord) ColumnStatisticsRecord {
	v.Statistics = api.CloneColumnStatistics(v.Statistics)
	return v
}
func (r memoryReader) ColumnStatistics(key ColumnStatisticsKey) (ColumnStatisticsRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ColumnStatisticsRecord{}, err
	}
	v, ok := r.s.columnStatistics[key]
	if !ok {
		return ColumnStatisticsRecord{}, ErrNotFound
	}
	return cloneColumnStatisticsRecord(v), nil
}
func (w memoryWriter) PutColumnStatistics(v ColumnStatisticsRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.columnStatistics[v.Key] = cloneColumnStatisticsRecord(v)
	return nil
}
func (w memoryWriter) DeleteColumnStatistics(key ColumnStatisticsKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.columnStatistics, key)
	return nil
}

func (r memoryReader) PartitionColumnStatistics(key PartitionColumnStatisticsKey) (PartitionColumnStatisticsRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return PartitionColumnStatisticsRecord{}, err
	}
	row, ok := r.s.partitionStatistics[key]
	if !ok {
		return PartitionColumnStatisticsRecord{}, ErrNotFound
	}
	row.Statistics = api.CloneColumnStatistics(row.Statistics)
	return row, nil
}
func (r memoryReader) PartitionStatistics(key PartitionKey) ([]PartitionColumnStatisticsRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := []PartitionColumnStatisticsRecord{}
	for candidate, row := range r.s.partitionStatistics {
		if candidate.PartitionKey == key {
			row.Statistics = api.CloneColumnStatistics(row.Statistics)
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b PartitionColumnStatisticsRecord) int { return cmp.Compare(a.Key.ColumnName, b.Key.ColumnName) })
	return rows, nil
}
func (w memoryWriter) PutPartitionColumnStatistics(row PartitionColumnStatisticsRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	row.Statistics = api.CloneColumnStatistics(row.Statistics)
	w.s.partitionStatistics[row.Key] = row
	return nil
}
func (w memoryWriter) DeletePartitionColumnStatistics(key PartitionColumnStatisticsKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.partitionStatistics, key)
	return nil
}
func (w memoryWriter) DeletePartitionStatistics(key PartitionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for candidate := range w.s.partitionStatistics {
		if candidate.PartitionKey == key {
			delete(w.s.partitionStatistics, candidate)
		}
	}
	return nil
}
func (w memoryWriter) DeletePartitionColumnStatisticsForColumn(key ColumnStatisticsKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for candidate := range w.s.partitionStatistics {
		if candidate.TableKey == key.TableKey && candidate.ColumnName == key.ColumnName {
			delete(w.s.partitionStatistics, candidate)
		}
	}
	return nil
}
func (r memoryReader) ResourcePolicy(key Scope) (ResourcePolicyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ResourcePolicyRecord{}, err
	}
	v, ok := r.s.policies[key]
	if !ok {
		return ResourcePolicyRecord{}, ErrNotFound
	}
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	return v, nil
}
func (w memoryWriter) PutResourcePolicy(v ResourcePolicyRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	w.s.policies[v.Scope] = v
	return nil
}
func (w memoryWriter) DeleteResourcePolicy(key Scope) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.policies, key)
	return nil
}
func (r memoryReader) CatalogImport(key CatalogKey) (CatalogImportRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return CatalogImportRecord{}, err
	}
	v, ok := r.s.imports[key]
	if !ok {
		return CatalogImportRecord{}, ErrNotFound
	}
	v.Status = api.CloneCatalogImportStatus(v.Status)
	return v, nil
}
func (w memoryWriter) PutCatalogImport(v CatalogImportRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Status = api.CloneCatalogImportStatus(v.Status)
	w.s.imports[v.Key] = v
	return nil
}
