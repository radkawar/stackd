package glue

import (
	"cmp"
	"maps"
	"slices"

	api "stackd/internal/awsapi/glue"
)

type crawlersMemory struct {
	crawlers             map[ResourceKey]CrawlerRecord
	crawls               map[string]CrawlRecord
	classifiers          map[ResourceKey]ClassifierRecord
	connections          map[ResourceKey]ConnectionRecord
	connectionEncryption map[Scope]ConnectionEncryptionRecord
}

func initCrawlersMemory() crawlersMemory {
	return crawlersMemory{crawlers: map[ResourceKey]CrawlerRecord{}, crawls: map[string]CrawlRecord{}, classifiers: map[ResourceKey]ClassifierRecord{}, connections: map[ResourceKey]ConnectionRecord{}, connectionEncryption: map[Scope]ConnectionEncryptionRecord{}}
}
func cloneCrawlersMemory(v crawlersMemory) crawlersMemory {
	v.crawlers, v.crawls, v.classifiers, v.connections = maps.Clone(v.crawlers), maps.Clone(v.crawls), maps.Clone(v.classifiers), maps.Clone(v.connections)
	v.connectionEncryption = maps.Clone(v.connectionEncryption)
	return v
}
func cloneCrawlerRecord(v CrawlerRecord) CrawlerRecord {
	v.Crawler = api.CloneCrawler(v.Crawler)
	v.Tags = maps.Clone(v.Tags)
	if v.NextScheduled != nil {
		v.NextScheduled = new(*v.NextScheduled)
	}
	return v
}
func cloneCrawlRecord(v CrawlRecord) CrawlRecord {
	if v.Completed != nil {
		v.Completed = new(*v.Completed)
	}
	return v
}
func cloneConnectionRecord(v ConnectionRecord) ConnectionRecord {
	v.Connection = api.CloneConnection(v.Connection)
	v.Tags = maps.Clone(v.Tags)
	v.PasswordCipher = slices.Clone(v.PasswordCipher)
	return v
}
func (r memoryReader) Crawler(key ResourceKey) (CrawlerRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return CrawlerRecord{}, err
	}
	v, ok := r.s.crawlers[key]
	if !ok {
		return CrawlerRecord{}, ErrNotFound
	}
	return cloneCrawlerRecord(v), nil
}
func (r memoryReader) Crawlers(scope Scope) ([]CrawlerRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []CrawlerRecord{}
	for key, v := range r.s.crawlers {
		if key.Scope == scope {
			out = append(out, cloneCrawlerRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b CrawlerRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (w memoryWriter) PutCrawler(v CrawlerRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.crawlers[v.Key] = cloneCrawlerRecord(v)
	return nil
}
func (w memoryWriter) DeleteCrawler(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.crawlers, key)
	for id, v := range w.s.crawls {
		if v.Crawler == key {
			delete(w.s.crawls, id)
		}
	}
	return nil
}
func (r memoryReader) Crawl(id string) (CrawlRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return CrawlRecord{}, err
	}
	v, ok := r.s.crawls[id]
	if !ok {
		return CrawlRecord{}, ErrNotFound
	}
	return cloneCrawlRecord(v), nil
}
func (r memoryReader) Crawls(key ResourceKey) ([]CrawlRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []CrawlRecord{}
	for _, v := range r.s.crawls {
		if v.Crawler == key {
			out = append(out, cloneCrawlRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b CrawlRecord) int { return cmp.Or(b.Started.Compare(a.Started), cmp.Compare(b.ID, a.ID)) })
	return out, nil
}
func (r memoryReader) PendingCrawls() ([]CrawlRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []CrawlRecord{}
	for _, v := range r.s.crawls {
		if v.State == "RUNNING" || v.State == "CANCELLING" {
			out = append(out, cloneCrawlRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b CrawlRecord) int { return cmp.Or(a.Started.Compare(b.Started), cmp.Compare(a.ID, b.ID)) })
	return out, nil
}
func (w memoryWriter) PutCrawl(v CrawlRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.crawls[v.ID] = cloneCrawlRecord(v)
	return nil
}
func (r memoryReader) Classifier(key ResourceKey) (ClassifierRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ClassifierRecord{}, err
	}
	v, ok := r.s.classifiers[key]
	if !ok {
		return ClassifierRecord{}, ErrNotFound
	}
	v.Classifier = api.CloneClassifier(v.Classifier)
	return v, nil
}
func (r memoryReader) Classifiers(scope Scope) ([]ClassifierRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ClassifierRecord{}
	for key, v := range r.s.classifiers {
		if key.Scope == scope {
			v.Classifier = api.CloneClassifier(v.Classifier)
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b ClassifierRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (w memoryWriter) PutClassifier(v ClassifierRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Classifier = api.CloneClassifier(v.Classifier)
	w.s.classifiers[v.Key] = v
	return nil
}
func (w memoryWriter) DeleteClassifier(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.classifiers, key)
	return nil
}
func (r memoryReader) Connection(key ResourceKey) (ConnectionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ConnectionRecord{}, err
	}
	v, ok := r.s.connections[key]
	if !ok {
		return ConnectionRecord{}, ErrNotFound
	}
	return cloneConnectionRecord(v), nil
}
func (r memoryReader) Connections(scope Scope) ([]ConnectionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ConnectionRecord{}
	for key, v := range r.s.connections {
		if key.Scope == scope {
			out = append(out, cloneConnectionRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b ConnectionRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (w memoryWriter) PutConnection(v ConnectionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.connections[v.Key] = cloneConnectionRecord(v)
	return nil
}
func (w memoryWriter) DeleteConnection(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.connections, key)
	return nil
}
