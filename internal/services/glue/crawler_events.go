package glue

import "context"

// CrawlerEvents publishes state changes through the existing EventBridge owner
// in the transaction which owns the crawler state. Messages never contain source
// rows or connection credentials.
type CrawlerEvents interface {
	Publish(context.Context, CrawlerRecord, string, string) error
}

func (s *Service) crawlerEvent(ctx context.Context, row CrawlerRecord, state, message string) error {
	if s.crawlerEvents == nil {
		return nil
	}
	return s.crawlerEvents.Publish(ctx, row, state, message)
}
