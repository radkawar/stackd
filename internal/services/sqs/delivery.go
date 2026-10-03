package sqs

import (
	"strconv"
	"time"
)

// availableMessages applies the same visibility and FIFO group ownership to
// consumer receives and redrive. Other groups remain available while one is held.
func (q *queue) availableMessages(now time.Time) []*message {
	blocked := make(map[string]bool)
	if q.config.fifo {
		for _, m := range q.messages {
			if m.receives > 0 && now.Before(m.available) {
				blocked[m.group] = true
			}
		}
	}
	var candidates []*message
	for _, m := range q.messages {
		if q.config.fifo && blocked[m.group] {
			continue
		}
		if now.Before(m.available) {
			if q.config.fifo {
				blocked[m.group] = true
			}
			continue
		}
		candidates = append(candidates, m)
	}
	return candidates
}

func (q *queue) dedupKey(group, id string) string {
	if q.config.dedupScope == "messageGroup" {
		return group + "\x00" + id
	}
	return id
}

// appendMessage publishes an accepted message and its FIFO identity together.
// Callers resolve duplicate sends before changing queue state.
func (q *queue) appendMessage(m *message, now time.Time) {
	if q.config.fifo {
		q.sequence++
		m.sequence = strconv.FormatUint(q.sequence, 10)
		q.dedup[q.dedupKey(m.group, m.dedup)] = dedupRecord{id: m.id, sequence: m.sequence, expires: now.Add(5 * time.Minute)}
	}
	activateQueueMetrics(&q.metricActiveUntil, &q.nextMetricSample, now)
	m.ageStarted, m.queueReceives = now, 0
	if m.receives == 0 {
		m.ageStarted = m.available
	}
	q.messages = append(q.messages, m)
	q.notify()
}
