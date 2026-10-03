package sqs

import (
	"context"
	"database/sql"

	"stackd/storage/sqlite"
	"stackd/storage/sqlite/sqs/internal/sqlcgen"
	domain "stackd/storage/sqs"
)

func (r reader) Messages(queueID string) (domain.QueueMessages, error) {
	var result domain.QueueMessages
	rows, err := r.q.ListMessages(r.ctx, queueID)
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		result.Messages = append(result.Messages, domain.MessageRecord{ID: row.ID, Group: row.MessageGroup, DeduplicationID: row.DeduplicationID, Sequence: row.Sequence, Sender: row.Sender,
			Data: row.Data, Encrypted: row.Encrypted, KMSKeyARN: row.KmsKeyArn, EncryptedDataKey: row.EncryptedDataKey,
			BodyMD5: row.BodyMd5, Sent: row.Sent, RetentionStarted: row.RetentionStarted, FirstReceived: row.FirstReceived, LastReceived: row.LastReceived, Available: row.Available,
			AgeStarted: row.AgeStarted.Time, QueueReceives: int(row.QueueReceives),
			Receives: int(row.Receives), LatestReceipt: row.LatestReceipt, Generation: uint64(row.Generation), SourceARN: row.SourceArn})
	}
	receipts, err := r.q.ListReceipts(r.ctx, queueID)
	if err != nil {
		return result, err
	}
	for _, row := range receipts {
		result.Receipts = append(result.Receipts, domain.ReceiptRecord{Handle: row.Handle, MessageID: row.MessageID, LatestReceipt: row.LatestReceipt, Expires: row.Expires, Available: row.Available, LastReceived: row.LastReceived, Generation: uint64(row.Generation)})
	}
	deduplications, err := r.q.ListDeduplications(r.ctx, queueID)
	if err != nil {
		return result, err
	}
	for _, row := range deduplications {
		result.Deduplications = append(result.Deduplications, domain.DeduplicationRecord{Token: row.Token, MessageID: row.MessageID, Sequence: row.Sequence, Expires: row.Expires})
	}
	attempts, err := r.q.ListReceiveAttempts(r.ctx, queueID)
	if err != nil {
		return result, err
	}
	byToken := make(map[string]int, len(attempts))
	for _, row := range attempts {
		byToken[row.Token] = len(result.Attempts)
		result.Attempts = append(result.Attempts, domain.ReceiveAttemptRecord{Token: row.Token, Expires: row.Expires})
	}
	items, err := r.q.ListReceiveAttemptMessages(r.ctx, queueID)
	if err != nil {
		return result, err
	}
	for _, row := range items {
		attempt := &result.Attempts[byToken[row.Token]]
		attempt.MessageIDs = append(attempt.MessageIDs, row.MessageID)
		attempt.Handles = append(attempt.Handles, row.Handle)
		attempt.Generations = append(attempt.Generations, uint64(row.Generation))
	}
	groups, err := r.q.ListNoisyGroups(r.ctx, queueID)
	if err != nil {
		return result, err
	}
	for _, row := range groups {
		result.NoisyGroups = append(result.NoisyGroups, domain.NoisyGroupRecord{Group: row.MessageGroup, InFlightUntil: row.InFlightUntil})
	}
	return result, nil
}

func (w writer) PutMessages(queueID string, records domain.QueueMessages) error {
	// The service supplies the complete atomic delivery set. Child rows of
	// receive attempts are deleted by their foreign key, not by a second path.
	for _, clear := range []func(context.Context, string) error{w.q.ClearMessages, w.q.ClearReceipts, w.q.ClearDeduplications, w.q.ClearReceiveAttempts, w.q.ClearNoisyGroups} {
		if err := clear(w.ctx, queueID); err != nil {
			return err
		}
	}
	for i, row := range records.Messages {
		if err := w.q.InsertMessage(w.ctx, sqlcgen.InsertMessageParams{QueueID: queueID, Position: int64(i), ID: row.ID, MessageGroup: row.Group, DeduplicationID: row.DeduplicationID, Sequence: row.Sequence, Sender: row.Sender,
			Data: row.Data, Encrypted: row.Encrypted, KmsKeyArn: row.KMSKeyARN, EncryptedDataKey: row.EncryptedDataKey,
			BodyMd5: row.BodyMD5, Sent: row.Sent, RetentionStarted: row.RetentionStarted, FirstReceived: row.FirstReceived, LastReceived: row.LastReceived, Available: row.Available,
			AgeStarted: sql.NullTime{Time: row.AgeStarted, Valid: !row.AgeStarted.IsZero()}, QueueReceives: int64(row.QueueReceives),
			Receives: int64(row.Receives), LatestReceipt: row.LatestReceipt, Generation: sqlite.Uint64(row.Generation), SourceArn: row.SourceARN}); err != nil {
			return err
		}
	}
	for _, row := range records.Receipts {
		if err := w.q.InsertReceipt(w.ctx, sqlcgen.InsertReceiptParams{QueueID: queueID, Handle: row.Handle, MessageID: row.MessageID, LatestReceipt: row.LatestReceipt, Expires: row.Expires, Available: row.Available, LastReceived: row.LastReceived, Generation: sqlite.Uint64(row.Generation)}); err != nil {
			return err
		}
	}
	for _, row := range records.Deduplications {
		if err := w.q.InsertDeduplication(w.ctx, sqlcgen.InsertDeduplicationParams{QueueID: queueID, Token: row.Token, MessageID: row.MessageID, Sequence: row.Sequence, Expires: row.Expires}); err != nil {
			return err
		}
	}
	for _, row := range records.Attempts {
		if err := w.q.InsertReceiveAttempt(w.ctx, sqlcgen.InsertReceiveAttemptParams{QueueID: queueID, Token: row.Token, Expires: row.Expires}); err != nil {
			return err
		}
		for i, messageID := range row.MessageIDs {
			if err := w.q.InsertReceiveAttemptMessage(w.ctx, sqlcgen.InsertReceiveAttemptMessageParams{QueueID: queueID, Token: row.Token, Position: int64(i), MessageID: messageID, Handle: row.Handles[i], Generation: sqlite.Uint64(row.Generations[i])}); err != nil {
				return err
			}
		}
	}
	for _, row := range records.NoisyGroups {
		if err := w.q.InsertNoisyGroup(w.ctx, sqlcgen.InsertNoisyGroupParams{QueueID: queueID, MessageGroup: row.Group, InFlightUntil: row.InFlightUntil}); err != nil {
			return err
		}
	}
	return nil
}
