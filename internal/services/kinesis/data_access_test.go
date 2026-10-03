package kinesis

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/iam"
	"stackd/storage/memory"
)

// Signal only after the initial stream snapshot and its authorization have left
// the transaction. The held engine gate then separates that snapshot from I/O.
type authorityGateRepository struct {
	Repository
	armed atomic.Bool
	ready chan struct{}
}

func (r *authorityGateRepository) View(ctx context.Context, fn func(Reader) error) error {
	seen := false
	err := r.Repository.View(ctx, func(reader Reader) error {
		return fn(authorityGateReader{Reader: reader, seen: &seen})
	})
	if err == nil && seen && r.armed.CompareAndSwap(true, false) {
		close(r.ready)
	}
	return err
}

type authorityGateReader struct {
	Reader
	seen *bool
}

func (r authorityGateReader) Stream(key StreamKey) (StreamRecord, error) {
	stream, err := r.Reader.Stream(key)
	if err == nil {
		*r.seen = true
	}
	return stream, err
}

func TestDataPlaneReauthorizesAfterEngineGate(t *testing.T) {
	for _, operation := range []string{"PutRecord", "PutRecords", "GetRecords", "GetShardIterator", "LatestSequence", "LatestConsumerSequence", "SubscribeToShard"} {
		for _, change := range []string{"identity-policy", "identity-replaced", "resource-policy", "resource-tag", "stream-replaced", "canceled"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				domain := memory.NewDomain()
				repository := &authorityGateRepository{Repository: NewMemoryRepository(domain), ready: make(chan struct{})}
				identities := iam.NewMemoryRepository(domain)
				source := clock.NewManual(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
				service := New(Config{Repository: repository, Clock: source, Authorizer: authorization.NewWithClock(iam.NewWithRepository(nil, identities), nil, source)})
				t.Cleanup(func() { _ = service.Close() })
				key := StreamKey{Scope: Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "authority"}
				stream := StreamRecord{Key: key, EngineID: "original", Data: api.StreamDescriptionSummary{StreamStatus: new(api.StreamStatusACTIVE)}}
				consumer := ConsumerKey{Stream: key, Name: "reader", CreatedAt: source.Now().Unix()}
				resource := ResourceKey{Scope: key.Scope, ARN: key.ARN()}
				action := operation
				switch operation {
				case "LatestSequence":
					action = "GetShardIterator"
				case "LatestConsumerSequence", "SubscribeToShard":
					action = "SubscribeToShard"
					resource.ARN = consumer.ARN()
				}
				if err := repository.Update(ctx, func(tx Transaction) error {
					if err := tx.PutStream(stream); err != nil {
						return err
					}
					if err := tx.PutConsumer(ConsumerRecord{Key: consumer, Data: api.ConsumerDescription{ConsumerStatus: new(api.ConsumerStatusACTIVE)}}); err != nil {
						return err
					}
					return tx.PutTags(TagRecord{Key: resource, Tags: api.TagList{{Key: new(api.TagKey("authority")), Value: new(api.TagValue("allowed"))}}})
				}); err != nil {
					t.Fatal(err)
				}
				user := iam.User{UserName: "actor", UserId: "AIDAACTOR", Arn: "arn:aws:iam::123456789012:user/actor", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{
					"access": fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"kinesis:%s","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/authority":"allowed"}}}}`, action, resource.ARN),
				}}}
				identityScope := iam.Scope{Partition: key.Partition, AccountID: key.AccountID}
				if err := identities.Update(ctx, func(tx iam.WriteTx) error { return tx.PutUser(identityScope, user) }); err != nil {
					t.Fatal(err)
				}
				caller := awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PrincipalARN: user.Arn, PrincipalID: user.UserId, UserName: user.UserName})
				caller, cancelCaller := context.WithCancel(caller)
				defer cancelCaller()
				release, err := service.engines.lock(ctx, stream.EngineID)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if release != nil {
						release()
					}
				}()
				repository.armed.Store(true)
				done := make(chan *awswire.Error, 1)
				go func() { done <- gateAuthorityCall(caller, service, operation, stream, consumer, source.Now()) }()
				select {
				case <-repository.ready:
				case rejected := <-done:
					t.Fatal("request failed before waiting for the gate:", rejected)
				case <-ctx.Done():
					t.Fatal("request did not reach the engine gate:", ctx.Err())
				}
				switch change {
				case "identity-policy", "identity-replaced":
					if change == "identity-policy" {
						user.Inline = nil
					} else {
						user.UserId = "AIDAREPLACEMENT"
					}
					err = identities.Update(ctx, func(tx iam.WriteTx) error { return tx.PutUser(identityScope, user) })
				case "resource-policy":
					err = repository.Update(ctx, func(tx Transaction) error {
						return tx.PutPolicy(PolicyRecord{Key: resource, Policy: authorization.BoundPolicy{Document: fmt.Sprintf(`{"Statement":{"Effect":"Deny","Principal":"*","Action":"kinesis:%s","Resource":%q}}`, action, resource.ARN)}})
					})
				case "resource-tag":
					err = repository.Update(ctx, func(tx Transaction) error { return tx.PutTags(TagRecord{Key: resource}) })
				case "stream-replaced":
					replacement := stream
					replacement.EngineID = "replacement"
					err = repository.Update(ctx, func(tx Transaction) error { return tx.PutStream(replacement) })
				case "canceled":
					cancelCaller()
				}
				if err != nil {
					t.Fatal(err)
				}
				// A canceled request must finish while the gate remains held.
				if change != "canceled" {
					release()
					release = nil
				}
				select {
				case rejected := <-done:
					if rejected == nil {
						t.Fatal("stale request succeeded")
					}
					want := "AccessDeniedException"
					if change == "stream-replaced" {
						want = "ResourceNotFoundException"
					} else if change == "canceled" {
						return
					}
					if rejected.Code != want {
						t.Fatalf("got %s (%s), want %s before any native access", rejected.Code, rejected.Message, want)
					}
				case <-ctx.Done():
					t.Fatal("request did not finish:", ctx.Err())
				}
			})
		}
	}
}

func gateAuthorityCall(ctx context.Context, service *Service, operation string, stream StreamRecord, consumer ConsumerKey, now time.Time) *awswire.Error {
	name := new(api.StreamName(stream.Key.Name))
	shard := ShardRecord{Key: ShardKey{Stream: stream.Key, Partition: 0}}
	switch operation {
	case "PutRecord":
		_, err := service.PutRecord(ctx, &api.PutRecordInput{StreamName: name, PartitionKey: new(api.PartitionKey("key")), Data: []byte("revoked")})
		return err
	case "PutRecords":
		_, err := service.PutRecords(ctx, &api.PutRecordsInput{StreamName: name, Records: api.PutRecordsRequestEntryList{{PartitionKey: new(api.PartitionKey("key")), Data: []byte("revoked")}}})
		return err
	case "GetRecords":
		_, err := service.GetRecords(ctx, &api.GetRecordsInput{ShardIterator: encodeShardCursor(stream.Key.Scope, stream, shard, 0, now)})
		return err
	case "GetShardIterator":
		_, err := service.GetShardIterator(ctx, &api.GetShardIteratorInput{StreamName: name, ShardId: new(api.ShardId(shard.Key.ID())), ShardIteratorType: new(api.ShardIteratorTypeLATEST)})
		return err
	case "LatestSequence":
		_, err := service.LatestSequence(ctx, stream.Key.ARN(), shard.Key.ID())
		return err
	case "LatestConsumerSequence":
		_, err := service.LatestSequence(ctx, consumer.ARN(), shard.Key.ID())
		return err
	default:
		_, err := service.SubscribeToShard(ctx, &api.SubscribeToShardInput{ConsumerARN: new(api.ConsumerARN(consumer.ARN())), ShardId: new(api.ShardId(shard.Key.ID())), StartingPosition: &api.StartingPosition{Type: new(api.ShardIteratorTypeLATEST)}})
		return err
	}
}
