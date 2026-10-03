package pipes

import (
	"database/sql"
	"errors"
	domain "stackd/storage/pipes"
	"stackd/storage/sqlite/pipes/internal/sqlcgen"
)

func (r reader) configuration(p *domain.PipeRecord) error {
	if p.Source.Kind == "kafka" || p.Source.Kind == "msk" {
		source, err := r.q.KafkaSource(r.ctx, p.ID)
		if err != nil {
			return err
		}
		p.Source.Kafka.Topic = source.Topic
		p.Source.Kafka.ConsumerGroupID = source.ConsumerGroupID
		p.Source.Kafka.Authentication = source.Authentication
		p.Source.Kafka.SecretARN = source.SecretArn
		p.Source.Kafka.RootCASecretARN = source.RootCaSecretArn
		brokers, err := r.q.KafkaBootstrapServers(r.ctx, p.ID)
		if err != nil {
			return err
		}
		for _, broker := range brokers {
			p.Source.Kafka.BootstrapServers = append(p.Source.Kafka.BootstrapServers, broker.Address)
		}
	}
	encrypted, e := r.q.Encryption(r.ctx, p.ID)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if e == nil {
		p.KMSKeyARN = encrypted.KeyArn
		p.Encrypted = &domain.EncryptedConfiguration{WrappedKey: encrypted.WrappedKey, Nonce: encrypted.Nonce, Ciphertext: encrypted.Ciphertext}
	}
	logging, e := r.q.Logging(r.ctx, p.ID)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if e == nil {
		p.Logging = domain.Logging{
			Level:                logging.Level,
			IncludeExecutionData: logging.IncludeExecutionData != 0,
			LogGroupARN:          logging.LogGroupArn,
			FirehoseARN:          logging.FirehoseArn,
			BucketName:           logging.BucketName,
			BucketOwner:          logging.BucketOwner,
			Prefix:               logging.Prefix,
			OutputFormat:         logging.OutputFormat,
		}
	}
	return nil
}
func (w writer) putConfiguration(p domain.PipeRecord) error {
	if p.Source.Kind == "kafka" || p.Source.Kind == "msk" {
		k := p.Source.Kafka
		if err := w.q.PutKafkaSource(w.ctx, sqlcgen.PutKafkaSourceParams{
			PipeID: p.ID, Topic: k.Topic, ConsumerGroupID: k.ConsumerGroupID,
			Authentication: k.Authentication, SecretArn: k.SecretARN, RootCaSecretArn: k.RootCASecretARN,
		}); err != nil {
			return err
		}
		if err := w.q.DeleteKafkaBootstrapServers(w.ctx, p.ID); err != nil {
			return err
		}
		for i, broker := range k.BootstrapServers {
			if err := w.q.PutKafkaBootstrapServer(w.ctx, sqlcgen.PutKafkaBootstrapServerParams{PipeID: p.ID, Position: int64(i), Address: broker}); err != nil {
				return err
			}
		}
	}
	if p.Encrypted == nil {
		if e := w.q.DeleteEncryption(w.ctx, p.ID); e != nil {
			return e
		}
	} else {
		if e := w.q.PutEncryption(w.ctx, sqlcgen.PutEncryptionParams{
			PipeID:     p.ID,
			KeyArn:     p.KMSKeyARN,
			WrappedKey: p.Encrypted.WrappedKey,
			Nonce:      p.Encrypted.Nonce,
			Ciphertext: p.Encrypted.Ciphertext,
		}); e != nil {
			return e
		}
	}
	v := p.Logging
	return w.q.PutLogging(w.ctx, sqlcgen.PutLoggingParams{
		PipeID:               p.ID,
		Level:                v.Level,
		IncludeExecutionData: boolean(v.IncludeExecutionData),
		LogGroupArn:          v.LogGroupARN,
		FirehoseArn:          v.FirehoseARN,
		BucketName:           v.BucketName,
		BucketOwner:          v.BucketOwner,
		Prefix:               v.Prefix,
		OutputFormat:         v.OutputFormat,
	})
}
