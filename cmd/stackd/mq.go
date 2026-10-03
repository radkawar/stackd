package main

import (
	"context"
	"errors"
	"fmt"

	"stackd/internal/services/mq"
	store "stackd/storage/mq"
)

func removeMQBrokers(ctx context.Context, repository store.Repository, runtime mq.Runtime) error {
	var brokers []store.BrokerRecord
	if err := repository.View(ctx, func(reader store.Reader) error {
		var err error
		brokers, err = reader.AllBrokers()
		return err
	}); err != nil {
		return err
	}
	var result error
	for _, broker := range brokers {
		if err := runtime.Delete(ctx, broker); err != nil {
			result = errors.Join(result, fmt.Errorf("remove ephemeral MQ broker %s: %w", broker.ARN, err))
		}
	}
	return result
}
