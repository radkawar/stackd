package main

import (
	"context"
	"errors"
	"fmt"

	service "stackd/internal/services/opensearch"
	store "stackd/storage/opensearch"
)

func removeOpenSearchDomains(ctx context.Context, repository store.Repository, runtime service.Runtime) error {
	var domains []store.Domain
	if err := repository.View(ctx, func(r store.Reader) error { var err error; domains, err = r.AllDomains(); return err }); err != nil {
		return err
	}
	var result error
	for _, v := range domains {
		if err := runtime.Delete(ctx, v.Incarnation); err != nil {
			result = errors.Join(result, fmt.Errorf("remove ephemeral OpenSearch domain %s: %w", v.Key.ARN(), err))
		}
	}
	return result
}
