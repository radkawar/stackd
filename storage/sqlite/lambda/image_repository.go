package lambda

import (
	"database/sql"
	"encoding/json"
	"errors"

	runtime "stackd/compute/lambda"
	api "stackd/internal/awsapi/lambda"
	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) functionImage(k domain.FunctionKey, pending bool, version uint64) (*runtime.Image, *api.ImageConfig, error) {
	row, err := r.q.GetFunctionImage(r.ctx, sqlcgen.GetFunctionImageParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(version)})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	image := &runtime.Image{URI: row.ImageUri, ID: row.ImageID, ResolvedURI: row.ResolvedImageUri, PinReference: row.PinReference, PinLease: row.PinLease, PinImageID: row.PinImageID, Size: row.ImageSize, WorkingDirectory: row.WorkingDirectory}
	for _, item := range []struct {
		body string
		out  any
	}{{row.Entrypoint, &image.EntryPoint}, {row.Command, &image.Command}, {row.Environment, &image.Environment}} {
		if err := json.Unmarshal([]byte(item.body), item.out); err != nil {
			return nil, nil, err
		}
	}
	var config *api.ImageConfig
	if err := json.Unmarshal([]byte(row.ImageConfig), &config); err != nil {
		return nil, nil, err
	}
	return image, config, nil
}
func (w writer) putFunctionImage(v domain.FunctionRecord, pending bool) error {
	k := v.Key
	if v.Image == nil {
		return w.q.DeleteFunctionImage(w.ctx, sqlcgen.DeleteFunctionImageParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version)})
	}
	bodies := make([]string, 0, 4)
	for _, value := range []any{v.Image.EntryPoint, v.Image.Command, v.Image.Environment, v.ImageConfig} {
		body, err := json.Marshal(value)
		if err != nil {
			return err
		}
		bodies = append(bodies, string(body))
	}
	return w.q.PutFunctionImage(w.ctx, sqlcgen.PutFunctionImageParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version), ImageUri: v.Image.URI, ImageID: v.Image.ID, ResolvedImageUri: v.Image.ResolvedURI, ImageSize: v.Image.Size, Entrypoint: bodies[0], Command: bodies[1], Environment: bodies[2], WorkingDirectory: v.Image.WorkingDirectory, ImageConfig: bodies[3], PinReference: v.Image.PinReference, PinLease: v.Image.PinLease, PinImageID: v.Image.PinImageID})
}
