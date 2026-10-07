package lambda

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"slices"
	"strings"
	"time"

	runtime "stackd/compute/lambda"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func cloneDeploymentImage(in *runtime.Image) *runtime.Image { return runtime.CloneImage(in) }
func cloneImageConfig(in *api.ImageConfig) *api.ImageConfig {
	if in == nil {
		return nil
	}
	out := *in
	out.Command = slices.Clone(in.Command)
	out.EntryPoint = slices.Clone(in.EntryPoint)
	if in.WorkingDirectory != nil {
		out.WorkingDirectory = new(*in.WorkingDirectory)
	}
	return &out
}
func runtimeImageConfig(in *api.ImageConfig) *runtime.ImageConfig {
	if in == nil {
		return nil
	}
	out := &runtime.ImageConfig{WorkingDirectory: value(in.WorkingDirectory)}
	if in.Command != nil {
		out.Command = make([]string, len(in.Command))
		for i, v := range in.Command {
			out.Command[i] = string(v)
		}
	}
	if in.EntryPoint != nil {
		out.EntryPoint = make([]string, len(in.EntryPoint))
		for i, v := range in.EntryPoint {
			out.EntryPoint[i] = string(v)
		}
	}
	return out
}
func validateImageConfig(in *api.ImageConfig) *awswire.Error {
	if in == nil {
		return nil
	}
	for _, list := range []api.StringList{in.Command, in.EntryPoint} {
		if len(list) > 1500 {
			return failure("InvalidParameterValueException", "Image configuration supports at most 1500 arguments.", 400)
		}
		for _, arg := range list {
			if strings.ContainsRune(string(arg), '\x00') {
				return failure("InvalidParameterValueException", "Image arguments cannot contain NUL.", 400)
			}
		}
	}
	directory := value(in.WorkingDirectory)
	if len(directory) > 1000 || strings.ContainsRune(directory, '\x00') || (directory != "" && !strings.HasPrefix(directory, "/")) {
		return failure("InvalidParameterValueException", "Image working directory must be an absolute path of at most 1000 characters.", 400)
	}
	return nil
}
func (s *Service) loadImage(ctx context.Context, uri, architecture string) (*runtime.Image, string, *awswire.Error) {
	resolver, ok := s.executor.(runtime.ImageResolver)
	if !ok {
		return nil, "", unsupported("Local image deployments require a configured Docker image resolver.")
	}
	image, err := resolver.ResolveImage(ctx, uri, architecture)
	if err != nil {
		return nil, "", failure("InvalidParameterValueException", err.Error(), 400)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(image.ID, "sha256:"))
	if err != nil || len(raw) != 32 {
		return nil, "", failure("ServiceException", "Image resolver returned no immutable image identity.", 500)
	}
	if retainer, ok := s.executor.(runtime.ImageRetainer); ok {
		image, err = retainer.RetainImage(ctx, image)
		if err != nil {
			return nil, "", failure("InvalidParameterValueException", err.Error(), 400)
		}
	}
	return &image, base64.StdEncoding.EncodeToString(raw), nil
}
func (s *Service) updateImageCode(ctx context.Context, in *api.UpdateFunctionCodeInput, ref FunctionReference, current FunctionRecord) (out *api.FunctionConfiguration, wire *awswire.Error) {
	if in.ImageUri == nil || in.ZipFile != nil || in.S3Bucket != nil || in.S3Key != nil || in.S3ObjectVersion != nil || in.S3ObjectStorageMode != nil {
		return nil, failure("InvalidParameterValueException", "Image functions require only ImageUri for code updates; package type is immutable.", 400)
	}
	architecture := current.Architecture
	if len(in.Architectures) > 0 {
		architecture = string(in.Architectures[0])
	}
	s.imageMu.Lock()
	defer s.imageMu.Unlock()
	defer s.finishImageStage(ctx, &wire)
	image, digest, wire := s.loadImage(ctx, value(in.ImageUri), architecture)
	if wire != nil {
		return nil, wire
	}
	return s.stageUpdate(ctx, in, ref, "UpdateFunctionCode", in.RevisionId, false, in.DryRun != nil && bool(*in.DryRun), in.Publish != nil && bool(*in.Publish), in.PublishTo, func(tx Transaction, v *FunctionRecord) *awswire.Error {
		if current.DeploymentRevision != v.DeploymentRevision {
			return failure("ResourceConflictException", "The function deployment changed during image resolution.", 409)
		}
		v.Image, v.CodeSHA256, v.CodeSize, v.Architecture = cloneDeploymentImage(image), digest, image.Size, architecture
		return validateDeployment(*v)
	})
}

// Caller holds imageMu. Repository reads collect the retention roots; all
// daemon effects occur after the storage snapshot has closed.
func (s *Service) reconcileImages(ctx context.Context) error {
	retainer, ok := s.executor.(runtime.ImageRetainer)
	if !ok {
		return nil
	}
	var images []runtime.Image
	// Admission and deployment mutation use this same service-to-storage lock
	// order. Snapshot execution roots with repository roots, then drop mu before
	// contacting the daemon; no role or guest I/O runs under either lock.
	s.mu.Lock()
	err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.AllFunctions()
		if err != nil {
			return err
		}
		pending, err := r.PendingFunctions()
		if err != nil {
			return err
		}
		for _, record := range rows {
			if record.Image != nil {
				images = append(images, *record.Image)
			}
			versions, err := r.FunctionVersions(record.Key)
			if err != nil {
				return err
			}
			for _, version := range versions {
				if version.Image != nil {
					images = append(images, *version.Image)
				}
			}
		}
		for _, record := range pending {
			if record.Image != nil {
				images = append(images, *record.Image)
			}
		}
		return nil
	})
	if err == nil {
		for _, pool := range s.environments {
			for _, slot := range pool {
				if slot.image != nil {
					images = append(images, *slot.image)
				}
			}
		}
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return retainer.ReconcileImages(ctx, images)
}

// Called after a slot is released or collected, without Service.mu. Snapshots
// never acquire slot.mu, so cleanup cannot wait on an accepted customer call.
func (s *Service) reconcileExecutionImages(slot *execution) {
	s.mu.Lock()
	hasImage := slot.image != nil
	s.mu.Unlock()
	if !hasImage {
		return
	}
	s.imageMu.Lock()
	defer s.imageMu.Unlock()
	cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.reconcileImages(cleanup); err != nil {
		slog.Error("Lambda execution image retention reconciliation failed", "function", slot.key.ARN(), "error", err)
	}
}

func (s *Service) finishImageStage(ctx context.Context, wire **awswire.Error) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := s.reconcileImages(cleanup); err != nil {
		if *wire != nil {
			previous := *wire
			*wire = failure(previous.Code, previous.Message+"; reconciling owned image retention: "+err.Error(), previous.StatusCode)
		} else {
			*wire = failure("ServiceException", "Reconciling owned image retention: "+err.Error(), 500)
		}
	}
}
