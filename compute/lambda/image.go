package lambda

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// ImageResolver inspects an installed local image without pulling it. Admission
// retains its native identity separately, before deployment state commits.
type ImageResolver interface {
	ResolveImage(context.Context, string, string) (Image, error)
}

// ImageRetainer owns daemon references independently of runtime environments.
// Reconciliation receives every active, pending and published deployment plus
// admitted execution leases, and releases only unreferenced owned artifacts.
type ImageRetainer interface {
	RetainImage(context.Context, Image) (Image, error)
	ReconcileImages(context.Context, []Image) error
}

type Image struct {
	URI, ID, ResolvedURI string
	// PinReference names a labeled, daemon-committed snapshot. ID/ResolvedURI
	// remain the admitted source identity; PinImageID is its actual distinct
	// native runtime identity. PinLease binds the artifact to its ownership labels.
	PinReference, PinLease, PinImageID string
	Size                               int64
	EntryPoint, Command, Environment   []string
	WorkingDirectory                   string
}

type ImageConfig struct {
	EntryPoint, Command []string
	WorkingDirectory    string
}

func CloneImage(in *Image) *Image {
	if in == nil {
		return nil
	}
	out := *in
	out.EntryPoint = slices.Clone(in.EntryPoint)
	out.Command = slices.Clone(in.Command)
	out.Environment = slices.Clone(in.Environment)
	return &out
}

func (d *DockerExecutor) ResolveImage(ctx context.Context, uri, architecture string) (Image, error) {
	platform := "amd64"
	if architecture == "arm64" {
		platform = "arm64"
	} else if architecture != "x86_64" {
		return Image{}, fmt.Errorf("unsupported Lambda architecture %q", architecture)
	}
	if uri == "" || strings.ContainsAny(uri, "\x00\r\n") {
		return Image{}, fmt.Errorf("image URI is required")
	}
	var info struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string
		Size         int64
		RepoDigests  []string
		Config       struct {
			Entrypoint, Cmd, Env []string
			WorkingDir           string
		}
	}
	if err := d.engine.JSON(ctx, "GET", "/images/"+url.PathEscape(uri)+"/json", nil, &info); err != nil {
		return Image{}, fmt.Errorf("lambda image %s is unavailable locally (automatic pull is disabled): %w", uri, err)
	}
	if info.OS != "linux" || info.Architecture != platform {
		return Image{}, fmt.Errorf("lambda image platform %s/%s does not match linux/%s", info.OS, info.Architecture, platform)
	}
	if !strings.HasPrefix(info.ID, "sha256:") || len(info.ID) != 71 {
		return Image{}, fmt.Errorf("docker image has no immutable sha256 identity")
	}
	if info.Size > 10<<30 {
		return Image{}, fmt.Errorf("lambda container image exceeds the 10 GiB image limit")
	}
	resolved := info.ID
	repository := strings.Split(uri, "@")[0]
	if colon := strings.LastIndex(repository, ":"); colon > strings.LastIndex(repository, "/") {
		repository = repository[:colon]
	}
	// Local images may have no registry digest. Do not invent one from a config ID.
	for _, digest := range info.RepoDigests {
		if strings.Split(digest, "@")[0] == repository {
			resolved = digest
			break
		}
	}
	return Image{URI: uri, ID: info.ID, ResolvedURI: resolved, Size: info.Size, EntryPoint: slices.Clone(info.Config.Entrypoint), Command: slices.Clone(info.Config.Cmd), Environment: slices.Clone(info.Config.Env), WorkingDirectory: info.Config.WorkingDir}, nil
}

func imageCommand(image *Image, config *ImageConfig) ([]string, string, error) {
	entrypoint, command, directory := image.EntryPoint, image.Command, image.WorkingDirectory
	if config != nil {
		if config.EntryPoint != nil {
			entrypoint = config.EntryPoint
		}
		if config.Command != nil {
			command = config.Command
		}
		if config.WorkingDirectory != "" {
			directory = config.WorkingDirectory
		}
	}
	args := append(slices.Clone(entrypoint), command...)
	if len(args) == 0 || args[0] == "" {
		return nil, "", fmt.Errorf("lambda image must configure a Runtime API client entrypoint or command")
	}
	if directory == "" {
		directory = "/"
	}
	return args, directory, nil
}
