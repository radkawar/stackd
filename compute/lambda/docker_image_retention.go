package lambda

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"stackd/compute/docker"
)

const imagePinKind = "lambda-image-pin"
const imagePinReferenceLabel = "io.stackd.lambda.image.reference"
const imagePinIDLabel = "io.stackd.lambda.image.id"

// Commit creates the derived image with its ownership labels before assigning
// its unique tag. Thus even an accepted commit completing after a transport
// failure remains discoverable by native image labels, independently of the
// staging container. The customer container is only created, never started.
func (d *DockerExecutor) RetainImage(ctx context.Context, image Image) (Image, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.lifetime == nil || d.lifetime.Err() != nil {
		return Image{}, fmt.Errorf("lambda Docker instance owner is closed")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopOwnership := context.AfterFunc(d.lifetime, cancel)
	defer stopOwnership()
	if image.PinReference != "" || image.PinLease != "" || image.PinImageID != "" || !nativeImageID(image.ID) {
		return Image{}, fmt.Errorf("lambda image admission requires an unretained native image identity")
	}
	var source struct {
		ID     string `json:"Id"`
		Config map[string]json.RawMessage
	}
	if err := d.engine.JSON(ctx, "GET", "/images/"+url.PathEscape(image.ID)+"/json", nil, &source); err != nil {
		return Image{}, fmt.Errorf("reading admitted Lambda image configuration: %w", err)
	}
	if source.ID != image.ID || source.Config == nil {
		return Image{}, fmt.Errorf("admitted Lambda image has lost its native identity or configuration")
	}
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		return Image{}, err
	}
	image.PinLease, image.PinReference = d.imagePinNames(hex.EncodeToString(token[:]))
	labels := map[string]string{namespaceLabel: d.config.Namespace, controllerLabel: d.owner, "io.stackd.kind": imagePinKind, imagePinReferenceLabel: image.PinReference, imagePinIDLabel: image.ID}
	var imageLabels map[string]string
	if raw := source.Config["Labels"]; len(raw) != 0 {
		if err := json.Unmarshal(raw, &imageLabels); err != nil {
			return Image{}, err
		}
	}
	if imageLabels == nil {
		imageLabels = make(map[string]string)
	}
	for key, value := range labels {
		imageLabels[key] = value
	}
	rawLabels, err := json.Marshal(imageLabels)
	if err != nil {
		return Image{}, err
	}
	source.Config["Labels"] = rawLabels
	// An image can intentionally have no default command and rely on ImageConfig.
	// Create still needs an executable, but never start this staging container.
	// Explicit empty defaults prevent commit's nil-field merge from inheriting
	// the inert staging entrypoint instead of the source's empty default.
	for _, key := range []string{"Entrypoint", "Cmd"} {
		if raw := source.Config[key]; len(raw) == 0 || string(raw) == "null" {
			source.Config[key] = json.RawMessage("[]")
		}
	}
	marker := docker.ContainerConfig{Image: image.ID, Entrypoint: []string{"/bin/true"}, Cmd: []string{}, Labels: labels, HostConfig: docker.ContainerHostConfig{NetworkMode: "none", ReadonlyRootfs: true, LogConfig: docker.ContainerLogConfig{Type: "none"}}}
	if err := d.engine.JSON(ctx, "POST", "/containers/create?name="+url.QueryEscape(image.PinLease), marker, nil); err != nil {
		return Image{}, fmt.Errorf("staging owned Lambda image retention: %w", err)
	}
	repository, tag, _ := strings.Cut(image.PinReference, ":")
	var committed struct {
		ID string `json:"Id"`
	}
	if err := d.engine.JSON(ctx, "POST", "/commit?container="+url.QueryEscape(image.PinLease)+"&repo="+url.QueryEscape(repository)+"&tag="+url.QueryEscape(tag)+"&pause=false", source.Config, &committed); err != nil {
		return Image{}, fmt.Errorf("committing owned Lambda image retention for %s: %w", image.ID, err)
	}
	if !nativeImageID(committed.ID) || committed.ID == image.ID {
		return Image{}, fmt.Errorf("docker commit returned no distinct native owned image identity")
	}
	image.PinImageID = committed.ID
	if d.imagePins == nil {
		d.imagePins = make(map[string]Image)
	}
	d.imagePins[image.PinLease] = image
	if err := d.verifyImagePin(ctx, image); err != nil {
		delete(d.imagePins, image.PinLease)
		return Image{}, err
	}
	return image, nil
}

func nativeImageID(id string) bool {
	return len(id) == 71 && strings.HasPrefix(id, "sha256:") && strings.Trim(id[7:], "0123456789abcdef") == ""
}

func (d *DockerExecutor) imagePinNames(token string) (string, string) {
	sum := sha256.Sum256([]byte(d.config.Namespace))
	return fmt.Sprintf("stackd-lambda-image-pin-%x-%s", sum[:16], token), fmt.Sprintf("stackd-lambda-retained-%x:%s", sum[:16], token)
}

func (d *DockerExecutor) imagePin(item nativeContainer) (Image, error) {
	if item.Labels[namespaceLabel] != d.config.Namespace || item.Labels["io.stackd.kind"] != imagePinKind {
		return Image{}, fmt.Errorf("native image marker %s is outside the Lambda instance", item.ID)
	}
	image, err := d.imagePinLabels(item.Labels)
	if err != nil {
		return Image{}, err
	}
	if !containsName(item.Names, image.PinLease) {
		return Image{}, fmt.Errorf("native Lambda image marker %s does not own its alias", item.ID)
	}
	return image, nil
}

func (d *DockerExecutor) imagePinLabels(labels map[string]string) (Image, error) {
	reference := labels[imagePinReferenceLabel]
	_, token, ok := strings.Cut(reference, ":")
	if labels[namespaceLabel] != d.config.Namespace || labels["io.stackd.kind"] != imagePinKind || !ok || len(token) != 48 || strings.Trim(token, "0123456789abcdef") != "" || !nativeImageID(labels[imagePinIDLabel]) {
		return Image{}, fmt.Errorf("invalid native Lambda image ownership labels")
	}
	lease, expected := d.imagePinNames(token)
	if reference != expected {
		return Image{}, fmt.Errorf("native Lambda image labels do not own their alias")
	}
	return Image{ID: labels[imagePinIDLabel], PinReference: reference, PinLease: lease}, nil
}

func (d *DockerExecutor) verifyImagePin(ctx context.Context, image Image) error {
	var info struct {
		ID     string `json:"Id"`
		Config struct{ Labels map[string]string }
	}
	if err := d.engine.JSON(ctx, "GET", "/images/"+url.PathEscape(image.PinReference)+"/json", nil, &info); err != nil {
		return fmt.Errorf("retained Lambda image %s (%s) is unavailable locally; automatic pull is disabled: %w", image.ID, image.PinReference, err)
	}
	owned, err := d.imagePinLabels(info.Config.Labels)
	if err != nil || owned.ID != image.ID || owned.PinLease != image.PinLease || info.ID != image.PinImageID {
		return fmt.Errorf("owned Lambda image alias %s changed native identity or ownership: want %s, got %s", image.PinReference, image.PinImageID, info.ID)
	}
	return nil
}

func (d *DockerExecutor) ReconcileImages(ctx context.Context, images []Image) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.lifetime == nil || d.lifetime.Err() != nil {
		return fmt.Errorf("lambda Docker instance owner is closed")
	}
	wanted := make(map[string]Image, len(images))
	for _, image := range images {
		if image.PinReference == "" || image.PinLease == "" || !nativeImageID(image.ID) || !nativeImageID(image.PinImageID) || image.PinImageID == image.ID {
			return fmt.Errorf("lambda deployment %s has no owned native image retention; redeploy the locally installed image", image.URI)
		}
		if previous, exists := wanted[image.PinLease]; exists && (previous.PinReference != image.PinReference || previous.ID != image.ID || previous.PinImageID != image.PinImageID) {
			return fmt.Errorf("conflicting Lambda image retention records for %s", image.PinLease)
		}
		wanted[image.PinLease] = image
	}
	d.imagePins, d.imagePinsReady = wanted, true
	return d.reconcileImagePins(ctx)
}

type nativePinnedImage struct {
	ID          string `json:"Id"`
	RepoTags    []string
	RepoDigests []string
	Labels      map[string]string
}

// Caller holds d.mu and the daemon owner flock. Native images are the durable
// inventory, including commits that appear after staging failed or a crash.
func (d *DockerExecutor) reconcileImagePins(ctx context.Context) error {
	if !d.imagePinsReady {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopOwnership := context.AfterFunc(d.lifetime, cancel)
	defer stopOwnership()
	if d.lifetime.Err() != nil {
		return fmt.Errorf("lambda instance ownership was lost")
	}
	var artifacts []nativePinnedImage
	if err := d.engine.JSON(ctx, "GET", "/images/json?all=true&filters="+d.filters(imagePinKind), nil, &artifacts); err != nil {
		return err
	}
	var errs []error
	found := make(map[string]bool, len(artifacts))
	for _, artifact := range artifacts {
		image, err := d.imagePinLabels(artifact.Labels)
		if err != nil || !nativeImageID(artifact.ID) || artifact.ID == image.ID {
			errs = append(errs, fmt.Errorf("invalid owned Lambda image artifact %s", artifact.ID))
			continue
		}
		image.PinImageID = artifact.ID
		if wanted, retain := d.imagePins[image.PinLease]; retain && wanted.PinImageID == artifact.ID {
			found[image.PinLease] = true
			if err := d.verifyImagePin(ctx, wanted); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := d.removeImagePin(ctx, artifact, image); err != nil {
			errs = append(errs, err)
		}
	}
	for lease := range d.imagePins {
		if !found[lease] {
			errs = append(errs, fmt.Errorf("deployed Lambda image has lost its native owned artifact %s", lease))
		}
	}
	markers, err := d.containers(ctx, imagePinKind)
	if err != nil {
		return errors.Join(errors.Join(errs...), err)
	}
	for _, marker := range markers {
		image, err := d.imagePin(marker)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// A late commit remains labeled and independently collectible even if
		// it had not yet created an image when this staging container is removed.
		if _, retain := d.imagePins[image.PinLease]; !retain {
			if err := d.engine.RemoveContainer(ctx, marker.ID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (d *DockerExecutor) removeImagePin(ctx context.Context, artifact nativePinnedImage, image Image) error {
	ownTag, foreignTag := false, len(artifact.RepoDigests) != 0
	for _, tag := range artifact.RepoTags {
		if tag == image.PinReference {
			ownTag = true
		} else if tag != "<none>:<none>" {
			foreignTag = true
		}
	}
	if foreignTag && !ownTag {
		return nil
	}
	identity := artifact.ID
	if ownTag {
		if err := d.verifyImagePin(ctx, image); err != nil {
			return err
		}
		identity = image.PinReference
	}
	// Never remove the admitted source ID, a foreign tag, or a registry digest.
	if err := d.deleteImagePin(ctx, identity); err != nil {
		return err
	}
	if !ownTag || foreignTag {
		return nil
	}
	// A successful tag deletion can leave a native dangling image (for example
	// containerd preserves a parent reference). Reclaim that exact derived
	// identity now rather than depending on the periodic late-effect inventory.
	var remaining struct {
		ID          string `json:"Id"`
		RepoTags    []string
		RepoDigests []string
		Config      struct{ Labels map[string]string }
	}
	err := d.engine.JSON(ctx, "GET", "/images/"+url.PathEscape(artifact.ID)+"/json", nil, &remaining)
	var remote *docker.Error
	if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading released Lambda image artifact %s: %w", artifact.ID, err)
	}
	owned, err := d.imagePinLabels(remaining.Config.Labels)
	if err != nil || remaining.ID != artifact.ID || owned.ID != image.ID || owned.PinLease != image.PinLease {
		return fmt.Errorf("released Lambda image artifact %s changed native identity or ownership", artifact.ID)
	}
	if len(remaining.RepoDigests) != 0 {
		return nil
	}
	for _, tag := range remaining.RepoTags {
		if tag != "<none>:<none>" {
			return nil
		}
	}
	return d.deleteImagePin(ctx, artifact.ID)
}

func (d *DockerExecutor) deleteImagePin(ctx context.Context, identity string) error {
	err := d.engine.JSON(ctx, "DELETE", "/images/"+url.PathEscape(identity)+"?noprune=true", nil, nil)
	var remote *docker.Error
	if err != nil && (!errors.As(err, &remote) || remote.StatusCode != http.StatusNotFound) {
		return fmt.Errorf("releasing owned Lambda image artifact %s: %w", identity, err)
	}
	return nil
}
