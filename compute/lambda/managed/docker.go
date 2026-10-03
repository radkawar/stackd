package managed

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"stackd/compute/docker"
	runtime "stackd/compute/lambda"
)

func (s *Server) startContainer(ctx context.Context, e *environment) error {
	spec := e.deployment.Specification
	image := ""
	for _, candidate := range s.config.Images {
		if candidate.Runtime == spec.Runtime && candidate.Architecture == spec.Architecture {
			image = candidate.Reference
			break
		}
	}
	if image == "" {
		return fmt.Errorf("managed runtime %s/%s has no installed image", spec.Runtime, spec.Architecture)
	}
	var imageInfo struct {
		ID, Architecture, Os string
		Config               struct{ Entrypoint []string }
	}
	if err := s.engine.JSON(ctx, "GET", "/images/"+url.PathEscape(image)+"/json", nil, &imageInfo); err != nil {
		return err
	}
	architecture := map[string]string{"x86_64": "amd64", "arm64": "arm64"}[spec.Architecture]
	if imageInfo.Os != "linux" || imageInfo.Architecture != architecture || architecture == "" {
		return errors.New("managed runtime image platform does not match the function")
	}
	if len(imageInfo.Config.Entrypoint) != 1 || imageInfo.Config.Entrypoint[0] != "/lambda-entrypoint.sh" {
		return errors.New("managed runtime image must implement the official Lambda entrypoint")
	}
	if err := runtime.ValidateDeploymentSize(spec.Code, spec.Layers); err != nil {
		return err
	}
	if err := os.MkdirAll(e.directory, 0700); err != nil {
		return err
	}
	for _, dir := range []string{"task", "opt", "tmp"} {
		if err := makeRuntimeDirectory(filepath.Join(e.directory, dir)); err != nil {
			return err
		}
	}
	if err := extractCode(spec.Code, filepath.Join(e.directory, "task")); err != nil {
		return err
	}
	for _, layer := range spec.Layers {
		if err := extractCode(layer, filepath.Join(e.directory, "opt")); err != nil {
			return err
		}
	}
	if entries, err := os.ReadDir(filepath.Join(e.directory, "opt", "extensions")); err == nil && len(entries) != 0 {
		// TODO: Comeback implement the managed guest Extensions/Telemetry lifecycle;
		// do not advertise readiness after silently skipping extension processes.
		return errors.New("managed guest external extensions are not implemented")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := mountTemporary(ctx, e.directory); err != nil {
		return err
	}
	arn := strings.Split(spec.FunctionARN, ":")
	if len(arn) != 8 || arn[0] != "arn" || arn[2] != "lambda" {
		return errors.New("managed deployment requires an immutable function-version ARN")
	}
	environment := []string{
		"AWS_LAMBDA_RUNTIME_API=" + e.listener.Addr().String(), "AWS_LAMBDA_MAX_CONCURRENCY=" + strconv.Itoa(e.deployment.MaxConcurrency),
		"AWS_LAMBDA_INITIALIZATION_TYPE=lambda-managed-instances", "AWS_LAMBDA_FUNCTION_NAME=" + spec.FunctionName, "AWS_LAMBDA_FUNCTION_VERSION=" + arn[7],
		"AWS_LAMBDA_FUNCTION_MEMORY_SIZE=" + strconv.Itoa(spec.MemoryMB), "AWS_REGION=" + arn[3], "AWS_DEFAULT_REGION=" + arn[3],
		"AWS_CONTAINER_CREDENTIALS_FULL_URI=http://" + e.listener.Addr().String() + "/credentials", "AWS_CONTAINER_AUTHORIZATION_TOKEN=" + e.credentialsToken,
		"AWS_EC2_METADATA_DISABLED=true", "LAMBDA_TASK_ROOT=/var/task", "LAMBDA_RUNTIME_DIR=/var/runtime", "_HANDLER=" + spec.Handler,
		"AWS_LAMBDA_LOG_GROUP_NAME=" + spec.LogGroup, "AWS_LAMBDA_LOG_STREAM_NAME=" + spec.LogStream,
	}
	if spec.Logging.Format == "JSON" {
		environment = append(environment, "AWS_LAMBDA_LOG_FORMAT=JSON", "AWS_LAMBDA_LOG_LEVEL="+spec.Logging.ApplicationLevel)
	} else {
		environment = append(environment, "AWS_LAMBDA_LOG_FORMAT=Text")
	}
	if spec.Endpoint != "" {
		environment = append(environment, "AWS_ENDPOINT_URL="+spec.Endpoint)
	}
	for name, value := range spec.Variables {
		reserved := false
		for _, setting := range environment {
			if key, _, _ := strings.Cut(setting, "="); key == name {
				reserved = true
				break
			}
		}
		if reserved || name == "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" || name == "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE" || name == "AWS_ACCESS_KEY_ID" || name == "AWS_SECRET_ACCESS_KEY" || name == "AWS_SESSION_TOKEN" {
			return fmt.Errorf("reserved managed environment variable %s", name)
		}
		environment = append(environment, name+"="+value)
	}
	labels := map[string]string{"stackd.lambda.capacity-provider": s.config.Identity.ProviderARN, "stackd.lambda.guest-generation": s.config.Identity.Generation, "stackd.lambda.environment": e.deployment.ID}
	config := docker.ContainerConfig{Image: imageInfo.ID, Entrypoint: []string{"/lambda-entrypoint.sh"}, Cmd: []string{spec.Handler}, Env: environment, WorkingDir: "/var/task", User: "993:993", Labels: labels, HostConfig: docker.ContainerHostConfig{
		NetworkMode: s.network, ReadonlyRootfs: true, Memory: int64(spec.MemoryMB) << 20, MemorySwap: int64(spec.MemoryMB) << 20, CPUPeriod: 100000, CPUQuota: int64(e.deployment.VCPUs) * 100000, PidsLimit: 4096,
		CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, LogConfig: docker.ContainerLogConfig{Type: "local", Config: map[string]string{"max-size": "10m", "max-file": "2"}},
		Mounts: []docker.ContainerMount{{Type: "bind", Source: filepath.Join(e.directory, "task"), Target: "/var/task", ReadOnly: true}, {Type: "bind", Source: filepath.Join(e.directory, "opt"), Target: "/opt", ReadOnly: true}, {Type: "bind", Source: filepath.Join(e.directory, "tmp"), Target: "/tmp"}},
	}}
	var created struct {
		ID string `json:"Id"`
	}
	if err := s.engine.JSON(ctx, "POST", "/containers/create?name="+e.container, config, &created); err != nil {
		return err
	}
	if err := s.engine.JSON(ctx, "POST", "/containers/"+e.container+"/start", nil, nil); err != nil {
		return err
	}
	var current struct {
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
		}
	}
	if err := s.engine.JSON(ctx, "GET", "/containers/"+e.container+"/json", nil, &current); err != nil {
		return err
	}
	e.containerIP = current.NetworkSettings.Networks[s.network].IPAddress
	if net.ParseIP(e.containerIP) == nil {
		return errors.New("managed container has no isolated runtime address")
	}
	return nil
}

func makeRuntimeDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	return os.Chmod(directory, 0755)
}

func makeCodeDirectory(root *os.Root, name string, directories map[string]struct{}) error {
	if name == "." {
		return nil
	}
	if _, exists := directories[name]; exists {
		return nil
	}
	if err := makeCodeDirectory(root, filepath.Dir(name), directories); err != nil {
		return err
	}
	if err := root.Mkdir(name, 0755); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := root.Stat(name)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("managed code path is not a directory: %s", name)
		}
	}
	if err := root.Chmod(name, 0755); err != nil {
		return err
	}
	directories[name] = struct{}{}
	return nil
}

func extractCode(code []byte, directory string) error {
	if err := runtime.ValidateCode(code); err != nil {
		return err
	}
	archive, err := zip.NewReader(bytes.NewReader(code), int64(len(code)))
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	directories := make(map[string]struct{})
	for _, entry := range archive.File {
		name := strings.TrimSuffix(entry.Name, "/")
		if entry.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("managed guest ZIP symbolic links are not implemented: %s", name)
		}
		if entry.FileInfo().IsDir() {
			if err = makeCodeDirectory(root, name, directories); err != nil {
				return err
			}
			continue
		}
		if err = makeCodeDirectory(root, filepath.Dir(name), directories); err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if entry.Mode().Perm()&0111 != 0 {
			mode = 0755
		}
		file, err := root.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		source, err := entry.Open()
		if err != nil {
			file.Close()
			return err
		}
		_, copyErr := io.Copy(file, source)
		modeErr := file.Chmod(mode)
		closeErr := errors.Join(source.Close(), file.Close())
		if err = errors.Join(copyErr, modeErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

func guestCommand(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("managed guest %s: %w: %s", name, err, out)
	}
	return nil
}
func mountedTemporary(ctx context.Context, directory string) (bool, error) {
	target := filepath.Join(directory, "tmp")
	out, err := exec.CommandContext(ctx, "findmnt", "--json", "--mountpoint", target, "--output", "SOURCE,TARGET").Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return false, nil
		}
		return false, err
	}
	var mounts struct {
		Filesystems []struct{ Source, Target string }
	}
	if err = json.Unmarshal(out, &mounts); err != nil {
		return false, err
	}
	if len(mounts.Filesystems) != 1 || mounts.Filesystems[0].Target != target {
		return false, errors.New("managed temporary filesystem mount differs")
	}
	out, err = exec.CommandContext(ctx, "losetup", "--json", "--output", "BACK-FILE", mounts.Filesystems[0].Source).Output()
	if err != nil {
		return false, err
	}
	var loops struct {
		Loopdevices []struct {
			BackingFile string `json:"back-file"`
		}
	}
	if err = json.Unmarshal(out, &loops); err != nil {
		return false, err
	}
	if len(loops.Loopdevices) != 1 || loops.Loopdevices[0].BackingFile != filepath.Join(directory, "tmp.ext4") {
		return false, errors.New("managed temporary filesystem belongs to another environment")
	}
	return true, nil
}
func mountTemporary(ctx context.Context, directory string) error {
	mounted, err := mountedTemporary(ctx, directory)
	if err != nil || mounted {
		return err
	}
	backing := filepath.Join(directory, "tmp.ext4")
	if _, err = os.Stat(backing); errors.Is(err, os.ErrNotExist) {
		file, err := os.OpenFile(backing, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		resizeErr := file.Truncate(512 << 20)
		closeErr := file.Close()
		if err = errors.Join(resizeErr, closeErr); err != nil {
			return err
		}
		if err = guestCommand(ctx, "mkfs.ext4", "-q", "-F", "-m", "0", backing); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	target := filepath.Join(directory, "tmp")
	if err = guestCommand(ctx, "mount", "-o", "loop,nosuid,nodev", backing, target); err != nil {
		return err
	}
	return os.Chmod(target, 0777)
}
func unmountTemporary(ctx context.Context, directory string) error {
	mounted, err := mountedTemporary(ctx, directory)
	if err != nil || !mounted {
		return err
	}
	return guestCommand(ctx, "umount", filepath.Join(directory, "tmp"))
}
