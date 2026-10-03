package ecs

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	runtime "stackd/compute/ecs"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/identity"
)

const taskMetadataAddress = "http://169.254.170.2"

// TaskMetadataRuntime exposes native facts without keeping another task ledger.
// The lifecycle owner must reject calls until Prepare/reconnection completes.
type TaskMetadataRuntime interface {
	Inspect(context.Context) ([]runtime.ContainerStatus, error)
	Stats(context.Context, string) (json.RawMessage, error)
}

// newTaskMetadata is bound to one task by the source-IP-checking runtime proxy.
// Capabilities are read from current task state, never accepted as resource IDs.
// The lifecycle owner controls proxy retirement and credential source lifetime.
func newTaskMetadata(s *Service, key TaskKey, credentials TaskCredentialSource, native TaskMetadataRuntime) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			taskMetadataError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Only GET is supported.")
			return
		}
		// Do not clean paths or decode an escaped capability into a valid one.
		if r.URL.EscapedPath() != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		var record TaskRecord
		err := s.repository.View(r.Context(), func(reader Reader) error {
			var err error
			record, err = reader.Task(key)
			return err
		})
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			taskMetadataError(w, http.StatusServiceUnavailable, "MetadataUnavailable", "Unable to read current task state.")
			return
		}
		if token, ok := strings.CutPrefix(r.URL.Path, "/v2/credentials/"); ok {
			if !taskCapabilityMatches(token, record.CredentialToken) || taskRoleARN(record) == "" {
				http.NotFound(w, r)
				return
			}
			if credentials == nil {
				taskMetadataError(w, http.StatusServiceUnavailable, "CredentialsUnavailable", "Task role credentials are not available.")
				return
			}
			credential, rejected := credentials(r.Context())
			if rejected != nil {
				taskMetadataError(w, http.StatusServiceUnavailable, rejected.Code, rejected.Message)
				return
			}
			// Fail closed if the integration supplies execution-role, long-term,
			// incomplete or expired credentials instead of the selected task role.
			if credential.IssuerARN != taskRoleARN(record) || credential.AccountID != key.AccountID || credential.SessionType != identity.SessionTypeAssumeRole || credential.AccessKeyID == "" || credential.SecretAccessKey == "" || credential.SessionToken == "" || !credential.Expiration.After(s.clock.Now()) {
				taskMetadataError(w, http.StatusServiceUnavailable, "CredentialsUnavailable", "Valid task role session credentials are not available.")
				return
			}
			taskMetadataJSON(w, http.StatusOK, taskMetadataCredentials{
				RoleARN: credential.IssuerARN, AccessKeyID: credential.AccessKeyID,
				SecretAccessKey: credential.SecretAccessKey, Token: credential.SessionToken,
				Expiration: credential.Expiration.UTC().Format(time.RFC3339),
			})
			return
		}
		path, ok := strings.CutPrefix(r.URL.Path, "/v4/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		token, suffix, hasSuffix := strings.Cut(path, "/")
		var container *api.Container
		for i := range record.Data.Containers {
			candidate := &record.Data.Containers[i]
			if taskCapabilityMatches(token, record.MetadataTokens[value(candidate.Name)]) {
				container = candidate
				break
			}
		}
		if container == nil {
			http.NotFound(w, r)
			return
		}
		if hasSuffix {
			switch suffix {
			case "task", "stats", "task/stats":
			case "taskWithTags":
				// Fargate's documented v4 paths exclude taskWithTags. The EC2
				// endpoint requires role-authorized ListTagsForResource calls;
				// reading private TagRecord data would bypass that authority.
				taskMetadataError(w, http.StatusNotImplemented, "TagMetadataUnavailable", "Task tag metadata requires an evidenced Fargate role and authorized ListTagsForResource integration.")
				return
			default:
				http.NotFound(w, r)
				return
			}
		}
		if native == nil {
			taskMetadataError(w, http.StatusServiceUnavailable, "MetadataUnavailable", "The task runtime is not ready.")
			return
		}
		observed, err := native.Inspect(r.Context())
		if err != nil {
			taskMetadataError(w, http.StatusServiceUnavailable, "MetadataUnavailable", "Unable to inspect the task runtime.")
			return
		}
		for _, current := range record.Data.Containers {
			status, found := metadataNativeContainer(observed, value(current.Name))
			if !found || status.RuntimeID == "" || (value(current.RuntimeId) != "" && value(current.RuntimeId) != status.RuntimeID) {
				taskMetadataError(w, http.StatusServiceUnavailable, "MetadataUnavailable", "Task container runtime identity is not available.")
				return
			}
		}
		switch {
		case !hasSuffix:
			status, _ := metadataNativeContainer(observed, value(container.Name))
			taskMetadataJSON(w, http.StatusOK, metadataContainer(record, *container, status))
		case suffix == "task":
			taskMetadataJSON(w, http.StatusOK, metadataTask(record, observed))
		case suffix == "stats":
			stats, err := native.Stats(r.Context(), value(container.Name))
			if err != nil {
				taskMetadataError(w, http.StatusServiceUnavailable, "StatsUnavailable", "Unable to read native container statistics.")
				return
			}
			taskMetadataJSON(w, http.StatusOK, stats)
		case suffix == "task/stats":
			stats := make(map[string]json.RawMessage, len(record.Data.Containers))
			for _, current := range record.Data.Containers {
				body, err := native.Stats(r.Context(), value(current.Name))
				if err != nil {
					taskMetadataError(w, http.StatusServiceUnavailable, "StatsUnavailable", "Unable to read native task container statistics.")
					return
				}
				status, _ := metadataNativeContainer(observed, value(current.Name))
				stats[status.RuntimeID] = body
			}
			taskMetadataJSON(w, http.StatusOK, stats)
		}
	})
}

func taskCapabilityMatches(supplied, retained string) bool {
	return retained != "" && subtle.ConstantTimeCompare([]byte(supplied), []byte(retained)) == 1
}

func taskServiceEnvironment(record TaskRecord, containerName, endpoint string) []string {
	out := []string{
		"AWS_EXECUTION_ENV=AWS_ECS_FARGATE",
		"AWS_REGION=" + record.Key.Region,
		"AWS_DEFAULT_REGION=" + record.Key.Region,
	}
	if token := record.MetadataTokens[containerName]; token != "" {
		out = append(out, "ECS_CONTAINER_METADATA_URI_V4="+taskMetadataAddress+"/v4/"+token)
	}
	if taskRoleARN(record) != "" && record.CredentialToken != "" {
		out = append(out, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/"+record.CredentialToken)
	}
	if endpoint != "" {
		out = append(out, "AWS_ENDPOINT_URL="+endpoint)
	}
	return out
}

type taskMetadataCredentials struct {
	RoleARN         string `json:"RoleArn"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

type taskMetadataDocument struct {
	Cluster            string                  `json:"Cluster"`
	TaskARN            string                  `json:"TaskARN"`
	Family             string                  `json:"Family"`
	Revision           string                  `json:"Revision"`
	DesiredStatus      string                  `json:"DesiredStatus"`
	KnownStatus        string                  `json:"KnownStatus"`
	Limits             map[string]float64      `json:"Limits,omitempty"`
	PullStartedAt      *time.Time              `json:"PullStartedAt,omitempty"`
	PullStoppedAt      *time.Time              `json:"PullStoppedAt,omitempty"`
	ExecutionStoppedAt *time.Time              `json:"ExecutionStoppedAt,omitempty"`
	AvailabilityZone   string                  `json:"AvailabilityZone,omitempty"`
	LaunchType         string                  `json:"LaunchType,omitempty"`
	Containers         []taskMetadataContainer `json:"Containers"`
}

type taskMetadataContainer struct {
	DockerID      string                `json:"DockerId,omitempty"`
	DockerName    string                `json:"DockerName"`
	Labels        map[string]string     `json:"Labels,omitempty"`
	Limits        map[string]int64      `json:"Limits,omitempty"`
	CreatedAt     *time.Time            `json:"CreatedAt,omitempty"`
	StartedAt     *time.Time            `json:"StartedAt,omitempty"`
	FinishedAt    *time.Time            `json:"FinishedAt,omitempty"`
	Name          string                `json:"Name"`
	Image         string                `json:"Image"`
	ImageID       string                `json:"ImageID,omitempty"`
	DesiredStatus string                `json:"DesiredStatus"`
	KnownStatus   string                `json:"KnownStatus"`
	ExitCode      *api.BoxedInteger     `json:"ExitCode,omitempty"`
	Type          string                `json:"Type"`
	LogDriver     string                `json:"LogDriver,omitempty"`
	LogOptions    map[string]string     `json:"LogOptions,omitempty"`
	ContainerARN  string                `json:"ContainerARN,omitempty"`
	Networks      []taskMetadataNetwork `json:"Networks,omitempty"`
}

type taskMetadataNetwork struct {
	NetworkMode     string   `json:"NetworkMode"`
	IPv4Addresses   []string `json:"IPv4Addresses,omitempty"`
	IPv6Addresses   []string `json:"IPv6Addresses,omitempty"`
	AttachmentIndex *int     `json:"AttachmentIndex,omitempty"`
	MACAddress      string   `json:"MACAddress,omitempty"`
}

func metadataTask(record TaskRecord, observed []runtime.ContainerStatus) taskMetadataDocument {
	data := record.Data
	out := taskMetadataDocument{
		Cluster: record.Key.ClusterKey.ARN(), TaskARN: record.Key.ARN(),
		Family: value(record.Definition.Family), DesiredStatus: value(data.DesiredStatus), KnownStatus: value(data.LastStatus),
		PullStartedAt: data.PullStartedAt, PullStoppedAt: data.PullStoppedAt, ExecutionStoppedAt: data.ExecutionStoppedAt,
		AvailabilityZone: value(data.AvailabilityZone), LaunchType: value(data.LaunchType),
		Containers: make([]taskMetadataContainer, 0, len(data.Containers)),
	}
	if record.Definition.Revision != nil {
		out.Revision = strconv.FormatInt(int64(*record.Definition.Revision), 10)
	}
	if cpu, err := strconv.ParseFloat(value(data.Cpu), 64); err == nil && cpu > 0 {
		out.Limits = map[string]float64{"CPU": cpu / 1024}
	}
	if memory, err := strconv.ParseFloat(value(data.Memory), 64); err == nil && memory > 0 {
		if out.Limits == nil {
			out.Limits = make(map[string]float64, 1)
		}
		out.Limits["Memory"] = memory
	}
	for _, container := range data.Containers {
		status, _ := metadataNativeContainer(observed, value(container.Name))
		out.Containers = append(out.Containers, metadataContainer(record, container, status))
	}
	return out
}

func metadataContainer(record TaskRecord, container api.Container, native runtime.ContainerStatus) taskMetadataContainer {
	out := taskMetadataContainer{
		DockerID: native.RuntimeID, DockerName: native.DockerName, Labels: native.Labels,
		Name: value(container.Name), Image: value(container.Image), ImageID: native.ImageDigest,
		DesiredStatus: value(record.Data.DesiredStatus), KnownStatus: value(container.LastStatus), ExitCode: container.ExitCode,
		Type: "NORMAL", ContainerARN: value(container.ContainerArn),
	}
	for _, definition := range record.Definition.ContainerDefinitions {
		if value(definition.Name) != out.Name {
			continue
		}
		if config := definition.LogConfiguration; config != nil {
			out.LogDriver = value(config.LogDriver)
			out.LogOptions = make(map[string]string, len(config.Options))
			for key, option := range config.Options {
				out.LogOptions[string(key)] = string(option)
			}
			if out.LogDriver == "awslogs" {
				// The awslogs adapter resolves the same immutable prefix to
				// this stream before allowing the container to start.
				if prefix := out.LogOptions["awslogs-stream-prefix"]; prefix != "" {
					out.LogOptions["awslogs-stream"] = prefix + "/" + out.Name + "/" + record.Key.ID
					delete(out.LogOptions, "awslogs-stream-prefix")
				}
				if out.LogOptions["mode"] == "" {
					out.LogOptions["mode"] = "non-blocking"
				}
			}
		}
		break
	}
	if native.CPUShares > 0 {
		out.Limits = map[string]int64{"CPU": native.CPUShares}
	}
	if native.MemoryBytes > 0 {
		if out.Limits == nil {
			out.Limits = make(map[string]int64, 1)
		}
		out.Limits["Memory"] = native.MemoryBytes / (1024 * 1024)
	}
	if !native.CreatedAt.IsZero() {
		out.CreatedAt = &native.CreatedAt
	}
	if !native.StartedAt.IsZero() {
		out.StartedAt = &native.StartedAt
	}
	if !native.FinishedAt.IsZero() {
		out.FinishedAt = &native.FinishedAt
	}
	for _, network := range container.NetworkInterfaces {
		entry := taskMetadataNetwork{NetworkMode: value(record.Definition.NetworkMode)}
		if ip := value(network.PrivateIpv4Address); ip != "" {
			entry.IPv4Addresses = []string{ip}
		}
		if ip := value(network.Ipv6Address); ip != "" {
			entry.IPv6Addresses = []string{ip}
		}
		if id := value(network.AttachmentId); id != "" {
			for i, attachment := range record.Data.Attachments {
				if value(attachment.Id) != id {
					continue
				}
				entry.AttachmentIndex = new(i)
				for _, detail := range attachment.Details {
					if value(detail.Name) == "macAddress" {
						entry.MACAddress = value(detail.Value)
					}
				}
				break
			}
		}
		out.Networks = append(out.Networks, entry)
	}
	return out
}

func metadataNativeContainer(observed []runtime.ContainerStatus, name string) (runtime.ContainerStatus, bool) {
	for _, container := range observed {
		if container.Name == name {
			return container, true
		}
	}
	return runtime.ContainerStatus{}, false
}

func taskMetadataError(w http.ResponseWriter, status int, code, message string) {
	taskMetadataJSON(w, status, struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{code, message})
}

func taskMetadataJSON(w http.ResponseWriter, status int, document any) {
	body, err := json.Marshal(document)
	if err != nil {
		http.Error(w, "Unable to encode task metadata.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
