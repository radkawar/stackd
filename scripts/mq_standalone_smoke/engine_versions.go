package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
)

// engine-versions starts with the explicitly supplied prior executable. Only
// that historical setup and the rejection probes use the old public version;
// the native engine and JMS client remain pinned to their actual 5.18.7 release.
func engineVersionsLifecycle(ctx context.Context, cloud *controller, newBinary string) {
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	evidencePath := filepath.Join(cloud.dir, "engine-versions-evidence.jsonl")
	file, err := os.OpenFile(evidencePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer file.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(file).Encode(map[string]any{"stage": stage, "at": time.Now().UTC(), "value": value}))
		must(file.Sync())
		fmt.Println("ActiveMQ engine versions:", stage)
	}
	record("explicit old/new executables and retained state", map[string]string{"priorBinary": cloud.binary, "newBinary": newBinary, "database": filepath.Join(cloud.dir, "state.db"), "nativeState": filepath.Join(cloud.dir, "native"), "priorAPIVersion": "5.18.7", "newAPIVersion": "5.18", "nativeVersion": "5.18.7"})

	configuration, err := c.CreateConfiguration(ctx, &mq.CreateConfigurationInput{Name: aws.String("engine-versions-owned"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18.7"), Tags: map[string]string{"owner": "engine-versions-smoke"}})
	must(err)
	cid := aws.ToString(configuration.Id)
	id := ""
	completed := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if cloud.cmd == nil {
			cloud.start(cleanup)
		}
		if id != "" {
			engineVersionDeleteBroker(cleanup, c, id, record)
		}
		deleted, err := c.DeleteConfiguration(cleanup, &mq.DeleteConfigurationInput{ConfigurationId: &cid})
		must(err)
		record("exact-owned DeleteConfiguration", deleted)
		_, err = c.DescribeConfiguration(cleanup, &mq.DescribeConfigurationInput{ConfigurationId: &cid})
		code(err, "NotFoundException")
		record("owned configuration absent", map[string]string{"configuration": cid, "result": err.Error()})
		if completed {
			record("PASS after exact-owned cleanup", map[string]string{"broker": id, "configuration": cid})
			fmt.Println("ActiveMQ prior/new executable migration + API 5.18 + unchanged native container/volume + persistent JMS bytes + modeled patch-version rejection + discovery + exact-owned cleanup: PASS")
			fmt.Println("ActiveMQ engine-version evidence:", evidencePath)
		}
	}()
	record("prior signed CreateConfiguration", configuration)
	brokerInput := func(name, version string) *mq.CreateBrokerInput {
		return &mq.CreateBrokerInput{BrokerName: aws.String(name), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String(version), HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Configuration: &types.ConfigurationId{Id: &cid, Revision: aws.Int32(1)}, Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123")}}}
	}
	created, err := c.CreateBroker(ctx, brokerInput("engine-versions-owned", "5.18.7"))
	must(err)
	id = aws.ToString(created.BrokerId)
	beforeBroker := running(ctx, c, id)
	beforeConfig, err := c.DescribeConfiguration(ctx, &mq.DescribeConfigurationInput{ConfigurationId: &cid})
	must(err)
	beforeRevision, err := c.DescribeConfigurationRevision(ctx, &mq.DescribeConfigurationRevisionInput{ConfigurationId: &cid, ConfigurationRevision: aws.String("1")})
	must(err)
	if aws.ToString(beforeBroker.EngineVersion) != "5.18.7" || aws.ToString(beforeConfig.EngineVersion) != "5.18.7" {
		panic("prior executable did not retain historical ActiveMQ API 5.18.7")
	}
	if beforeBroker.Configurations == nil || beforeBroker.Configurations.Current == nil || aws.ToString(beforeBroker.Configurations.Current.Id) != cid || aws.ToInt32(beforeBroker.Configurations.Current.Revision) != 1 || len(beforeBroker.BrokerInstances) != 1 || len(beforeBroker.BrokerInstances[0].Endpoints) == 0 {
		panic("prior broker omitted the exact-owned configuration or native endpoint")
	}
	record("prior signed broker/configuration/revision", map[string]any{"createBroker": created, "describeBroker": beforeBroker, "describeConfiguration": beforeConfig, "describeRevision": beforeRevision})
	beforeNative := engineVersionNative(ctx, id, aws.ToString(beforeBroker.BrokerArn))
	record("prior exact-owned native identity", beforeNative)

	// Include NUL and non-UTF-8 bytes so a text-message substitution cannot pass.
	payload := append([]byte{0, 1, 2, 10, 13, 127, 128, 254, 255}, []byte("engine-version-migration/"+id)...)
	body := base64.StdEncoding.EncodeToString(payload)
	payloadEvidence := map[string]any{"queue": "standalone-retained", "messageType": "BytesMessage", "deliveryMode": "PERSISTENT", "payloadBase64": body, "sha256": fmt.Sprintf("%x", sha256.Sum256(payload)), "bytes": len(payload)}
	must(jms(ctx, cloud, beforeBroker.BrokerInstances[0].Endpoints[0], "writer", "writer-password-123", "publish-bytes", body))
	record("prior persistent JMS bytes published", payloadEvidence)
	cloud.stop()
	record("prior controller exited", map[string]string{"binary": cloud.binary})
	cloud.binary = newBinary
	cloud.start(ctx)
	record("new controller started on same SQLite and native state", map[string]string{"binary": cloud.binary})

	afterBroker := running(ctx, c, id)
	afterConfig, err := c.DescribeConfiguration(ctx, &mq.DescribeConfigurationInput{ConfigurationId: &cid})
	must(err)
	afterRevision, err := c.DescribeConfigurationRevision(ctx, &mq.DescribeConfigurationRevisionInput{ConfigurationId: &cid, ConfigurationRevision: aws.String("1")})
	must(err)
	record("new signed broker/configuration/revision", map[string]any{"describeBroker": afterBroker, "describeConfiguration": afterConfig, "describeRevision": afterRevision})
	if aws.ToString(afterBroker.EngineVersion) != "5.18" || aws.ToString(afterConfig.EngineVersion) != "5.18" {
		panic("retained ActiveMQ API versions did not migrate to 5.18")
	}
	if aws.ToString(afterBroker.BrokerId) != id || aws.ToString(afterBroker.BrokerArn) != aws.ToString(beforeBroker.BrokerArn) || !reflect.DeepEqual(afterBroker.Configurations, beforeBroker.Configurations) || !reflect.DeepEqual(afterBroker.BrokerInstances, beforeBroker.BrokerInstances) || !reflect.DeepEqual(afterBroker.Users, beforeBroker.Users) || aws.ToString(afterConfig.Id) != cid || aws.ToString(afterConfig.Arn) != aws.ToString(beforeConfig.Arn) || !reflect.DeepEqual(afterConfig.LatestRevision, beforeConfig.LatestRevision) || !reflect.DeepEqual(afterConfig.Tags, beforeConfig.Tags) || aws.ToString(afterRevision.Data) != aws.ToString(beforeRevision.Data) {
		panic("migration changed retained broker/configuration identity, native endpoints, users, tags or revision bytes")
	}
	afterNative := engineVersionNative(ctx, id, aws.ToString(afterBroker.BrokerArn))
	record("new exact-owned native identity", afterNative)
	if !reflect.DeepEqual(afterNative, beforeNative) {
		panic("migration recreated or restarted the native container or changed its retained data volume")
	}
	must(jms(ctx, cloud, afterBroker.BrokerInstances[0].Endpoints[0], "writer", "writer-password-123", "consume-bytes", body))
	record("new native broker delivered exact retained persistent JMS bytes", payloadEvidence)

	// Both probes use the signed public SDK route, not a direct service handler.
	unexpectedConfiguration, err := c.CreateConfiguration(ctx, &mq.CreateConfigurationInput{Name: aws.String("engine-versions-rejected"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18.7")})
	if err == nil && unexpectedConfiguration != nil {
		_, deleteErr := c.DeleteConfiguration(ctx, &mq.DeleteConfigurationInput{ConfigurationId: unexpectedConfiguration.Id})
		must(deleteErr)
	}
	engineVersionReject("new CreateConfiguration rejects patch-qualified API version", err, record)
	rejectedBrokerInput := brokerInput("engine-versions-rejected", "5.18.7")
	// No attached configuration: a configuration/version mismatch must not
	// masquerade as engine-version admission rejecting the patch label.
	rejectedBrokerInput.Configuration = nil
	unexpectedBroker, err := c.CreateBroker(ctx, rejectedBrokerInput)
	if err == nil && unexpectedBroker != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		unexpectedCurrent, describeErr := c.DescribeBroker(cleanup, &mq.DescribeBrokerInput{BrokerId: unexpectedBroker.BrokerId})
		must(describeErr)
		engineVersionDeleteBroker(cleanup, c, aws.ToString(unexpectedBroker.BrokerId), record)
		if unexpectedCurrent.Configurations != nil && unexpectedCurrent.Configurations.Current != nil {
			_, deleteErr := c.DeleteConfiguration(cleanup, &mq.DeleteConfigurationInput{ConfigurationId: unexpectedCurrent.Configurations.Current.Id})
			must(deleteErr)
		}
	}
	engineVersionReject("new CreateBroker rejects patch-qualified API version", err, record)
	engineVersionDiscovery(ctx, c, record)
	completed = true
}

func engineVersionReject(stage string, err error, record func(string, any)) {
	var bad *types.BadRequestException
	if !errors.As(err, &bad) || bad.ErrorCode() != "BadRequestException" || aws.ToString(bad.ErrorAttribute) != "engineVersion" {
		panic(fmt.Sprintf("%s: wanted modeled BadRequestException with engineVersion, got %T: %v", stage, err, err))
	}
	record(stage, map[string]string{"errorCode": bad.ErrorCode(), "errorAttribute": aws.ToString(bad.ErrorAttribute), "message": bad.ErrorMessage()})
}

func engineVersionDiscovery(ctx context.Context, c *mq.Client, record func(string, any)) {
	engines, err := c.DescribeBrokerEngineTypes(ctx, &mq.DescribeBrokerEngineTypesInput{EngineType: aws.String("ACTIVEMQ")})
	must(err)
	record("new signed DescribeBrokerEngineTypes", engines)
	if aws.ToString(engines.NextToken) != "" || len(engines.BrokerEngineTypes) != 1 || engines.BrokerEngineTypes[0].EngineType != types.EngineTypeActivemq || len(engines.BrokerEngineTypes[0].EngineVersions) != 1 || aws.ToString(engines.BrokerEngineTypes[0].EngineVersions[0].Name) != "5.18" {
		panic("ActiveMQ engine discovery did not advertise only public API 5.18")
	}
	options, err := c.DescribeBrokerInstanceOptions(ctx, &mq.DescribeBrokerInstanceOptionsInput{EngineType: aws.String("ACTIVEMQ"), HostInstanceType: aws.String("mq.t3.micro")})
	must(err)
	record("new signed DescribeBrokerInstanceOptions", options)
	if aws.ToString(options.NextToken) != "" || len(options.BrokerInstanceOptions) == 0 {
		panic("ActiveMQ instance discovery omitted the native instance option")
	}
	for _, option := range options.BrokerInstanceOptions {
		if option.EngineType != types.EngineTypeActivemq || aws.ToString(option.HostInstanceType) != "mq.t3.micro" || len(option.SupportedEngineVersions) != 1 || option.SupportedEngineVersions[0] != "5.18" {
			panic("ActiveMQ instance discovery did not advertise only public API 5.18")
		}
	}
}

type engineVersionNativeIdentity struct {
	ContainerID, ContainerName, ContainerCreated, ImageID, ImageReference, StartedAt string
	VolumeName, VolumeCreated, VolumeMountpoint, VolumeDriver                        string
	Labels                                                                           map[string]string
}

func engineVersionNative(ctx context.Context, id, arn string) engineVersionNativeIdentity {
	out, err := exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "ps", "--all", "--no-trunc", "--filter", "label=stackd.mq.id="+id, "--format", "{{.ID}}").Output()
	must(err)
	ids := strings.Fields(string(out))
	if len(ids) != 1 {
		panic(fmt.Sprintf("expected one exact-owned native ActiveMQ container, got %v", ids))
	}
	out, err = exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "container", "inspect", ids[0]).Output()
	must(err)
	var containers []struct {
		ID, Name, Created, Image string
		Config                   struct {
			Image  string
			Labels map[string]string
		}
		State struct {
			Running   bool
			StartedAt string
		}
		Mounts []struct {
			Type, Name, Destination string
			RW                      bool
		}
	}
	must(json.Unmarshal(out, &containers))
	if len(containers) != 1 || !containers[0].State.Running || containers[0].Config.Labels["stackd.mq.id"] != id || containers[0].Config.Labels["stackd.mq.arn"] != arn {
		panic("native inspection did not identify the running exact-owned broker")
	}
	container := containers[0]
	volumeName := ""
	for _, mount := range container.Mounts {
		if mount.Destination == "/opt/apache-activemq/data" && mount.Type == "volume" && mount.RW {
			volumeName = mount.Name
		}
	}
	if volumeName == "" {
		panic("native ActiveMQ broker omitted its writable journal volume")
	}
	out, err = exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "volume", "inspect", volumeName).Output()
	must(err)
	var volumes []struct {
		Name, CreatedAt, Mountpoint, Driver string
		Labels                              map[string]string
	}
	must(json.Unmarshal(out, &volumes))
	if len(volumes) != 1 || volumes[0].Name != volumeName {
		panic("native volume ownership did not match the exact-owned broker")
	}
	volume := volumes[0]
	// Containers can inherit unrelated image labels; compare the ownership
	// labels shared with the data volume, not the entire Docker label map.
	for _, key := range []string{"stackd.mq.namespace", "stackd.mq.arn", "stackd.mq.id", "stackd.mq.layout"} {
		if volume.Labels[key] == "" || volume.Labels[key] != container.Config.Labels[key] {
			panic("native volume ownership did not match the exact-owned broker")
		}
	}
	return engineVersionNativeIdentity{ContainerID: container.ID, ContainerName: container.Name, ContainerCreated: container.Created, ImageID: container.Image, ImageReference: container.Config.Image, StartedAt: container.State.StartedAt, VolumeName: volume.Name, VolumeCreated: volume.CreatedAt, VolumeMountpoint: volume.Mountpoint, VolumeDriver: volume.Driver, Labels: volume.Labels}
}

func engineVersionDeleteBroker(ctx context.Context, c *mq.Client, id string, record func(string, any)) {
	deleted, err := c.DeleteBroker(ctx, &mq.DeleteBrokerInput{BrokerId: &id})
	must(err)
	record("exact-owned DeleteBroker", deleted)
	wait(ctx, func() (bool, error) {
		_, err := c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
		if err == nil {
			return false, nil
		}
		code(err, "NotFoundException")
		return true, nil
	})
	wait(ctx, func() (bool, error) {
		containers, err := exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "ps", "--all", "--filter", "label=stackd.mq.id="+id, "--format", "{{.ID}}").Output()
		if err != nil {
			return false, err
		}
		volumes, err := exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "volume", "ls", "--filter", "label=stackd.mq.id="+id, "--format", "{{.Name}}").Output()
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(string(containers)) != "" || strings.TrimSpace(string(volumes)) != "" {
			return false, nil
		}
		record("owned broker, native container and data volume absent", map[string]string{"broker": id, "containerIDs": string(containers), "volumeNames": string(volumes)})
		return true, nil
	})
}
