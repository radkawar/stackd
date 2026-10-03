package codebuild

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"path"
	runtime "stackd/compute/codebuild"
	api "stackd/internal/awsapi/codebuild"
	"strings"
)

func logDestination(r BuildRecord) (string, string) {
	group := "/aws/codebuild/" + value(r.Data.ProjectName)
	_, id, _ := strings.Cut(r.Key.ID, ":")
	stream := id
	if config := r.Logs.CloudWatchLogs; config != nil {
		if value(config.GroupName) != "" {
			group = value(config.GroupName)
		}
		if value(config.StreamName) != "" {
			stream = value(config.StreamName) + "/" + id
		}
	}
	return group, stream
}
func (c *controller) publishLogs(ctx context.Context, r BuildRecord, e runtime.Execution) error {
	data, next, err := e.Logs(ctx, r.LogOffset)
	if err != nil {
		return err
	}
	if next == r.LogOffset {
		return nil
	}
	enabled := r.Logs.CloudWatchLogs != nil && value(r.Logs.CloudWatchLogs.Status) == "ENABLED"
	if enabled && len(data) > 0 {
		if c.s.logs == nil {
			return errors.New("CloudWatch Logs adapter is unavailable")
		}
		command, err := c.roleContext(ctx, r)
		if err != nil {
			return err
		}
		group, stream := logDestination(r)
		if err = c.s.logs.Write(command, group, stream, data, c.s.clock.Now()); err != nil {
			return err
		}
	}
	return c.s.repository.Update(c.ctx, func(tx Transaction) error {
		latest, err := tx.Build(r.Key)
		if err != nil {
			return err
		}
		if latest.LogOffset != r.LogOffset {
			return nil
		}
		latest.LogOffset = next
		if enabled {
			group, stream := logDestination(r)
			if latest.Data.Logs == nil {
				latest.Data.Logs = &api.LogsLocation{}
			}
			latest.Data.Logs.GroupName = new(api.String(group))
			latest.Data.Logs.StreamName = new(api.String(stream))
			latest.Data.Logs.CloudWatchLogs = r.Logs.CloudWatchLogs
			latest.Data.Logs.CloudWatchLogsArn = new(api.String("arn:" + r.Key.Partition + ":logs:" + r.Key.Region + ":" + r.Key.AccountID + ":log-group:" + group + ":log-stream:" + stream))
		}
		return tx.PutBuild(latest)
	})
}
func archiveFiles(files []runtime.File) ([]byte, error) {
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for _, file := range files {
		if path.IsAbs(file.Path) || path.Clean(file.Path) == ".." || strings.HasPrefix(path.Clean(file.Path), "../") {
			return nil, errors.New("artifact path escapes workspace")
		}
		header := &zip.FileHeader{Name: file.Path, Method: zip.Deflate}
		header.SetMode(fs.FileMode(file.Mode))
		entry, err := writer.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err = entry.Write(file.Body); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}
func (c *controller) publishOutputs(ctx context.Context, r BuildRecord, e runtime.Execution, artifactNames map[string]string) error {
	if c.s.objects == nil && (value(r.Artifacts.Type) == "S3" || len(r.SecondaryArtifacts) != 0 || len(r.PipelineOutputs) != 0 || r.Data.Cache != nil && value(r.Data.Cache.Type) == "S3") {
		return errors.New("S3 publication adapter is unavailable")
	}
	command, err := c.roleContext(ctx, r)
	if err != nil {
		return err
	}
	var failures []error
	if value(r.Artifacts.Type) == "S3" {
		if err = c.publishArtifacts(command, r, e, r.Artifacts, "artifacts", artifactNames["artifacts"]); err != nil {
			failures = append(failures, err)
		}
	}
	if value(r.Artifacts.Type) == "CODEPIPELINE" {
		if err = c.publishPipelineArtifacts(command, r, e); err != nil {
			failures = append(failures, err)
		}
	}
	for _, artifact := range r.SecondaryArtifacts {
		selector := "artifacts:" + value(artifact.ArtifactIdentifier)
		if err = c.publishArtifacts(command, r, e, artifact, selector, artifactNames[selector]); err != nil {
			failures = append(failures, err)
		}
	}
	if r.Data.Cache != nil && value(r.Data.Cache.Type) == "S3" {
		files, eErr := e.Files(ctx, "cache")
		if eErr == nil && len(files) > 0 {
			var archive []byte
			archive, eErr = archiveFiles(files)
			if eErr == nil {
				bucket, key, locationErr := cacheLocation(r)
				eErr = locationErr
				if eErr == nil {
					eErr = c.s.objects.Write(command, bucket, key, archive, value(r.Data.EncryptionKey))
				}
			}
		}
		if eErr != nil {
			failures = append(failures, eErr)
		}
	}
	if config := r.Logs.S3Logs; config != nil && value(config.Status) == "ENABLED" {
		data, _, eErr := e.Logs(ctx, 0)
		if eErr == nil {
			bucket, key, locationErr := objectPrefixLocation(value(config.Location))
			eErr = locationErr
			if eErr == nil {
				_, id, _ := strings.Cut(r.Key.ID, ":")
				key = path.Join(key, id+".log")
				kms := value(r.Data.EncryptionKey)
				if config.EncryptionDisabled != nil && *config.EncryptionDisabled {
					kms = ""
				}
				eErr = c.s.objects.Write(command, bucket, key, data, kms)
				if eErr == nil {
					eErr = c.s.repository.Update(ctx, func(tx Transaction) error {
						latest, err := tx.Build(r.Key)
						if err != nil {
							return err
						}
						if latest.Data.Logs == nil {
							latest.Data.Logs = &api.LogsLocation{}
						}
						latest.Data.Logs.S3Logs = config
						latest.Data.Logs.S3LogsArn = new(api.String("arn:" + r.Key.Partition + ":s3:::" + bucket + "/" + key))
						return tx.PutBuild(latest)
					})
				}
			}
		}
		if eErr != nil {
			failures = append(failures, eErr)
		}
	}
	return errors.Join(failures...)
}
func artifactKey(r *BuildRecord, config api.ProjectArtifacts, artifactName string) string {
	prefix := strings.Trim(value(config.Path), "/")
	if value(config.NamespaceType) == "BUILD_ID" {
		_, id, _ := strings.Cut(r.Key.ID, ":")
		prefix = path.Join(prefix, id)
	}
	name := value(config.Name)
	if config.OverrideArtifactName != nil && *config.OverrideArtifactName && artifactName != "" {
		name = artifactName
	}
	if name == "" {
		name = value(r.Data.ProjectName)
	}
	return path.Join(prefix, name)
}

func (c *controller) publishArtifacts(ctx context.Context, r BuildRecord, e runtime.Execution, config api.ProjectArtifacts, selector, artifactName string) error {
	files, err := e.Files(ctx, selector)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("no files matched the build artifact selection")
	}
	bucket := value(config.Location)
	key := artifactKey(&r, config, artifactName)
	kms := value(r.Data.EncryptionKey)
	if config.EncryptionDisabled != nil && *config.EncryptionDisabled {
		kms = ""
	}
	artifact := api.BuildArtifacts{Location: new(api.String("arn:" + r.Key.Partition + ":s3:::" + bucket + "/" + key)), EncryptionDisabled: config.EncryptionDisabled, OverrideArtifactName: config.OverrideArtifactName, ArtifactIdentifier: config.ArtifactIdentifier}
	if value(config.Packaging) == "ZIP" {
		archive, err := archiveFiles(files)
		if err != nil {
			return err
		}
		if err = c.s.objects.Write(ctx, bucket, key, archive, kms); err != nil {
			return err
		}
		md5sum := md5.Sum(archive)
		sha := sha256.Sum256(archive)
		artifact.Md5sum = new(api.String(hex.EncodeToString(md5sum[:])))
		artifact.Sha256sum = new(api.String(hex.EncodeToString(sha[:])))
	} else {
		for _, file := range files {
			if err = c.s.objects.Write(ctx, bucket, path.Join(key, file.Path), file.Body, kms); err != nil {
				return err
			}
		}
	}
	return c.s.repository.Update(ctx, func(tx Transaction) error {
		latest, err := tx.Build(r.Key)
		if err != nil {
			return err
		}
		if selector == "artifacts" {
			latest.Data.Artifacts = &artifact
		} else {
			replaced := false
			for i, previous := range latest.Data.SecondaryArtifacts {
				if value(previous.ArtifactIdentifier) == value(artifact.ArtifactIdentifier) {
					latest.Data.SecondaryArtifacts[i] = artifact
					replaced = true
					break
				}
			}
			if !replaced {
				latest.Data.SecondaryArtifacts = append(latest.Data.SecondaryArtifacts, artifact)
			}
		}
		return tx.PutBuild(latest)
	})
}

// CodePipeline owns exact locations and always consumes ZIPs, even when the
// observed StartBuild artifactsOverride.packaging is NONE. Multiple outputs
// select their matching buildspec secondary-artifacts, not the primary files.
func (c *controller) publishPipelineArtifacts(ctx context.Context, r BuildRecord, e runtime.Execution) error {
	if r.PipelineActionID == "" {
		// Native manual StartBuild accepts the S3 ARN and runs commands, but
		// the captured unbound output failed at UPLOAD_ARTIFACTS. Do not invent
		// internal signing credentials or report a synthetic pipeline artifact.
		// TODO: Comeback calibrate the native manual CODEPIPELINE output-signing
		// mechanism; its observed SignatureDoesNotMatch is not synthesized here.
		return errors.New("CodePipeline artifact publication requires an admitted pipeline action")
	}
	artifacts := make(api.BuildArtifactsList, 0, len(r.PipelineOutputs))
	for _, output := range r.PipelineOutputs {
		selector := "artifacts"
		if len(r.PipelineOutputs) > 1 {
			selector += ":" + output.Name
		}
		files, err := e.Files(ctx, selector)
		if err != nil {
			return err
		}
		if len(files) == 0 {
			return errors.New("no files matched the build artifact selection")
		}
		archive, err := archiveFiles(files)
		if err != nil {
			return err
		}
		bucket, key, err := pipelineObjectLocation(r.Key.Partition, output.Location)
		if err != nil {
			return err
		}
		if err = c.s.objects.Write(ctx, bucket, key, archive, output.EncryptionKey); err != nil {
			return err
		}
		md5sum := md5.Sum(archive)
		sha := sha256.Sum256(archive)
		artifact := api.BuildArtifacts{
			Location:           new(api.String(output.Location)),
			EncryptionDisabled: new(api.WrapperBoolean(false)),
			Md5sum:             new(api.String(hex.EncodeToString(md5sum[:]))),
			Sha256sum:          new(api.String(hex.EncodeToString(sha[:]))),
		}
		if len(r.PipelineOutputs) > 1 {
			artifact.ArtifactIdentifier = new(api.String(output.Name))
		}
		artifacts = append(artifacts, artifact)
	}
	if len(artifacts) == 0 {
		return nil
	}
	return c.s.repository.Update(ctx, func(tx Transaction) error {
		latest, err := tx.Build(r.Key)
		if err != nil {
			return err
		}
		if len(artifacts) == 1 {
			latest.Data.Artifacts = &artifacts[0]
		} else {
			latest.Data.SecondaryArtifacts = artifacts
		}
		return tx.PutBuild(latest)
	})
}
