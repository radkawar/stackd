package integrations

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/services/logs"
)

// CodeBuildLogs publishes native output through ordinary current-role commands.
// The service retains the native byte cursor only after this method succeeds.
type CodeBuildLogs struct{ Logs RuntimeLogsAPI }

func (a CodeBuildLogs) Write(ctx context.Context, group, stream string, body []byte, at time.Time) error {
	text := strings.ToValidUTF8(string(body), "\uFFFD")
	if text == "" {
		return nil
	}
	input := &api.PutLogEventsRequest{LogGroupName: new(api.LogGroupName(group)), LogStreamName: new(api.LogStreamName(stream))}
	batchBytes := 0
	flush := func() error {
		if len(input.LogEvents) == 0 {
			return nil
		}
		out, rejected := a.Logs.PutLogEvents(codeBuildCommandContext(ctx), input)
		if rejected != nil && rejected.Code == "ResourceNotFoundException" {
			_, streamErr := a.Logs.CreateLogStream(codeBuildCommandContext(ctx), &api.CreateLogStreamRequest{LogGroupName: input.LogGroupName, LogStreamName: input.LogStreamName})
			if streamErr != nil && streamErr.Code == "ResourceNotFoundException" {
				_, groupErr := a.Logs.CreateLogGroup(codeBuildCommandContext(ctx), &api.CreateLogGroupRequest{LogGroupName: input.LogGroupName})
				if groupErr != nil && groupErr.Code != "ResourceAlreadyExistsException" {
					return groupErr
				}
				_, streamErr = a.Logs.CreateLogStream(codeBuildCommandContext(ctx), &api.CreateLogStreamRequest{LogGroupName: input.LogGroupName, LogStreamName: input.LogStreamName})
			}
			if streamErr != nil && streamErr.Code != "ResourceAlreadyExistsException" {
				return streamErr
			}
			out, rejected = a.Logs.PutLogEvents(codeBuildCommandContext(ctx), input)
		}
		if rejected != nil {
			return rejected
		}
		if out.RejectedLogEventsInfo != nil {
			return fmt.Errorf("CloudWatch Logs rejected CodeBuild output timestamps")
		}
		input.LogEvents = input.LogEvents[:0]
		batchBytes = 0
		return nil
	}
	for len(text) > 0 {
		n := len(text)
		if line := strings.IndexByte(text, '\n'); line >= 0 {
			n = line + 1
		}
		if n > logs.MaxBatchBytes-logs.EventOverheadBytes {
			n = logs.MaxBatchBytes - logs.EventOverheadBytes
		}
		for n < len(text) && !utf8.RuneStart(text[n]) {
			n--
		}
		if batchBytes+n+logs.EventOverheadBytes > logs.MaxBatchBytes || len(input.LogEvents) == logs.MaxBatchEvents {
			if err := flush(); err != nil {
				return err
			}
		}
		input.LogEvents = append(input.LogEvents, api.InputLogEvent{Message: new(api.EventMessage(text[:n])), Timestamp: new(api.Timestamp(at.UnixMilli()))})
		batchBytes += n + logs.EventOverheadBytes
		text = text[n:]
	}
	return flush()
}
