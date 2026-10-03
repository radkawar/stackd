package dynamodb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type dockerDatabase struct {
	runtime              *Docker
	id, endpoint, region string
	transport            *http.Transport
	client               *http.Client
	signer               *v4.Signer
	lifetime             context.Context
	cancel               context.CancelFunc
	closeOnce            sync.Once
}

var _ Database = (*dockerDatabase)(nil)

func newDatabase(runtime *Docker, spec Specification, id, endpoint string) *dockerDatabase {
	transport := &http.Transport{
		// Do not route a private engine endpoint through environment proxies.
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &dockerDatabase{
		runtime: runtime, id: id, endpoint: endpoint, region: spec.Region,
		transport: transport, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		signer: v4.NewSigner(), lifetime: lifetime, cancel: cancel,
	}
}

func (db *dockerDatabase) Close() error {
	db.closeOnce.Do(func() {
		db.cancel()
		db.transport.CloseIdleConnections()
	})
	return nil
}

func (db *dockerDatabase) Request(ctx context.Context, target string, body []byte) (Response, error) {
	response, err := db.exchange(ctx, target, body)
	if err != nil {
		if ctx.Err() != nil || db.lifetime.Err() != nil {
			return response, err
		}
		return response, db.runtime.failure(ctx, db.id, fmt.Errorf("request %s at %s: %w", target, db.endpoint, err))
	}
	return response, nil
}

func (db *dockerDatabase) exchange(ctx context.Context, target string, body []byte) (Response, error) {
	if db.lifetime.Err() != nil {
		return Response{}, errors.New("DynamoDB database handle is closed")
	}
	prefix, operation, ok := strings.Cut(target, ".")
	if !ok || operation == "" || (prefix != "DynamoDB_20120810" && prefix != "DynamoDBStreams_20120810") {
		return Response{}, fmt.Errorf("complete DynamoDB or DynamoDB Streams AWS target required, got %q", target)
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(db.lifetime, cancel)
	defer func() { stop(); cancel() }()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, db.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	request.Header.Set("Content-Type", "application/x-amz-json-1.0")
	request.Header.Set("X-Amz-Target", target)
	digest := sha256.Sum256(body)
	// -sharedDb gives this retained regional instance one database. Identity
	// labels, not customer credentials or these synthetic signing keys, select it.
	credentials := aws.Credentials{AccessKeyID: "StackdDynamoDBLocal", SecretAccessKey: "StackdDynamoDBLocalSyntheticSecret"}
	if err := db.signer.SignHTTP(ctx, credentials, request, hex.EncodeToString(digest[:]), "dynamodb", db.region, time.Now().UTC()); err != nil {
		return Response{}, fmt.Errorf("sign DynamoDB Local request: %w", err)
	}
	response, err := db.client.Do(request)
	if err != nil {
		return Response{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return Response{}, fmt.Errorf("read DynamoDB Local HTTP %d response: %w", response.StatusCode, err)
	}
	if response.StatusCode == http.StatusOK && target == "DynamoDB_20120810.ExecuteStatement" {
		data, err = localStatementPage(data)
		if err != nil {
			return Response{}, err
		}
	}
	if response.StatusCode == http.StatusOK && prefix == "DynamoDB_20120810" {
		data, err = localReadCapacity(operation, body, data)
		if err != nil {
			return Response{}, err
		}
	}
	if response.StatusCode == http.StatusBadRequest && prefix == "DynamoDB_20120810" && (operation == "ExecuteStatement" || operation == "ExecuteTransaction") {
		data, err = localPartiQLError(operation, data)
		if err != nil {
			return Response{}, err
		}
	}
	return Response{StatusCode: response.StatusCode, Body: data}, nil
}

// Local 3.3.1 retains the evaluated physical key in its continuation, but omits
// the corresponding AWS response member. Recover it at the backend boundary;
// projected Items cannot supply keys for key-excluding or filtered-empty pages.
func localStatementPage(body []byte) ([]byte, error) {
	var page struct {
		NextToken        string
		LastEvaluatedKey json.RawMessage
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, err
	}
	if page.NextToken == "" || len(page.LastEvaluatedKey) != 0 {
		return body, nil
	}
	data, err := base64.StdEncoding.DecodeString(page.NextToken)
	if err != nil {
		return nil, fmt.Errorf("decode DynamoDB Local continuation: %w", err)
	}
	var cursor struct {
		Keys map[string]json.RawMessage `json:"opIndexToExclusiveNextKey"`
	}
	if err := json.Unmarshal(data, &cursor); err != nil {
		return nil, fmt.Errorf("decode DynamoDB Local continuation: %w", err)
	}
	if len(cursor.Keys) != 1 {
		return body, nil
	}
	for _, key := range cursor.Keys {
		if bytes.Equal(key, []byte("null")) || bytes.Equal(key, []byte("{}")) {
			return body, nil
		}
		body = bytes.TrimSpace(body)
		body = append(body[:len(body)-1], `,"LastEvaluatedKey":`...)
		body = append(body, key...)
		return append(body, '}'), nil
	}
	return body, nil
}

func (db *dockerDatabase) ready(ctx context.Context) error {
	var last error
	for {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		response, err := db.exchange(attempt, "DynamoDB_20120810.ListTables", []byte(`{"Limit":1}`))
		cancel()
		if err == nil && response.StatusCode == http.StatusOK {
			var result struct{ TableNames *[]string }
			if err = json.Unmarshal(response.Body, &result); err == nil && result.TableNames != nil {
				return nil
			}
			err = fmt.Errorf("invalid ListTables success document: %s", response.Body)
		} else if err == nil {
			err = fmt.Errorf("ListTables HTTP %d: %s", response.StatusCode, response.Body)
		}
		last = err
		state, inspectErr := db.runtime.inspect(ctx, db.id)
		if inspectErr != nil {
			return fmt.Errorf("DynamoDB API readiness failed (%v): inspect process: %w", last, inspectErr)
		}
		if !state.State.Running || state.State.Paused || state.State.Restarting || state.State.Dead {
			return fmt.Errorf("DynamoDB API readiness failed (%v): process state %+v", last, state.State)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("DynamoDB API readiness: %w; last ListTables result: %v", ctx.Err(), last)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
