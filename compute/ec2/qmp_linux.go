package ec2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type qmpClient struct {
	conn     *net.UnixConn
	decoder  *json.Decoder
	encoder  *json.Encoder
	pid      int
	sequence uint64
}

type qmpMessage struct {
	Return json.RawMessage `json:"return"`
	Error  *struct {
		Class       string `json:"class"`
		Description string `json:"desc"`
	} `json:"error"`
	Event string          `json:"event"`
	ID    uint64          `json:"id"`
	QMP   json.RawMessage `json:"QMP"`
}

type qmpError struct {
	command, class, description string
}

func (e *qmpError) Error() string {
	return fmt.Sprintf("QMP %s: %s: %s", e.command, e.class, e.description)
}

func connectQMP(ctx context.Context, path string) (*qmpClient, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	u := conn.(*net.UnixConn)
	c := &qmpClient{conn: u, decoder: json.NewDecoder(u), encoder: json.NewEncoder(u)}
	raw, err := u.SyscallConn()
	if err != nil {
		u.Close()
		return nil, err
	}
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		credential, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		credentialErr = e
		if e == nil {
			if credential.Uid != uint32(os.Geteuid()) {
				credentialErr = errors.New("QMP socket belongs to another user")
			} else {
				c.pid = int(credential.Pid)
			}
		}
	})
	if err != nil || credentialErr != nil {
		u.Close()
		return nil, errors.Join(err, credentialErr)
	}
	cancel := c.deadline(ctx)
	var greeting qmpMessage
	err = c.decoder.Decode(&greeting)
	cancel()
	if err != nil || len(greeting.QMP) == 0 {
		u.Close()
		return nil, fmt.Errorf("QMP greeting: %w", errors.Join(err, errors.New("missing valid QMP greeting")))
	}
	if err := c.execute(ctx, "qmp_capabilities", nil, nil); err != nil {
		u.Close()
		return nil, err
	}
	return c, nil
}

func (c *qmpClient) close() error { return c.conn.Close() }

func (c *qmpClient) deadline(ctx context.Context) func() {
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.conn.SetDeadline(deadline)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = c.conn.SetDeadline(time.Now()); close(done) })
	return func() {
		if !stop() {
			<-done
		}
		_ = c.conn.SetDeadline(time.Time{})
	}
}

func (c *qmpClient) execute(ctx context.Context, command string, args any, result any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cancel := c.deadline(ctx)
	defer cancel()
	c.sequence++
	request := struct {
		Execute   string `json:"execute"`
		Arguments any    `json:"arguments,omitempty"`
		ID        uint64 `json:"id"`
	}{command, args, c.sequence}
	if err := c.encoder.Encode(request); err != nil {
		return fmt.Errorf("QMP %s: %w", command, err)
	}
	for {
		var response qmpMessage
		if err := c.decoder.Decode(&response); err != nil {
			return fmt.Errorf("QMP %s: %w", command, err)
		}
		if response.Event != "" {
			continue
		}
		if response.ID != c.sequence {
			return errors.New("QMP response ID mismatch")
		}
		if response.Error != nil {
			return &qmpError{command: command, class: response.Error.Class, description: response.Error.Description}
		}
		if result != nil {
			return json.Unmarshal(response.Return, result)
		}
		return nil
	}
}

func processOwns(pid int, name, socket string) (bool, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	args := strings.Split(string(data), "\x00")
	var named, connected bool
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-name" && args[i+1] == name {
			named = true
		}
		if args[i] == "-qmp" && args[i+1] == "unix:"+escapeOption(socket)+",server=on,wait=off" {
			connected = true
		}
	}
	return named && connected, nil
}

func waitTick(ctx context.Context) error {
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func escapeOption(value string) string { return strings.ReplaceAll(value, ",", ",,") }

func jsonOption(value any) string {
	// Only concrete maps of strings, integers and booleans are passed here.
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func processStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, errors.New("invalid native process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	// Fields starts with field 3 (state); Linux starttime is field 22.
	if len(fields) <= 19 {
		return 0, errors.New("native process starttime is unavailable")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
