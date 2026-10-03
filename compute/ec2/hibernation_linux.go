package ec2

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Hibernate asks the standard guest agent to suspend to disk. The guest kernel
// owns the memory image and its resume configuration on the encrypted EBS root.
func (i *nativeInstance) Hibernate(ctx context.Context) error {
	return i.guestHibernation(ctx, true)
}

// guestHibernation shares the standard agent synchronization between a
// read-only readiness observation and the subsequently admitted S4 request.
func (i *nativeInstance) guestHibernation(ctx context.Context, suspend bool) error {
	if !i.spec.Hibernation {
		return &CapabilityError{Feature: "guest hibernation channel"}
	}
	unlock, err := i.driver.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	monitor, err := i.driver.existing(ctx, i.directory)
	if err != nil {
		return err
	}
	defer monitor.close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(i.directory, "qga.sock"))
	if err != nil {
		return fmt.Errorf("guest hibernation agent: %w", err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		return err
	}
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		peer, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		peerErr = err
		if err == nil && (peer.Uid != uint32(os.Geteuid()) || int(peer.Pid) != monitor.pid) {
			peerErr = errors.New("guest agent socket does not belong to the owned VMM")
		}
	}); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}

	// QGA survives controller replacement. Its documented sentinel handshake
	// discards a previous connection's incomplete request/response, not errors
	// from this request. The nonce is protocol synchronization, never persisted.
	var nonceBytes [8]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return err
	}
	nonce := binary.LittleEndian.Uint64(nonceBytes[:]) >> 1
	if _, err := conn.Write([]byte{0xff}); err != nil {
		return err
	}
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(map[string]any{"execute": "guest-sync-delimited", "arguments": map[string]uint64{"id": nonce}}); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	for consumed := 0; ; consumed++ {
		if consumed == 64<<10 {
			return errors.New("guest agent synchronization exceeded response limit")
		}
		b, err := reader.ReadByte()
		if err != nil {
			return fmt.Errorf("guest hibernation agent synchronization: %w", err)
		}
		if b == 0xff {
			break
		}
	}
	decoder := json.NewDecoder(reader)
	var response qmpMessage
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("guest hibernation agent synchronization response: %w", err)
	}
	var echoed uint64
	if response.Error != nil || json.Unmarshal(response.Return, &echoed) != nil || echoed != nonce {
		return errors.New("guest agent synchronization response mismatch")
	}
	if !suspend {
		if err := encoder.Encode(map[string]string{"execute": "guest-info"}); err != nil {
			return err
		}
		response = qmpMessage{}
		if err := decoder.Decode(&response); err != nil {
			return err
		}
		if response.Error != nil {
			return &qmpError{command: "guest-info", class: response.Error.Class, description: response.Error.Description}
		}
		var info struct {
			Commands []struct {
				Name    string `json:"name"`
				Enabled bool   `json:"enabled"`
			} `json:"supported_commands"`
		}
		if err := json.Unmarshal(response.Return, &info); err != nil {
			return err
		}
		for _, command := range info.Commands {
			if command.Name == "guest-suspend-disk" && command.Enabled {
				return nil
			}
		}
		return &CapabilityError{Feature: "guest suspend-to-disk"}
	}
	if err := encoder.Encode(map[string]string{"execute": "guest-suspend-disk"}); err != nil {
		return err
	}
	// QGA deliberately sends no successful response for suspend-to-disk. An
	// immediate error is useful; otherwise the lifecycle observer must wait for
	// actual native shutdown. A sent command is never memory-preservation proof.
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return err
	}
	response = qmpMessage{}
	if err := decoder.Decode(&response); err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() && ctx.Err() == nil {
			return nil
		}
		return err
	}
	if response.Error != nil {
		return &qmpError{command: "guest-suspend-disk", class: response.Error.Class, description: response.Error.Description}
	}
	return errors.New("guest suspend-to-disk returned an unexpected response")
}
