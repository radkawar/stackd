package eks

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const auditBatchLimit = 8 << 20

// auditSpool is the acknowledged native webhook source. Each frame contains the
// original EventList request bytes, not rewritten events or a second audit feed.
// Acknowledgement follows fsync; the delivery byte cursor advances only after Logs.
type auditSpool struct {
	mu        sync.Mutex
	path      string
	closed    bool
	committed int64
}

func prepareAuditSpool(dir string) (*auditSpool, error) {
	path := filepath.Join(dir, "audit.events")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return nil, errors.New("eks: audit source must be a private regular file, not a symlink")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("eks: audit source must be a private regular file")
	}
	parent, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(file)
	var offset int64
	for {
		var header [4]byte
		_, err = io.ReadFull(reader, header[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return repairAuditTail(file, path, offset)
		}
		if err != nil {
			return nil, err
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > auditBatchLimit {
			return nil, errors.New("eks: invalid retained audit source frame")
		}
		if _, err = io.CopyN(io.Discard, reader, int64(size)); errors.Is(err, io.EOF) {
			return repairAuditTail(file, path, offset)
		}
		if err != nil {
			return nil, err
		}
		offset += 4 + int64(size)
	}
	return &auditSpool{path: path, committed: offset}, nil
}

// A crashed append cannot have been acknowledged before fsync. Discard only its
// incomplete final frame; complete acknowledged frames and their bytes survive.
func repairAuditTail(file *os.File, path string, offset int64) (*auditSpool, error) {
	if err := file.Truncate(offset); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	return &auditSpool{path: path, committed: offset}, nil
}

func (s *auditSpool) append(body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("eks: audit source is closed")
	}
	if len(body) == 0 || len(body) > auditBatchLimit {
		return errors.New("eks: invalid audit source frame size")
	}
	file, err := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if _, err = file.Write(header[:]); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	if err != nil {
		// Do not leave a partial frame in front of a subsequent successful append.
		if truncateErr := file.Truncate(offset); truncateErr != nil {
			s.closed = true
			return errors.Join(err, truncateErr)
		}
		return err
	}
	s.committed = offset + 4 + int64(len(body))
	return nil
}
func (s *auditSpool) close() { s.mu.Lock(); s.closed = true; s.mu.Unlock() }

func (l *nativeLogs) collectAudit(ctx context.Context) error {
	file, err := os.Open(l.audit.path)
	if err != nil {
		return err
	}
	defer file.Close()
	l.audit.mu.Lock()
	committed := l.audit.committed
	l.audit.mu.Unlock()
	if l.cursor.AuditOffset < 0 || l.cursor.AuditOffset > committed {
		return errors.New("eks: audit cursor exceeds acknowledged source")
	}
	reader := bufio.NewReader(io.NewSectionReader(file, l.cursor.AuditOffset, committed-l.cursor.AuditOffset))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var header [4]byte
		if _, err = io.ReadFull(reader, header[:]); errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > auditBatchLimit {
			return errors.New("eks: invalid audit source frame")
		}
		body := make([]byte, int(size))
		if _, err = io.ReadFull(reader, body); err != nil {
			return err
		}
		var batch struct {
			Items []json.RawMessage `json:"items"`
		}
		if err = json.Unmarshal(body, &batch); err != nil {
			return err
		}
		records := make([]LogRecord, 0, len(batch.Items))
		for _, raw := range batch.Items {
			var event struct {
				StageTimestamp           time.Time `json:"stageTimestamp"`
				RequestReceivedTimestamp time.Time `json:"requestReceivedTimestamp"`
			}
			if err = json.Unmarshal(raw, &event); err != nil {
				return err
			}
			at := event.StageTimestamp
			if at.IsZero() {
				at = event.RequestReceivedTimestamp
			}
			if at.IsZero() {
				return errors.New("eks: native audit event timestamp is absent")
			}
			if l.enabled("audit", at) {
				records = append(records, LogRecord{Category: "audit", Stream: logStream("audit", l.state.Token), Timestamp: at, Message: string(raw)})
			}
		}
		if len(records) != 0 {
			if err = l.sink.PutControlPlaneLogs(ctx, l.state.ID, records); err != nil {
				return err
			}
		}
		l.cursor.AuditOffset += 4 + int64(size)
		if err = l.save(l.cursor); err != nil {
			return err
		}
	}
}
