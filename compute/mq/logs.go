package mq

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	service "stackd/internal/services/mq"
)

const (
	mqLogBatchBytes  = 1 << 20
	mqLogBatchEvents = 10000
	// JSON can expand one source byte to six bytes (e.g. a control character).
	mqLogReadBytes  = 6*mqLogBatchBytes + 4096
	mqLogGuardBytes = 64
)

var _ service.LogSource = (*Runtime)(nil)

type nativeLogFile struct {
	name, identity string
	size           int64
}

type nativeLogLayout struct {
	directory, file, archives string
	firstArchive              int
}

func logLayout(engine string, kind service.LogType) (nativeLogLayout, error) {
	switch engine {
	case "ACTIVEMQ":
		layout := nativeLogLayout{directory: "/opt/apache-activemq/data", archives: ".7 .6 .5 .4 .3 .2 .1", firstArchive: 1}
		switch kind {
		case service.GeneralLog:
			layout.file = "activemq.log"
		case service.AuditLog:
			layout.file = "audit.log"
		default:
			return nativeLogLayout{}, errors.New("unknown native MQ log type")
		}
		return layout, nil
	case "RABBITMQ":
		if kind != service.GeneralLog {
			return nativeLogLayout{}, errors.New("RabbitMQ supports only general logs")
		}
		return nativeLogLayout{directory: "/var/lib/rabbitmq", file: "rabbit.log", archives: ".6 .5 .4 .3 .2 .1 .0"}, nil
	default:
		return nativeLogLayout{}, errors.New("unsupported native MQ log engine")
	}
}

// The inode and birth time survive rename and broker/container restart. A
// bounded boundary digest also detects copy-truncate followed by regrowth.
// This is an opaque cursor, never a filename supplied to native execution.
type nativeLogIdentity struct {
	Native string `json:"native"`
	Guard  string `json:"guard"`
}

// ReadLogs collects only retained files of the inspected, exact-owned native
// container. It never starts or reconfigures the broker.
func (r *Runtime) ReadLogs(ctx context.Context, v service.BrokerRecord, kind service.LogType, cursor service.LogCursor) (service.LogBatch, error) {
	batch := service.LogBatch{Next: cursor}
	layout, err := logLayout(v.Engine, kind)
	if err != nil {
		return batch, err
	}
	var identity nativeLogIdentity
	if cursor.Offset < 0 || (cursor.FileID == "" && cursor.Offset != 0) {
		return batch, errors.New("invalid native MQ log cursor")
	}
	if cursor.FileID != "" {
		if err := json.Unmarshal([]byte(cursor.FileID), &identity); err != nil || identity.Native == "" || len(identity.Guard) != sha256.Size*2 {
			return batch, errors.New("invalid native MQ log identity")
		}
	}
	if err := r.lock(ctx); err != nil {
		return batch, err
	}
	defer r.unlock()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	native, err := r.inspect(ctx, v)
	if err != nil {
		return batch, err
	}
	if err = r.checkNativeStorage(ctx, v, native); err != nil {
		return batch, err
	}
	if !native.State.Running {
		return batch, errors.New("native MQ log collection requires the owned container to be running")
	}
	files, err := r.listNativeLogs(ctx, native.ID, layout)
	if err != nil {
		return batch, err
	}
	if len(files) == 0 {
		batch.LostPrefix = cursor.FileID != ""
		return batch, nil
	}
	selected, offset := 0, cursor.Offset
	if identity.Native != "" {
		selected = -1
		for index, candidate := range files {
			if candidate.identity == identity.Native {
				selected = index
				break
			}
		}
		if selected == -1 {
			selected, offset = 0, 0
			batch.LostPrefix = true
		}
	}
	current := files[selected]
	if current.size < offset {
		offset = 0
		batch.LostPrefix = true
	}
	data, err := r.readNativeLog(ctx, native.ID, layout.directory, current, offset)
	if err != nil {
		return batch, err
	}
	guardSize := int(min(offset, int64(mqLogGuardBytes)))
	if !batch.LostPrefix && identity.Native != "" && logGuard(data[:guardSize]) != identity.Guard {
		batch.LostPrefix = true
		offset = 0
		data, err = r.readNativeLog(ctx, native.ID, layout.directory, current, offset)
		if err != nil {
			return batch, err
		}
		guardSize = 0
	}
	// Finish the cursor's file before moving forward. Both native rollover
	// strategies number archives newest-first; never infer order from mtime.
	if offset == current.size && selected+1 < len(files) && !batch.LostPrefix {
		current = files[selected+1]
		offset, guardSize = 0, 0
		data, err = r.readNativeLog(ctx, native.ID, layout.directory, current, offset)
		if err != nil {
			return batch, err
		}
	}
	records, consumed, err := parseNativeLogs(data[guardSize:], current.size-offset, v.Engine)
	if err != nil {
		return batch, err
	}
	batch.Records = records
	boundary := guardSize + consumed
	encoded, err := json.Marshal(nativeLogIdentity{Native: current.identity, Guard: logGuard(data[max(0, boundary-mqLogGuardBytes):boundary])})
	if err != nil {
		return batch, err
	}
	batch.Next = service.LogCursor{FileID: string(encoded), Offset: offset + int64(consumed)}
	return batch, nil
}

func logGuard(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// Only enumerated fixed filenames enter native commands. Symlinks and special
// files are rejected before reading; the directory itself must not be a link.
const nativeLogListScript = `set -eu
[ ! -L "$1" ] && [ -d "$1" ] || exit 1
cd "$1"
if [ ! -e stackd-logs ] && [ ! -L stackd-logs ]; then exit 0; fi
[ ! -L stackd-logs ] && [ -d stackd-logs ] || exit 1
cd stackd-logs
for suffix in $3 ''; do
  file="$2$suffix"
  if [ ! -e "$file" ] && [ ! -L "$file" ]; then continue; fi
  [ ! -L "$file" ] && [ -f "$file" ] || exit 1
  printf '%s|' "$file"
  stat -c '%d:%i:%W|%s' -- "$file"
done
`

func (r *Runtime) listNativeLogs(ctx context.Context, id string, layout nativeLogLayout) ([]nativeLogFile, error) {
	data, err := r.execNative(ctx, id, []string{"sh", "-c", nativeLogListScript, "stackd-log-list", layout.directory, layout.file, layout.archives}, 4096)
	if err != nil {
		return nil, err
	}
	var files []nativeLogFile
	for line := range strings.SplitSeq(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 3 || len(files) == 8 {
			return nil, errors.New("invalid native MQ log listing")
		}
		valid := fields[0] == layout.file
		for index := layout.firstArchive; index < layout.firstArchive+7; index++ {
			valid = valid || fields[0] == layout.file+"."+strconv.Itoa(index)
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if !valid || err != nil || size < 0 || fields[1] == "" {
			return nil, errors.New("invalid native MQ log file metadata")
		}
		files = append(files, nativeLogFile{name: fields[0], identity: fields[1], size: size})
	}
	return files, nil
}

const nativeLogReadScript = `set -eu
[ ! -L "$6" ] && [ -d "$6" ] || exit 1
cd "$6"
[ ! -L stackd-logs ] && [ -d stackd-logs ] || exit 1
cd stackd-logs
[ ! -L "$1" ] && [ -f "$1" ] || exit 1
exec 3<"$1"
[ "$(stat -Lc '%d:%i:%W' /proc/$$/fd/3)" = "$2" ]
[ "$(stat -Lc '%s' /proc/$$/fd/3)" -ge "$5" ]
dd bs=65536 iflag=skip_bytes,count_bytes skip="$3" count="$4" status=none <&3
`

func (r *Runtime) readNativeLog(ctx context.Context, id, directory string, file nativeLogFile, offset int64) ([]byte, error) {
	start := max(int64(0), offset-mqLogGuardBytes)
	count := min(int64(mqLogReadBytes), file.size-start)
	data, err := r.execNative(ctx, id, []string{"sh", "-c", nativeLogReadScript, "stackd-log-read", file.name, file.identity, strconv.FormatInt(start, 10), strconv.FormatInt(count, 10), strconv.FormatInt(file.size, 10), directory}, mqLogReadBytes)
	if err == nil && int64(len(data)) != count {
		err = errors.New("native MQ log changed during collection")
	}
	return data, err
}

func parseNativeLogs(data []byte, available int64, engine string) ([]service.LogRecord, int, error) {
	var records []service.LogRecord
	consumed, requestBytes := 0, 0
	var earliest, latest time.Time
	for consumed < len(data) && len(records) < mqLogBatchEvents {
		end := bytes.IndexByte(data[consumed:], '\n')
		if end < 0 {
			if consumed == 0 && int64(len(data)) < available {
				return nil, 0, errors.New("native MQ log record exceeds the bounded record size")
			}
			break // Never acknowledge an incomplete native write.
		}
		line := data[consumed : consumed+end]
		var event struct {
			Timestamp string `json:"timestamp"`
			Message   string `json:"message"`
			Time      string `json:"time"`
			Msg       string `json:"msg"`
		}
		if !utf8.Valid(line) || json.Unmarshal(line, &event) != nil {
			return nil, 0, fmt.Errorf("invalid native MQ log record at relative byte %d", consumed)
		}
		layout := "2006-01-02T15:04:05.000Z"
		if engine == "RABBITMQ" {
			event.Timestamp, event.Message = event.Time, event.Msg
			layout = time.RFC3339Nano
		}
		if event.Message == "" {
			return nil, 0, fmt.Errorf("empty native MQ log message at relative byte %d", consumed)
		}
		stamp, err := time.Parse(layout, event.Timestamp)
		if err != nil || stamp.UnixMilli() < 0 {
			return nil, 0, fmt.Errorf("invalid native MQ log timestamp at relative byte %d", consumed)
		}
		size := len(event.Message) + 26
		if size > mqLogBatchBytes {
			return nil, 0, fmt.Errorf("native MQ log event at relative byte %d exceeds one PutLogEvents request", consumed)
		}
		if requestBytes+size > mqLogBatchBytes {
			break
		}
		if len(records) == 0 {
			earliest, latest = stamp, stamp
		} else {
			if stamp.Before(earliest) {
				earliest = stamp
			}
			if stamp.After(latest) {
				latest = stamp
			}
			if latest.Sub(earliest) > 24*time.Hour {
				break
			}
		}
		records = append(records, service.LogRecord{Timestamp: stamp, Message: event.Message})
		requestBytes += size
		consumed += end + 1
	}
	return records, consumed, nil
}
