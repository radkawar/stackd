package ec2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"os"
	"time"

	"golang.org/x/image/draw"
)

const maxScreenshotBytes = 100000

// Screenshot captures the actual first graphical console, including a crashed
// guest's last framebuffer. Neither QMP capture nor WakeUp resumes a paused VM
// or starts a replacement process. The private temporary PNG is never retained.
func (i *nativeInstance) Screenshot(ctx context.Context, wakeUp bool) ([]byte, error) {
	unlock, err := i.driver.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	client, err := i.driver.existing(ctx, i.directory)
	if err != nil {
		return nil, err
	}
	defer client.close()
	if wakeUp {
		// A modifier wakes console blanking without typing a command, changing
		// a lock key, or sending Enter to a guest's active application. q35 has
		// a native i8042/PS2 keyboard even with -nodefaults.
		if err := client.execute(ctx, "send-key", map[string]any{
			"keys": []map[string]string{{"type": "qcode", "data": "shift"}}, "hold-time": 100,
		}, nil); err != nil {
			return nil, err
		}
		// QEMU releases send-key asynchronously. Give the real guest a key
		// press/release window before asking it to refresh its framebuffer.
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	file, err := os.CreateTemp(i.directory, ".screenshot-*.png")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := client.execute(ctx, "screendump", map[string]any{"filename": file.Name(), "format": "png"}, nil); err != nil {
		var rejected *qmpError
		if errors.As(err, &rejected) && (rejected.class == "CommandNotFound" || rejected.description == "There is no console to take a screendump from") {
			return nil, &CapabilityError{Feature: "graphical console capture: " + rejected.description}
		}
		return nil, fmt.Errorf("capture guest framebuffer: %w", err)
	}
	frame, err := png.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("decode QEMU framebuffer: %w", err)
	}
	return screenshotJPEG(ctx, frame)
}

func screenshotJPEG(ctx context.Context, frame image.Image) ([]byte, error) {
	var encoded bytes.Buffer
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		encoded.Reset()
		if err := jpeg.Encode(&encoded, frame, &jpeg.Options{Quality: 75}); err != nil {
			return nil, err
		}
		if encoded.Len() <= maxScreenshotBytes {
			return encoded.Bytes(), nil
		}
		// The documented EC2 response is at most 100 kB. Ordinary text
		// consoles retain native resolution. Only oversized real frames are
		// reduced; a borrowed resampler, not a generated substitute, owns it.
		bounds := frame.Bounds()
		reduced := image.NewRGBA(image.Rect(0, 0, max(1, bounds.Dx()/2), max(1, bounds.Dy()/2)))
		draw.ApproxBiLinear.Scale(reduced, reduced.Bounds(), frame, bounds, draw.Src, nil)
		frame = reduced
	}
}
