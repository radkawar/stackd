package ec2

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real firmware changes the real VGA framebuffer. No stored picture, mock QMP
// server or in-process guest can satisfy this regression. Full OS/SDK console
// changes are exercised separately by the configured guest smoke.
func TestQEMUScreenshotFramebuffer(t *testing.T) {
	binary, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		t.Skipf("native screenshot regression requires QEMU: %v", err)
	}
	for _, graphics := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-framebuffer", true: "firmware-framebuffer"}[graphics], func(t *testing.T) {
			driver := &QEMU{config: Config{StateDirectory: t.TempDir(), SystemBinary: binary}}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			directory := driver.directory("arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			args := []string{"-machine", "q35", "-m", "128", "-nodefaults", "-display", "none", "-S", "-name", nativeName(directory),
				"-qmp", "unix:" + escapeOption(filepath.Join(directory, "qmp.sock")) + ",server=on,wait=off"}
			if graphics {
				args = append(args, "-device", "VGA,id=console-video")
			}
			startNativeTestQEMU(t, ctx, driver, directory, args)
			instance := &nativeInstance{driver: driver, directory: directory}
			before, err := instance.Screenshot(ctx, false)
			if !graphics {
				var capability *CapabilityError
				if !errors.As(err, &capability) || before != nil {
					t.Fatalf("missing native graphics must reject, not return an invented image: bytes=%d error=%v", len(before), err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := instance.Start(ctx); err != nil {
				t.Fatal(err)
			}
			for {
				after, err := instance.Screenshot(ctx, false)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					if _, err := jpeg.Decode(bytes.NewReader(after)); err != nil || len(after) > maxScreenshotBytes {
						t.Fatalf("native changed framebuffer must be a bounded JPEG: bytes=%d error=%v", len(after), err)
					}
					break
				}
				if err := waitTick(ctx); err != nil {
					t.Fatal("firmware never changed the captured framebuffer:", err)
				}
			}
			if err := instance.Pause(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := instance.Screenshot(ctx, true); err != nil {
				t.Fatal(err)
			}
			status, err := instance.Inspect(ctx)
			if err != nil || status.State != Paused {
				t.Fatalf("WakeUp must inject keyboard input without resuming a VMM: status=%+v error=%v", status, err)
			}
			files, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				if strings.HasPrefix(file.Name(), ".screenshot-") {
					t.Fatal("sensitive temporary capture survived the request:", file.Name())
				}
			}
		})
	}
}

func TestScreenshotJPEGLimitPreservesPixels(t *testing.T) {
	// A deterministic high-detail frame exceeds the response cap. The two
	// colored halves must remain distinguishable after actual image reduction.
	frame := image.NewRGBA(image.Rect(0, 0, 1920, 1080))
	random := rand.New(rand.NewPCG(4, 9))
	for y := range frame.Bounds().Dy() {
		for x := range frame.Bounds().Dx() {
			noise := uint8(random.Uint32N(128))
			pixel := color.RGBA{R: 128 + noise, G: noise, B: noise, A: 255}
			if x >= frame.Bounds().Dx()/2 {
				pixel.R, pixel.B = noise, 128+noise
			}
			frame.SetRGBA(x, y, pixel)
		}
	}
	encoded, err := screenshotJPEG(t.Context(), frame)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := jpeg.Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > maxScreenshotBytes || decoded.Bounds().Dx() >= frame.Bounds().Dx() {
		t.Fatalf("oversized frame was not reduced to the native response boundary: bytes=%d bounds=%v", len(encoded), decoded.Bounds())
	}
	left := color.RGBAModel.Convert(decoded.At(decoded.Bounds().Dx()/4, decoded.Bounds().Dy()/2)).(color.RGBA)
	right := color.RGBAModel.Convert(decoded.At(decoded.Bounds().Dx()*3/4, decoded.Bounds().Dy()/2)).(color.RGBA)
	if int(left.R)-int(left.B) < 80 || int(right.B)-int(right.R) < 80 {
		t.Fatalf("resized screenshot lost actual frame content: left=%+v right=%+v", left, right)
	}
}
