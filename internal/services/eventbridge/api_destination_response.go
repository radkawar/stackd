package eventbridge

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"

	"stackd/internal/awswire"
)

// readAPIDestinationResponse owns the response body. Only successful enrichment
// responses are decoded; ordinary targets and HTTP failures retain their existing
// bounded drain and status-based retry behavior. Callers discard output on error.
func readAPIDestinationResponse(response *http.Response, output io.Writer) *awswire.Error {
	defer response.Body.Close()
	// HEAD and bodyless responses such as 204 have no representation to decode,
	// even when metadata advertises an encoding. Preserve empty-result filtering.
	if response.Body == http.NoBody {
		return nil
	}
	capture := output != nil && response.StatusCode >= 200 && response.StatusCode < 300
	if !capture {
		if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20)); err != nil {
			return apiDestinationTransportError(err)
		}
		return nil
	}

	// Accept-Encoding is explicit, so net/http does not decompress automatically.
	// Native captures accept more than 6 MiB decoded when target transformation
	// removes padding. Do not apply the wire limit to the expanded JSON.
	// TODO: Comeback calibrate the native wire ceiling and larger expansion limits.
	const wireLimit = 6 << 20
	// This is a local resource-safety ceiling, not an asserted AWS payload quota.
	const decodedLimit = 64 << 20
	wire := &io.LimitedReader{R: response.Body, N: wireLimit + 1}
	var body io.Reader = wire
	var decoded io.ReadCloser
	var err error
	switch strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		decoded, err = gzip.NewReader(body)
	case "deflate":
		decoded, err = apiDestinationDeflate(body)
	default:
		// TODO: Comeback calibrate additional and stacked HTTP content codings.
		return failure("ServiceUnavailable", "The API destination response content encoding is not supported.", http.StatusServiceUnavailable)
	}
	if err != nil {
		return apiDestinationTransportError(err)
	}
	if decoded != nil {
		defer decoded.Close()
		body = decoded
	}
	n, err := io.Copy(output, io.LimitReader(body, decodedLimit+1))
	if wire.N == 0 {
		return failure("PayloadTooLargeException", "The enrichment HTTP response exceeds 6 MiB on the wire.", http.StatusRequestEntityTooLarge)
	}
	if n > decodedLimit {
		return failure("NotImplementedException", "Decoded enrichment responses above the local 64 MiB safety ceiling are not supported.", http.StatusNotImplemented)
	}
	if err != nil {
		return apiDestinationTransportError(err)
	}
	return nil
}

// AWS accepts both the RFC zlib wrapper and legacy raw DEFLATE. Peek rather than
// retry after a failed decode: the reader is not rewindable, and corrupt zlib
// streams must fail their checksum instead of being reinterpreted as raw data.
func apiDestinationDeflate(body io.Reader) (io.ReadCloser, error) {
	buffered := bufio.NewReader(body)
	header, err := buffered.Peek(2)
	if err != nil {
		return nil, err
	}
	if header[0]&0x0f == 8 && header[0]>>4 <= 7 && (uint16(header[0])<<8|uint16(header[1]))%31 == 0 {
		return zlib.NewReader(buffered)
	}
	return flate.NewReader(buffered), nil
}
