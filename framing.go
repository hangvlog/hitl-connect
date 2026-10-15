package main

import (
	"encoding/binary"
	"errors"
	"io"
)

// Per-stream scratch storage is bounded and never shared across peers. Reuse
// it only after the synchronous write completes; no queue can grow behind a
// slow receiver. The encrypted wire format and 32 KiB limit stay unchanged.
type frameWriter struct{ buffer [maxChunk + 5]byte }

func (f *frameWriter) write(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > maxChunk {
		return errors.New("frame too large")
	}
	f.buffer[0] = kind
	binary.BigEndian.PutUint32(f.buffer[1:5], uint32(len(payload)))
	copy(f.buffer[5:], payload)
	return writeFrameBytes(w, f.buffer[:5+len(payload)])
}
func writeFrameBytes(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err == nil && n != len(p) {
		return io.ErrShortWrite
	}
	return err
}

// Returned bytes remain valid until the next read on this stream. Validate
// the header before reading into the fixed buffer, including empty FIN frames.
type frameReader struct {
	header [5]byte
	buffer [maxChunk]byte
}

func (f *frameReader) read(r io.Reader) (byte, []byte, error) {
	if _, err := io.ReadFull(r, f.header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(f.header[1:])
	kind := f.header[0]
	if size > maxChunk || kind < 1 || kind > 3 || (kind == 2 && size != 0) {
		return 0, nil, errors.New("invalid encrypted frame")
	}
	p := f.buffer[:size]
	_, err := io.ReadFull(r, p)
	return kind, p, err
}
