package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestReusableFramingWireCompatibility(t *testing.T) {
	for _, n := range []int{0, 1, 1024, maxChunk} {
		payload := bytes.Repeat([]byte{byte(n + 1)}, n)
		var old, updated bytes.Buffer
		if err := writeFrame(&old, 1, payload); err != nil {
			t.Fatal(err)
		}
		writer := frameWriter{}
		if err := writer.write(&updated, 1, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(old.Bytes(), updated.Bytes()) {
			t.Fatal("wire format changed")
		}
		reader := frameReader{}
		kind, data, err := reader.read(&old)
		if err != nil || kind != 1 || !bytes.Equal(data, payload) {
			t.Fatal("legacy frame not decoded", err)
		}
		kind, data, err = readFrame(&updated)
		if err != nil || kind != 1 || !bytes.Equal(data, payload) {
			t.Fatal("new frame not legacy compatible", err)
		}
	}
	var stream bytes.Buffer
	writer, reader := frameWriter{}, frameReader{}
	for _, payload := range []string{"first", "", "second"} {
		if err := writer.write(&stream, 1, []byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	writer.write(&stream, 2, nil)
	for _, payload := range []string{"first", "", "second"} {
		kind, data, err := reader.read(&stream)
		if err != nil || kind != 1 || string(data) != payload {
			t.Fatal("reused buffer mixed frames", err)
		}
	}
	kind, data, err := reader.read(&stream)
	if err != nil || kind != 2 || len(data) != 0 {
		t.Fatal("FIN was not preserved")
	}
}

func TestReusableFramingRejectsInvalidOrTruncatedFrames(t *testing.T) {
	for _, raw := range [][]byte{{1}, {1, 0, 0, 0, 1}, {0, 0, 0, 0, 0}, {4, 0, 0, 0, 0}, {2, 0, 0, 0, 1}, {1, 0, 1, 0, 0}} {
		reader := frameReader{}
		if _, _, err := reader.read(bytes.NewReader(raw)); err == nil {
			t.Fatalf("accepted %v", raw)
		}
	}
	writer := frameWriter{}
	if err := writer.write(io.Discard, 1, make([]byte, maxChunk+1)); err == nil {
		t.Fatal("oversized output accepted")
	}
	if err := writer.write(shortFrameWriter{}, 1, []byte("payload")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write ignored: %v", err)
	}
}

type shortFrameWriter struct{}

func (shortFrameWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestReusableFramingStreamsAreIndependent(t *testing.T) {
	for i := 0; i < 8; i++ {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			t.Parallel()
			w, r := frameWriter{}, frameReader{}
			for n := 0; n < 100; n++ {
				var wire bytes.Buffer
				payload := bytes.Repeat([]byte{byte(i)}, maxChunk)
				if err := w.write(&wire, 1, payload); err != nil {
					t.Fatal(err)
				}
				_, got, err := r.read(&wire)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatal("cross-stream contamination", err)
				}
			}
		})
	}
}

// Isolate the framing cost under parallel streams; this does not measure the
// Internet link. Both versions process the same payload and wire representation.
func BenchmarkParallelFraming(b *testing.B) {
	payload := bytes.Repeat([]byte{7}, maxChunk)
	wire := make([]byte, maxChunk+5)
	wire[0] = 1
	binary.BigEndian.PutUint32(wire[1:5], maxChunk)
	copy(wire[5:], payload)
	for _, reuse := range []bool{false, true} {
		name := "legacy"
		if reuse {
			name = "reused"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(maxChunk)
			b.RunParallel(func(pb *testing.PB) {
				writer, reader := frameWriter{}, frameReader{}
				src := bytes.NewReader(wire)
				for pb.Next() {
					src.Reset(wire)
					if reuse {
						if err := writer.write(io.Discard, 1, payload); err != nil {
							b.Fatal(err)
						}
						if _, _, err := reader.read(src); err != nil {
							b.Fatal(err)
						}
					} else {
						if err := writeFrame(io.Discard, 1, payload); err != nil {
							b.Fatal(err)
						}
						if _, _, err := readFrame(src); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		})
	}
}
