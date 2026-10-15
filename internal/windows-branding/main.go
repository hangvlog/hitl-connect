// Generate the existing HITL arrow mark at Windows icon sizes, using only Go's
// standard library. Geometry and colors match gui-assets/brand.svg.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

func segment(x, y, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := math.Max(0, math.Min(1, ((x-ax)*dx+(y-ay)*dy)/(dx*dx+dy*dy)))
	return math.Hypot(x-ax-t*dx, y-ay-t*dy)
}

func mark(size int) *image.NRGBA {
	im := image.NewNRGBA(image.Rect(0, 0, size, size))
	const samples = 4
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a int
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/samples) * 256 / float64(size)
					py := (float64(y) + (float64(sy)+0.5)/samples) * 256 / float64(size)
					qx, qy := math.Max(math.Abs(px-128)-56, 0), math.Max(math.Abs(py-128)-56, 0)
					if math.Hypot(qx, qy) > 64 {
						continue
					}
					a += 255
					if math.Min(segment(px, py, 78, 178, 178, 78), math.Min(segment(px, py, 86, 78, 178, 78), segment(px, py, 178, 78, 178, 170))) <= 12 {
						r += 255
						g += 255
						b += 255
					} else {
						r += 27
						g += 99
						b += 77
					}
				}
			}
			if a != 0 {
				im.SetNRGBA(x, y, color.NRGBA{uint8(r * 255 / a), uint8(g * 255 / a), uint8(b * 255 / a), uint8(a / (samples * samples))})
			}
		}
	}
	return im
}

func run() error {
	out := flag.String("out", "", "output .ico file")
	flag.Parse()
	if *out == "" {
		return fmt.Errorf("--out is required")
	}
	sizes := []int{16, 24, 32, 48, 64, 128, 256}
	var payload bytes.Buffer
	header := make([]byte, 6+16*len(sizes))
	binary.LittleEndian.PutUint16(header[2:], 1)
	binary.LittleEndian.PutUint16(header[4:], uint16(len(sizes)))
	for i, size := range sizes {
		var encoded bytes.Buffer
		if err := png.Encode(&encoded, mark(size)); err != nil {
			return err
		}
		entry := header[6+16*i:]
		entry[0], entry[1] = byte(size), byte(size) // 0 means 256 pixels in ICO.
		binary.LittleEndian.PutUint16(entry[4:], 1)
		binary.LittleEndian.PutUint16(entry[6:], 32)
		binary.LittleEndian.PutUint32(entry[8:], uint32(encoded.Len()))
		binary.LittleEndian.PutUint32(entry[12:], uint32(len(header)+payload.Len()))
		payload.Write(encoded.Bytes())
	}
	return os.WriteFile(*out, append(header, payload.Bytes()...), 0644)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
