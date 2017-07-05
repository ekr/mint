package mint

import (
	"testing"
)

var kTestFrame = []byte{0x00, 0x05, 'a', 'b', 'c', 'd', 'e'}
var kTestEmptyFrame = []byte{0x00, 0x00}

type simpleHeader struct{}

func (h simpleHeader) headerLen() int {
	return 2
}

func (h simpleHeader) defaultReadLen() int {
	return 1024
}

func (h simpleHeader) frameLen(hdr []byte) (int, error) {
	if len(hdr) != 2 {
		panic("Assert!")
	}

	return (int(hdr[0]) << 8) | int(hdr[1]), nil
}

func checkFrame(t *testing.T, hdr []byte, body []byte) {
	assertByteEquals(t, hdr, kTestFrame[:2])
	assertByteEquals(t, body, kTestFrame[2:])
}

func TestFrameReaderFullFrame(t *testing.T) {
	r := NewFrameReader(simpleHeader{})
	r.AddChunk(kTestFrame)
	hdr, body, err := r.Process()
	assertNotError(t, err, "Couldn't read frame 1")
	checkFrame(t, hdr, body)

	r.AddChunk(kTestFrame)
	hdr, body, err = r.Process()
	assertNotError(t, err, "Couldn't read frame 2")
	checkFrame(t, hdr, body)
}

func TestFrameReaderTwoFrames(t *testing.T) {
	r := NewFrameReader(simpleHeader{})
	r.AddChunk(kTestFrame)
	r.AddChunk(kTestFrame)
	hdr, body, err := r.Process()
	assertNotError(t, err, "Couldn't read frame 1")
	checkFrame(t, hdr, body)

	hdr, body, err = r.Process()
	assertNotError(t, err, "Couldn't read frame 2")
	checkFrame(t, hdr, body)
}

func TestFrameReaderTrickle(t *testing.T) {
	r := NewFrameReader(simpleHeader{})

	var hdr, body []byte
	var err error
	for i := 0; i <= len(kTestFrame); i += 1 {
		hdr, body, err = r.Process()
		if i < len(kTestFrame) {
			assertEquals(t, err, WouldBlock)
			assertEquals(t, 0, len(hdr))
			assertEquals(t, 0, len(body))
			r.AddChunk(kTestFrame[i : i+1])
		}
	}
	assertNil(t, err, "Error reading")
	checkFrame(t, hdr, body)
}
