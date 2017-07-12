// Read a generic "framed" packet consisting of a header and a
// This is used for both TLS Records and TLS Handshake Messages
package mint

import ()

type framing interface {
	headerLen() int
	defaultReadLen() int
	frameLen(hdr []byte) (int, error)
}

const (
	kFrameReaderHdr  = 0
	kFrameReaderBody = 1
)

type frameNextAction func(f *FrameReader) error

type FrameReader struct {
	details     framing
	state       uint8
	header      []byte
	body        []byte
	working     []byte
	writeOffset int
	remainder   []byte
}

func NewFrameReader(d framing) *FrameReader {
	hdr := make([]byte, d.headerLen())
	return &FrameReader{
		d,
		kFrameReaderHdr,
		hdr,
		nil,
		hdr,
		0,
		nil,
	}
}

func dup(a []byte) []byte {
	r := make([]byte, len(a))
	copy(r, a)
	return r
}

func (f *FrameReader) needed() int {
	tmp := (len(f.working) - f.writeOffset) - len(f.remainder)
	if tmp < 0 {
		return 0
	}
	return tmp
}

func (f *FrameReader) AddChunk(in []byte) {
	// Append to the buffer.
	logf(logTypeFrameReader, "Appending %v", len(in))
	f.remainder = append(f.remainder, in...)
}

func (f *FrameReader) Process() (hdr []byte, body []byte, err error) {
	for f.needed() == 0 {
		logf(logTypeFrameReader, "%v bytes needed for next block", len(f.working)-f.writeOffset)
		// Fill out our working block
		copied := copy(f.working[f.writeOffset:], f.remainder)
		f.remainder = f.remainder[copied:]
		f.writeOffset += copied
		if f.writeOffset < len(f.working) {
			logf(logTypeFrameReader, "Read would have blocked 1")
			return nil, nil, WouldBlock
		}
		// Reset the write offset, because we are now full.
		f.writeOffset = 0

		// We have read a full frame
		if f.state == kFrameReaderBody {
			logf(logTypeFrameReader, "Returning frame hdr=%v len=%d buffered=%d", f.header, len(f.body), len(f.remainder))
			f.state = kFrameReaderHdr
			f.working = f.header
			return dup(f.header), dup(f.body), nil
		}

		// We have read the header
		bodyLen, err := f.details.frameLen(f.header)
		if err != nil {
			return nil, nil, err
		}
		logf(logTypeFrameReader, "Processed header, body len = %v", bodyLen)

		f.body = make([]byte, bodyLen)
		f.working = f.body
		f.writeOffset = 0
		f.state = kFrameReaderBody
	}

	logf(logTypeFrameReader, "Read would have blocked 2")
	return nil, nil, WouldBlock
}
