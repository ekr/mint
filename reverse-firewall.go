package mint

import (
	"encoding/hex"
	"fmt"
)

func parsePacket(ht byte, b []byte) (payload []byte, err error) {
	// Read record header
	if b[0] != 22 {
		// Sanity check
		return nil, fmt.Errorf("Not a handshake packet")
	}
	l := (int(b[3]) << 8) | int(b[4])
	if len(b) != l+5 {
		return nil, fmt.Errorf("Length mismatch l=%v len=%v", l, len(b))
	}
	b = b[5:]

	// Read handshake header
	if b[0] != ht {
		// Sanity check
		return nil, fmt.Errorf("Unexpected handshake type %v != %v", b[0], ht)
	}
	l = (int(b[1]) << 16) | (int(b[2]) << 8) | int(b[3])
	if len(b) != l+4 {
		return nil, fmt.Errorf("Length mismatch 2")
	}
	b = b[4:]

	return b, nil
}

type ReverseFirewallProxy struct {
	readCH bool
	readSH bool
}

func NewReverseFirewallProxy() *ReverseFirewallProxy {
	return &ReverseFirewallProxy{}
}

type Direction uint8

const (
	C2S = Direction(1)
	S2C = Direction(2)
)

func (p *ReverseFirewallProxy) processCH(in []byte) ([]byte, error) {
	p.readCH = true
	return in, nil
}

func (p *ReverseFirewallProxy) processSH(in []byte) ([]byte, error) {
	p.readSH = true
	return in, nil
}

func (p *ReverseFirewallProxy) ProcessMessage(d Direction, in []byte) (out []byte, err error) {
	dir := "C->S"
	if d == S2C {
		dir = "S->C"
	}
	logf(logTypeFirewall, "%v: %v bytes", dir, hex.EncodeToString(in))
	switch {
	case d == C2S && !p.readCH:
		out, err = p.processCH(in)
	case d == S2C && !p.readSH:
		out, err = p.processSH(in)
	default:
		out = in
	}
	return
}
