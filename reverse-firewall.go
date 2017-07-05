package mint

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

func parsePacket(ht HandshakeType, b []byte) (payload []byte, err error) {
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
	if b[0] != byte(ht) {
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

func writePacket(ht HandshakeType, in []byte) []byte {
	var b bytes.Buffer

	// Record header.
	b.WriteByte(22) // Record type
	b.WriteByte(03) // Version
	b.WriteByte(01)
	// Len
	rl := len(in) + 4
	b.WriteByte(byte(rl >> 8))
	b.WriteByte(byte(rl & 0xff))

	// Handshake header
	b.WriteByte(byte(ht)) // Handshake type
	hl := len(in)
	b.WriteByte(byte(hl >> 16))
	b.WriteByte(byte(hl >> 8))
	b.WriteByte(byte(hl & 0xff))

	b.Write(in)
	return b.Bytes()
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
	chb, err := parsePacket(HandshakeTypeClientHello, in)
	if err != nil {
		return nil, err
	}
	var ch ClientHelloBody
	_, err = ch.Unmarshal(chb)
	if err != nil {
		return nil, err
	}
	out, err := ch.Marshal()
	if err != nil {
		return nil, err
	}
	p.readCH = true

	pkt := writePacket(HandshakeTypeClientHello, out)
	return pkt, nil
}

func (p *ReverseFirewallProxy) processSH(in []byte) ([]byte, error) {
	shb, err := parsePacket(HandshakeTypeClientHello, in)
	if err != nil {
		return nil, err
	}
	var sh ServerHelloBody
	_, err = sh.Unmarshal(shb)
	if err != nil {
		return nil, err
	}
	out, err := sh.Marshal()
	if err != nil {
		return nil, err
	}
	p.readSH = true

	pkt := writePacket(HandshakeTypeServerHello, out)
	return pkt, nil
}

func (p *ReverseFirewallProxy) ProcessMessage(d Direction, in []byte) (out []byte, err error) {
	dir := "C->S"
	if d == S2C {
		dir = "S->C"
	}
	logf(logTypeFirewall, "%v: in %v bytes", dir, hex.EncodeToString(in))
	switch {
	case d == C2S && !p.readCH:
		out, err = p.processCH(in)
		logf(logTypeFirewall, "%v: out %v bytes", dir, hex.EncodeToString(out))

	case d == S2C && !p.readSH:
		out, err = p.processSH(in)
		logf(logTypeFirewall, "%v: out %v bytes", dir, hex.EncodeToString(out))
	default:
		out = in
	}
	return
}
