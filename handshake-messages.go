package mint

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/bifurcation/mint/syntax"
)

const (
	fixedClientHelloBodyLen      = 39
	fixedServerHelloBodyLen      = 36
	fixedNewSessionTicketBodyLen = 10
	maxCipherSuites              = 1 << 15
	extensionHeaderLen           = 4
	maxExtensionDataLen          = (1 << 16) - 1
	maxExtensionsLen             = (1 << 16) - 1
	maxCertRequestContextLen     = 255
	maxTicketLen                 = (1 << 16) - 1
)

type HandshakeMessageBody interface {
	Type() HandshakeType
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (int, error)
}

// struct {
//     ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
//     Random random;
//     opaque legacy_session_id<0..32>;
//     CipherSuite cipher_suites<2..2^16-2>;
//     opaque legacy_compression_methods<1..2^8-1>;
//     Extension extensions<0..2^16-1>;
// } ClientHello;
type ClientHelloBody struct {
	// Omitted: clientVersion
	// Omitted: legacySessionID
	// Omitted: legacyCompressionMethods
	Random       [32]byte
	CipherSuites []CipherSuite
	Extensions   ExtensionList
}

type clientHelloBodyInner struct {
	LegacyVersion            uint16
	Random                   [32]byte
	LegacySessionID          []byte        `tls:"head=1,max=32"`
	CipherSuites             []CipherSuite `tls:"head=2,min=2"`
	LegacyCompressionMethods []byte        `tls:"head=1,min=1"`
	Extensions               []Extension   `tls:"head=2"`
}

func (ch ClientHelloBody) Type() HandshakeType {
	return HandshakeTypeClientHello
}

func (ch ClientHelloBody) Marshal() ([]byte, error) {
	return syntax.Marshal(clientHelloBodyInner{
		LegacyVersion:            0x0303,
		Random:                   ch.Random,
		LegacySessionID:          []byte{},
		CipherSuites:             ch.CipherSuites,
		LegacyCompressionMethods: []byte{0},
		Extensions:               ch.Extensions,
	})
}

func (ch *ClientHelloBody) Unmarshal(data []byte) (int, error) {
	var inner clientHelloBodyInner
	read, err := syntax.Unmarshal(data, &inner)
	if err != nil {
		return 0, err
	}

	// We are strict about these things because we only support 1.3
	if inner.LegacyVersion != 0x0303 {
		return 0, fmt.Errorf("tls.clienthello: Incorrect version number")
	}

	if len(inner.LegacyCompressionMethods) != 1 || inner.LegacyCompressionMethods[0] != 0 {
		return 0, fmt.Errorf("tls.clienthello: Invalid compression method")
	}

	ch.Random = inner.Random
	ch.CipherSuites = inner.CipherSuites
	ch.Extensions = inner.Extensions
	return read, nil
}

// TODO: File a spec bug to clarify this
func (ch ClientHelloBody) Truncated() ([]byte, error) {
	if len(ch.Extensions) == 0 {
		return nil, fmt.Errorf("tls.clienthello.truncate: No extensions")
	}

	pskExt := ch.Extensions[len(ch.Extensions)-1]
	if pskExt.ExtensionType != ExtensionTypePreSharedKey {
		return nil, fmt.Errorf("tls.clienthello.truncate: Last extension is not PSK")
	}

	chm, err := HandshakeMessageFromBody(&ch)
	if err != nil {
		return nil, err
	}
	chData := chm.Marshal()

	psk := PreSharedKeyExtension{
		HandshakeType: HandshakeTypeClientHello,
	}
	_, err = psk.Unmarshal(pskExt.ExtensionData)
	if err != nil {
		return nil, err
	}

	// Marshal just the binders so that we know how much to truncate
	binders := struct {
		Binders []PSKBinderEntry `tls:"head=2,min=33"`
	}{Binders: psk.Binders}
	binderData, _ := syntax.Marshal(binders)
	binderLen := len(binderData)

	chLen := len(chData)
	return chData[:chLen-binderLen], nil
}

// struct {
//     ProtocolVersion version;
//     Random random;
//     CipherSuite cipher_suite;
//     Extension extensions<0..2^16-1>;
// } ServerHello;
type ServerHelloBody struct {
	Version     uint16
	Random      [32]byte
	CipherSuite CipherSuite
	Extensions  ExtensionList `tls:"head=2"`
}

func (sh ServerHelloBody) Type() HandshakeType {
	return HandshakeTypeServerHello
}

func (sh ServerHelloBody) Marshal() ([]byte, error) {
	return syntax.Marshal(sh)
}

func (sh *ServerHelloBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, sh)
}

// struct {
//     opaque verify_data[verify_data_length];
// } Finished;
//
// verifyDataLen is not a field in the TLS struct, but we add it here so
// that calling code can tell us how much data to expect when we marshal /
// unmarshal.  (We could add this to the marshal/unmarshal methods, but let's
// try to keep the signature consistent for now.)
//
// For similar reasons, we don't use the `syntax` module here, because this
// struct doesn't map well to standard TLS presentation language concepts.
//
// TODO: File a spec bug
type FinishedBody struct {
	VerifyDataLen int
	VerifyData    []byte
}

func (fin FinishedBody) Type() HandshakeType {
	return HandshakeTypeFinished
}

func (fin FinishedBody) Marshal() ([]byte, error) {
	if len(fin.VerifyData) != fin.VerifyDataLen {
		return nil, fmt.Errorf("tls.finished: data length mismatch")
	}

	body := make([]byte, len(fin.VerifyData))
	copy(body, fin.VerifyData)
	return body, nil
}

func (fin *FinishedBody) Unmarshal(data []byte) (int, error) {
	if len(data) < fin.VerifyDataLen {
		return 0, fmt.Errorf("tls.finished: Malformed finished; too short")
	}

	fin.VerifyData = make([]byte, fin.VerifyDataLen)
	copy(fin.VerifyData, data[:fin.VerifyDataLen])
	return fin.VerifyDataLen, nil
}

// struct {
//     Extension extensions<0..2^16-1>;
// } EncryptedExtensions;
//
// Marshal() and Unmarshal() are handled by ExtensionList
type EncryptedExtensionsBody struct {
	Extensions ExtensionList `tls:"head=2"`
}

func (ee EncryptedExtensionsBody) Type() HandshakeType {
	return HandshakeTypeEncryptedExtensions
}

func (ee EncryptedExtensionsBody) Marshal() ([]byte, error) {
	return syntax.Marshal(ee)
}

func (ee *EncryptedExtensionsBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, ee)
}

// opaque ASN1Cert<1..2^24-1>;
//
// struct {
//     ASN1Cert cert_data;
//     Extension extensions<0..2^16-1>
// } CertificateEntry;
//
// struct {
//     opaque certificate_request_context<0..2^8-1>;
//     CertificateEntry certificate_list<0..2^24-1>;
// } Certificate;
type CertificateEntry struct {
	CertData   *x509.Certificate
	Extensions ExtensionList
}

type CertificateBody struct {
	CertificateRequestContext []byte
	CertificateList           []CertificateEntry
}

func (c CertificateBody) Type() HandshakeType {
	return HandshakeTypeCertificate
}

func (c CertificateBody) Marshal() ([]byte, error) {
	if len(c.CertificateRequestContext) > maxCertRequestContextLen {
		return nil, fmt.Errorf("tls.certificate: Request context too long")
	}

	certsData := []byte{}
	for _, entry := range c.CertificateList {
		if entry.CertData == nil || len(entry.CertData.Raw) == 0 {
			return nil, fmt.Errorf("tls:certificate: Unmarshaled certificate")
		}

		extData, err := entry.Extensions.Marshal()
		if err != nil {
			return nil, err
		}

		certLen := len(entry.CertData.Raw)
		entryData := []byte{byte(certLen >> 16), byte(certLen >> 8), byte(certLen)}
		entryData = append(entryData, entry.CertData.Raw...)
		entryData = append(entryData, extData...)
		certsData = append(certsData, entryData...)
	}
	certsDataLen := len(certsData)
	certsDataLenBytes := []byte{byte(certsDataLen >> 16), byte(certsDataLen >> 8), byte(certsDataLen)}

	data := []byte{byte(len(c.CertificateRequestContext))}
	data = append(data, c.CertificateRequestContext...)
	data = append(data, certsDataLenBytes...)
	data = append(data, certsData...)
	return data, nil
}

func (c *CertificateBody) Unmarshal(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("tls:certificate: Message too short for context length")
	}

	contextLen := int(data[0])
	if len(data) < 1+contextLen+3 {
		return 0, fmt.Errorf("tls:certificate: Message too short for context")
	}
	c.CertificateRequestContext = make([]byte, contextLen)
	copy(c.CertificateRequestContext, data[1:1+contextLen])

	certsLen := (int(data[1+contextLen]) << 16) + (int(data[1+contextLen+1]) << 8) + int(data[1+contextLen+2])
	if len(data) < 1+contextLen+3+certsLen {
		return 0, fmt.Errorf("tls:certificate: Message too short for certificates")
	}

	start := 1 + contextLen + 3
	end := 1 + contextLen + 3 + certsLen
	c.CertificateList = []CertificateEntry{}
	for start < end {
		if len(data[start:]) < 3 {
			return 0, fmt.Errorf("tls:certificate: Message too short for certificate length")
		}

		certLen := (int(data[start]) << 16) + (int(data[start+1]) << 8) + int(data[start+2])
		if len(data[start+3:]) < certLen {
			return 0, fmt.Errorf("tls:certificate: Message too short for certificate")
		}

		cert, err := x509.ParseCertificate(data[start+3 : start+3+certLen])
		if err != nil {
			return 0, fmt.Errorf("tls:certificate: Certificate failed to parse: %v", err)
		}

		var ext ExtensionList
		read, err := ext.Unmarshal(data[start+3+certLen:])
		if err != nil {
			return 0, err
		}

		c.CertificateList = append(c.CertificateList, CertificateEntry{
			CertData:   cert,
			Extensions: ext,
		})
		start += 3 + certLen + read
	}
	return start, nil
}

// struct {
//     SignatureScheme algorithm;
//     opaque signature<0..2^16-1>;
// } CertificateVerify;
type CertificateVerifyBody struct {
	Algorithm SignatureScheme
	Signature []byte `tls:"head=2"`
}

func (cv CertificateVerifyBody) Type() HandshakeType {
	return HandshakeTypeCertificateVerify
}

func (cv CertificateVerifyBody) Marshal() ([]byte, error) {
	return syntax.Marshal(cv)
}

func (cv *CertificateVerifyBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, cv)
}

func (cv *CertificateVerifyBody) ComputeContext(ctx cryptoContext, transcript []*HandshakeMessage) (hashed []byte, err error) {
	h := ctx.params.hash.New()
	handshakeContext := []byte{}
	for _, msg := range transcript {
		if msg == nil {
			err = fmt.Errorf("tls.certverify: Nil message")
			return
		}
		data := msg.Marshal()
		logf(logTypeHandshake, "Added Message to Handshake Context to be verified: [%d] %x", len(data), data)
		handshakeContext = append(handshakeContext, data...)
		h.Write(data)
	}

	hashed = h.Sum(nil)
	logf(logTypeHandshake, "Handshake Context to be verified: [%d] %x", len(handshakeContext), handshakeContext)
	logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hashed), hashed)
	return
}

func (cv *CertificateVerifyBody) EncodeSignatureInput(data []byte) []byte {
	const context = "TLS 1.3, server CertificateVerify"
	sigInput := bytes.Repeat([]byte{0x20}, 64)
	sigInput = append(sigInput, []byte(context)...)
	sigInput = append(sigInput, []byte{0}...)
	sigInput = append(sigInput, data...)
	return sigInput
}

func (cv *CertificateVerifyBody) Sign(privateKey crypto.Signer, transcript []*HandshakeMessage, ctx cryptoContext) error {
	hashedWithContext, err := cv.ComputeContext(ctx, transcript)
	if err != nil {
		return err
	}

	sigInput := cv.EncodeSignatureInput(hashedWithContext)
	cv.Signature, err = sign(cv.Algorithm, privateKey, sigInput)
	logf(logTypeHandshake, "Signed: alg=[%04x] sigInput=[%x], sig=[%x]", cv.Algorithm, sigInput, cv.Signature)
	return err
}

func (cv *CertificateVerifyBody) Verify(publicKey crypto.PublicKey, transcript []*HandshakeMessage, ctx cryptoContext) error {
	hashedWithContext, err := cv.ComputeContext(ctx, transcript)
	if err != nil {
		return err
	}

	sigInput := cv.EncodeSignatureInput(hashedWithContext)
	logf(logTypeHandshake, "About to verify: alg=[%04x] sigInput=[%x], sig=[%x]", cv.Algorithm, sigInput, cv.Signature)
	return verify(cv.Algorithm, publicKey, sigInput, cv.Signature)
}

// struct {
//     uint32 ticket_lifetime;
//     uint32 ticket_age_add;
//     opaque ticket<1..2^16-1>;
//     Extension extensions<0..2^16-2>;
// } NewSessionTicket;
type NewSessionTicketBody struct {
	TicketLifetime uint32
	TicketAgeAdd   uint32
	Ticket         []byte        `tls:"head=2,min=1"`
	Extensions     ExtensionList `tls:"head=2"`
}

func NewSessionTicket(ticketLen int) (*NewSessionTicketBody, error) {
	tkt := &NewSessionTicketBody{
		Ticket: make([]byte, ticketLen),
	}
	_, err := prng.Read(tkt.Ticket)
	return tkt, err
}

func (tkt NewSessionTicketBody) Type() HandshakeType {
	return HandshakeTypeNewSessionTicket
}

func (tkt NewSessionTicketBody) Marshal() ([]byte, error) {
	return syntax.Marshal(tkt)
}

func (tkt *NewSessionTicketBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, tkt)
}

// enum {
//     update_not_requested(0), update_requested(1), (255)
// } KeyUpdateRequest;
//
// struct {
//     KeyUpdateRequest request_update;
// } KeyUpdate;
type KeyUpdateBody struct {
	KeyUpdateRequest KeyUpdateRequest
}

func (ku KeyUpdateBody) Type() HandshakeType {
	return HandshakeTypeKeyUpdate
}

func (ku KeyUpdateBody) Marshal() ([]byte, error) {
	return syntax.Marshal(ku)
}

func (ku *KeyUpdateBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, ku)
}
