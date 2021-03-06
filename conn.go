package mint

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"time"
)

type Certificate struct {
	Chain      []*x509.Certificate
	PrivateKey crypto.Signer
}

type PreSharedKey struct {
	CipherSuite  CipherSuite
	IsResumption bool
	Identity     []byte
	Key          []byte
	NextProto    string
	ReceivedAt   time.Time
	ExpiresAt    time.Time
	TicketAgeAdd uint32
}

type PreSharedKeyCache interface {
	Get(string) (PreSharedKey, bool)
	Put(string, PreSharedKey)
	Size() int
}

type PSKMapCache map[string]PreSharedKey

func (cache PSKMapCache) Get(key string) (psk PreSharedKey, ok bool) {
	psk, ok = cache[key]
	return
}

func (cache *PSKMapCache) Put(key string, psk PreSharedKey) {
	(*cache)[key] = psk
}

func (cache PSKMapCache) Size() int {
	return len(cache)
}

// Config is the struct used to pass configuration settings to a TLS client or
// server instance.  The settings for client and server are pretty different,
// but we just throw them all in here.
type Config struct {
	// Client fields
	ServerName string

	// Server fields
	SendSessionTickets bool
	TicketLifetime     uint32
	TicketLen          int
	EarlyDataLifetime  uint32
	AllowEarlyData     bool
	RequireCookie      bool
	RequireClientAuth  bool

	// Shared fields
	Certificates     []*Certificate
	AuthCertificate  func(chain []CertificateEntry) error
	CipherSuites     []CipherSuite
	Groups           []NamedGroup
	SignatureSchemes []SignatureScheme
	NextProtos       []string
	PSKs             PreSharedKeyCache
	PSKModes         []PSKKeyExchangeMode

	// The same config object can be shared among different connections, so it
	// needs its own mutex
	mutex sync.RWMutex
}

func (c *Config) Init(isClient bool) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Set defaults
	if len(c.CipherSuites) == 0 {
		c.CipherSuites = defaultSupportedCipherSuites
	}
	if len(c.Groups) == 0 {
		c.Groups = defaultSupportedGroups
	}
	if len(c.SignatureSchemes) == 0 {
		c.SignatureSchemes = defaultSignatureSchemes
	}
	if c.TicketLen == 0 {
		c.TicketLen = defaultTicketLen
	}
	if !reflect.ValueOf(c.PSKs).IsValid() {
		c.PSKs = &PSKMapCache{}
	}
	if len(c.PSKModes) == 0 {
		c.PSKModes = defaultPSKModes
	}

	// If there is no certificate, generate one
	if !isClient && len(c.Certificates) == 0 {
		priv, err := newSigningKey(RSA_PSS_SHA256)
		if err != nil {
			return err
		}

		cert, err := newSelfSigned(c.ServerName, RSA_PKCS1_SHA256, priv)
		if err != nil {
			return err
		}

		c.Certificates = []*Certificate{
			{
				Chain:      []*x509.Certificate{cert},
				PrivateKey: priv,
			},
		}
	}

	return nil
}

func (c Config) ValidForServer() bool {
	return (reflect.ValueOf(c.PSKs).IsValid() && c.PSKs.Size() > 0) ||
		(len(c.Certificates) > 0 &&
			len(c.Certificates[0].Chain) > 0 &&
			c.Certificates[0].PrivateKey != nil)
}

func (c Config) ValidForClient() bool {
	return len(c.ServerName) > 0
}

var (
	defaultSupportedCipherSuites = []CipherSuite{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
	}

	defaultSupportedGroups = []NamedGroup{
		P256,
		P384,
		FFDHE2048,
		X25519,
	}

	defaultSignatureSchemes = []SignatureScheme{
		RSA_PSS_SHA256,
		RSA_PSS_SHA384,
		RSA_PSS_SHA512,
		ECDSA_P256_SHA256,
		ECDSA_P384_SHA384,
		ECDSA_P521_SHA512,
	}

	defaultTicketLen = 16

	defaultPSKModes = []PSKKeyExchangeMode{
		PSKModeKE,
		PSKModeDHEKE,
	}
)

type ConnectionState struct {
	HandshakeComplete bool                // TLS handshake is complete
	CipherSuite       CipherSuite         // cipher suite in use (TLS_RSA_WITH_RC4_128_SHA, ...)
	PeerCertificates  []*x509.Certificate // certificate chain presented by remote peer
}

// Conn implements the net.Conn interface, as with "crypto/tls"
// * Read, Write, and Close are provided locally
// * LocalAddr, RemoteAddr, and Set*Deadline are forwarded to the inner Conn
type Conn struct {
	config   *Config
	conn     net.Conn
	isClient bool

	EarlyData []byte

	state             StateConnected
	handshakeMutex    sync.Mutex
	handshakeAlert    Alert
	handshakeComplete bool

	readBuffer []byte
	in, out    *RecordLayer
	hIn, hOut  *HandshakeLayer
}

func NewConn(conn net.Conn, config *Config, isClient bool) *Conn {
	c := &Conn{conn: conn, config: config, isClient: isClient}
	c.in = NewRecordLayer(c.conn)
	c.out = NewRecordLayer(c.conn)
	c.hIn = NewHandshakeLayer(c.in)
	c.hOut = NewHandshakeLayer(c.out)
	return c
}

func (c *Conn) extendBuffer(n int) error {
	// XXX: crypto/tls bounds the number of empty records that can be read.  Should we?
	// if there's no more data left, stop reading
	if len(c.in.nextData) == 0 && len(c.readBuffer) > 0 {
		return nil
	}

	for len(c.readBuffer) <= n {
		pt, err := c.in.ReadRecord()
		if pt == nil {
			return err
		}

		switch pt.contentType {
		case RecordTypeHandshake:
			// We do not support fragmentation of post-handshake handshake messages.
			// TODO: Factor this more elegantly; coalesce with handshakeLayer.ReadMessage()
			start := 0
			for start < len(pt.fragment) {
				if len(pt.fragment[start:]) < handshakeHeaderLen {
					return fmt.Errorf("Post-handshake handshake message too short for header")
				}

				hm := &HandshakeMessage{}
				hm.msgType = HandshakeType(pt.fragment[start])
				hmLen := (int(pt.fragment[start+1]) << 16) + (int(pt.fragment[start+2]) << 8) + int(pt.fragment[start+3])

				if len(pt.fragment[start+handshakeHeaderLen:]) < hmLen {
					return fmt.Errorf("Post-handshake handshake message too short for body")
				}
				hm.body = pt.fragment[start+handshakeHeaderLen : start+handshakeHeaderLen+hmLen]

				// Advance state machine
				state, actions, alert := c.state.Next(hm)

				if alert != AlertNoAlert {
					logf(logTypeHandshake, "Error in state transition: %v", alert)
					c.sendAlert(alert)
					return io.EOF
				}

				for _, action := range actions {
					alert = c.takeAction(action)
					if alert != AlertNoAlert {
						logf(logTypeHandshake, "Error during handshake actions: %v", alert)
						c.sendAlert(alert)
						return io.EOF
					}
				}

				// XXX: If we want to support more advanced cases, e.g., post-handshake
				// authentication, we'll need to allow transitions other than
				// Connected -> Connected
				var connected bool
				c.state, connected = state.(StateConnected)
				if !connected {
					logf(logTypeHandshake, "Disconnected after state transition: %v", alert)
					c.sendAlert(alert)
					return io.EOF
				}

				start += handshakeHeaderLen + hmLen
			}
		case RecordTypeAlert:
			logf(logTypeIO, "extended buffer (for alert): [%d] %x", len(c.readBuffer), c.readBuffer)
			if len(pt.fragment) != 2 {
				c.sendAlert(AlertUnexpectedMessage)
				return io.EOF
			}
			if Alert(pt.fragment[1]) == AlertCloseNotify {
				return io.EOF
			}

			switch pt.fragment[0] {
			case AlertLevelWarning:
				// drop on the floor
			case AlertLevelError:
				return Alert(pt.fragment[1])
			default:
				c.sendAlert(AlertUnexpectedMessage)
				return io.EOF
			}

		case RecordTypeApplicationData:
			c.readBuffer = append(c.readBuffer, pt.fragment...)
			logf(logTypeIO, "extended buffer: [%d] %x", len(c.readBuffer), c.readBuffer)
		}

		if err != nil {
			return err
		}

		// if there's no more data left, stop reading
		if len(c.in.nextData) == 0 {
			return nil
		}

		// if we're over the limit and the next record is not an alert, exit
		if len(c.readBuffer) == n && RecordType(c.in.nextData[0]) != RecordTypeAlert {
			return nil
		}
	}
	return nil
}

// Read application data until the buffer is full.  Handshake and alert records
// are consumed by the Conn object directly.
func (c *Conn) Read(buffer []byte) (int, error) {
	if alert := c.Handshake(); alert != AlertNoAlert {
		return 0, alert
	}

	// Lock the input channel
	c.in.Lock()
	defer c.in.Unlock()

	n := len(buffer)
	err := c.extendBuffer(n)
	var read int
	if len(c.readBuffer) < n {
		buffer = buffer[:len(c.readBuffer)]
		copy(buffer, c.readBuffer)
		read = len(c.readBuffer)
		c.readBuffer = c.readBuffer[:0]
	} else {
		logf(logTypeIO, "read buffer larger than than input buffer")
		copy(buffer[:n], c.readBuffer[:n])
		c.readBuffer = c.readBuffer[n:]
		read = n
	}

	return read, err
}

// Write application data
func (c *Conn) Write(buffer []byte) (int, error) {
	// Lock the output channel
	c.out.Lock()
	defer c.out.Unlock()

	// Send full-size fragments
	var start int
	sent := 0
	for start = 0; len(buffer)-start >= maxFragmentLen; start += maxFragmentLen {
		err := c.out.WriteRecord(&TLSPlaintext{
			contentType: RecordTypeApplicationData,
			fragment:    buffer[start : start+maxFragmentLen],
		})

		if err != nil {
			return sent, err
		}
		sent += maxFragmentLen
	}

	// Send a final partial fragment if necessary
	if start < len(buffer) {
		err := c.out.WriteRecord(&TLSPlaintext{
			contentType: RecordTypeApplicationData,
			fragment:    buffer[start:],
		})

		if err != nil {
			return sent, err
		}
		sent += len(buffer[start:])
	}
	return sent, nil
}

// sendAlert sends a TLS alert message.
// c.out.Mutex <= L.
func (c *Conn) sendAlert(err Alert) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	var level int
	switch err {
	case AlertNoRenegotiation, AlertCloseNotify:
		level = AlertLevelWarning
	default:
		level = AlertLevelError
	}

	buf := []byte{byte(err), byte(level)}
	c.out.WriteRecord(&TLSPlaintext{
		contentType: RecordTypeAlert,
		fragment:    buf,
	})

	// close_notify and end_of_early_data are not actually errors
	if level == AlertLevelWarning {
		return &net.OpError{Op: "local error", Err: err}
	}

	return c.Close()
}

// Close closes the connection.
func (c *Conn) Close() error {
	// XXX crypto/tls has an interlock with Write here.  Do we need that?

	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means Read and Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) takeAction(actionGeneric HandshakeAction) Alert {
	label := "[server]"
	if c.isClient {
		label = "[client]"
	}

	switch action := actionGeneric.(type) {
	case SendHandshakeMessage:
		err := c.hOut.WriteMessage(action.Message)
		if err != nil {
			logf(logTypeHandshake, "%s Error writing handshake message: %v", label, err)
			return AlertInternalError
		}

	case RekeyIn:
		logf(logTypeHandshake, "%s Rekeying in to %s: %+v", label, action.Label, action.KeySet)
		err := c.in.Rekey(action.KeySet.cipher, action.KeySet.key, action.KeySet.iv)
		if err != nil {
			logf(logTypeHandshake, "%s Unable to rekey inbound: %v", label, err)
			return AlertInternalError
		}

	case RekeyOut:
		logf(logTypeHandshake, "%s Rekeying out to %s: %+v", label, action.Label, action.KeySet)
		err := c.out.Rekey(action.KeySet.cipher, action.KeySet.key, action.KeySet.iv)
		if err != nil {
			logf(logTypeHandshake, "%s Unable to rekey outbound: %v", label, err)
			return AlertInternalError
		}

	case SendEarlyData:
		logf(logTypeHandshake, "%s Sending early data...", label)
		_, err := c.Write(c.EarlyData)
		if err != nil {
			logf(logTypeHandshake, "%s Error writing early data: %v", label, err)
			return AlertInternalError
		}

	case ReadPastEarlyData:
		logf(logTypeHandshake, "%s Reading past early data...", label)
		// Scan past all records that fail to decrypt
		_, err := c.in.PeekRecordType()
		if err == nil {
			break
		}
		_, ok := err.(DecryptError)

		for ok {
			_, err = c.in.PeekRecordType()
			if err == nil {
				break
			}
			_, ok = err.(DecryptError)
		}

	case ReadEarlyData:
		logf(logTypeHandshake, "%s Reading early data...", label)
		t, err := c.in.PeekRecordType()
		if err != nil {
			logf(logTypeHandshake, "%s Error reading record type: %v", label, err)
			return AlertInternalError
		}
		logf(logTypeHandshake, "%s Got record type: %v", label, t)

		for t == RecordTypeApplicationData {
			// Read a record into the buffer
			pt, err := c.in.ReadRecord()
			if err != nil {
				logf(logTypeHandshake, "%s Error reading early data record: %v", label, err)
				return AlertInternalError
			}

			logf(logTypeHandshake, "%s Read early data: %x", label, pt.fragment)
			c.EarlyData = append(c.EarlyData, pt.fragment...)

			t, err = c.in.PeekRecordType()
			if err != nil {
				logf(logTypeHandshake, "%s Error reading record type: %v", label, err)
				return AlertInternalError
			}
			logf(logTypeHandshake, "%s Got record type: %v", label, t)
		}

	case StorePSK:
		logf(logTypeHandshake, "%s Storing new session ticket with identity [%x]", label, action.PSK.Identity)
		if c.isClient {
			// Clients look up PSKs based on server name
			c.config.PSKs.Put(c.config.ServerName, action.PSK)
		} else {
			// Servers look them up based on the identity in the extension
			c.config.PSKs.Put(hex.EncodeToString(action.PSK.Identity), action.PSK)
		}

	default:
		logf(logTypeHandshake, "%s Unknown actionuction type", label)
		return AlertInternalError
	}

	return AlertNoAlert
}

// Handshake causes a TLS handshake on the connection.  The `isClient` member
// determines whether a client or server handshake is performed.  If a
// handshake has already been performed, then its result will be returned.
func (c *Conn) Handshake() Alert {
	// TODO Lock handshakeMutex
	// TODO Remove CloseNotify hack
	if c.handshakeAlert != AlertNoAlert && c.handshakeAlert != AlertCloseNotify {
		logf(logTypeHandshake, "Pre-existing handshake error: %v", c.handshakeAlert)
		return c.handshakeAlert
	}
	if c.handshakeComplete {
		return AlertNoAlert
	}

	if err := c.config.Init(c.isClient); err != nil {
		logf(logTypeHandshake, "Error initializing config: %v", err)
		return AlertInternalError
	}

	// Set things up
	caps := Capabilities{
		CipherSuites:      c.config.CipherSuites,
		Groups:            c.config.Groups,
		SignatureSchemes:  c.config.SignatureSchemes,
		PSKs:              c.config.PSKs,
		PSKModes:          c.config.PSKModes,
		AllowEarlyData:    c.config.AllowEarlyData,
		RequireCookie:     c.config.RequireCookie,
		RequireClientAuth: c.config.RequireClientAuth,
		NextProtos:        c.config.NextProtos,
		Certificates:      c.config.Certificates,
	}
	opts := ConnectionOptions{
		ServerName: c.config.ServerName,
		NextProtos: c.config.NextProtos,
		EarlyData:  c.EarlyData,
	}

	var state HandshakeState
	var actions []HandshakeAction
	var alert Alert
	connected := false

	if c.isClient {
		state, actions, alert = ClientStateStart{Caps: caps, Opts: opts}.Next(nil)
		if alert != AlertNoAlert {
			logf(logTypeHandshake, "Error initializing client state: %v", alert)
			return alert
		}

		for _, action := range actions {
			alert = c.takeAction(action)
			if alert != AlertNoAlert {
				logf(logTypeHandshake, "Error during handshake actions: %v", alert)
				return alert
			}
		}

		_, connected = state.(StateConnected)
	} else {
		state = ServerStateStart{Caps: caps}
	}

	for !connected {
		// Read a handshake message
		hm, err := c.hIn.ReadMessage()
		if err != nil {
			logf(logTypeHandshake, "Error reading message: %v", err)
			c.sendAlert(AlertCloseNotify)
			return AlertCloseNotify
		}
		logf(logTypeHandshake, "Read message with type: %v", hm.msgType)

		// Advance the state machine
		state, actions, alert = state.Next(hm)

		if alert != AlertNoAlert {
			logf(logTypeHandshake, "Error in state transition: %v", alert)
			return alert
		}

		for _, action := range actions {
			alert = c.takeAction(action)
			if alert != AlertNoAlert {
				logf(logTypeHandshake, "Error during handshake actions: %v", alert)
				c.sendAlert(alert)
				return alert
			}
		}

		_, connected = state.(StateConnected)
	}

	c.state = state.(StateConnected)

	// Send NewSessionTicket if acting as server
	if !c.isClient {
		actions, alert := c.state.NewSessionTicket(
			c.config.TicketLen,
			c.config.TicketLifetime,
			c.config.EarlyDataLifetime)

		for _, action := range actions {
			alert = c.takeAction(action)
			if alert != AlertNoAlert {
				logf(logTypeHandshake, "Error during handshake actions: %v", alert)
				c.sendAlert(alert)
				return alert
			}
		}
	}

	c.handshakeComplete = true
	return AlertNoAlert
}

func (c *Conn) SendKeyUpdate(requestUpdate bool) error {
	if !c.handshakeComplete {
		return fmt.Errorf("Cannot update keys until after handshake")
	}

	request := KeyUpdateNotRequested
	if requestUpdate {
		request = KeyUpdateRequested
	}

	// Create the key update and update state
	actions, alert := c.state.KeyUpdate(request)
	if alert != AlertNoAlert {
		c.sendAlert(alert)
		return fmt.Errorf("Alert while generating key update: %v", alert)
	}

	// Take actions (send key update and rekey)
	for _, action := range actions {
		alert = c.takeAction(action)
		if alert != AlertNoAlert {
			c.sendAlert(alert)
			return fmt.Errorf("Alert during key update actions: %v", alert)
		}
	}

	return nil
}
