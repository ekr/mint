package mint

// enum {...} ContentType;
type recordType byte

const (
	recordTypeAlert           recordType = 21
	recordTypeHandshake       recordType = 22
	recordTypeApplicationData recordType = 23
)

// enum {...} HandshakeType;
type handshakeType byte

const (
	// Omitted: *_RESERVED
	handshakeTypeClientHello         handshakeType = 1
	handshakeTypeServerHello         handshakeType = 2
	handshakeTypeSessionTicket       handshakeType = 4
	handshakeTypeHelloRetryRequest   handshakeType = 6
	handshakeTypeEncryptedExtensions handshakeType = 8
	handshakeTypeCertificate         handshakeType = 11
	handshakeTypeCertificateRequest  handshakeType = 13
	handshakeTypeCertificateVerify   handshakeType = 15
	handshakeTypeServerConfiguration handshakeType = 17
	handshakeTypeFinished            handshakeType = 20
	handshakeTypeKeyUpdate           handshakeType = 24
)

// uint8 CipherSuite[2];
type cipherSuite uint16

const (
	// REQUIRED
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipherSuite = 0xC02B
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   cipherSuite = 0xC02F
	// RECOMMENDED
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       cipherSuite = 0xC02C
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 cipherSuite = 0xCCA9
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         cipherSuite = 0xC030
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   cipherSuite = 0xCCA8
)

// enum {...} HashAlgorithm
type hashAlgorithm uint8

const (
	// Omitted: *_RESERVED
	hashAlgorithmSHA1   hashAlgorithm = 2
	hashAlgorithmSHA256 hashAlgorithm = 4
	hashAlgorithmSHA384 hashAlgorithm = 5
	hashAlgorithmSHA512 hashAlgorithm = 6
)

// enum {...} SignatureAlgorithm
type signatureAlgorithm uint8

const (
	// Omitted: *_RESERVED
	signatureAlgorithmRSA    signatureAlgorithm = 1
	signatureAlgorithmDSA    signatureAlgorithm = 2
	signatureAlgorithmECDSA  signatureAlgorithm = 3
	signatureAlgorithmRSAPSS signatureAlgorithm = 4
	signatureAlgorithmEdDSA  signatureAlgorithm = 5
)

// struct {
//     HashAlgorithm hash;
//     SignatureAlgorithm signature;
// } SignatureAndHashAlgorithm;
//
type signatureAndHashAlgorithm struct {
	hash      hashAlgorithm
	signature signatureAlgorithm
}

// enum {...} ExtensionType
type helloExtensionType uint16

const (
	extensionTypeUnknown             helloExtensionType = 0xffff
	extensionTypeServerName          helloExtensionType = 0
	extensionTypeSupportedGroups     helloExtensionType = 10
	extensionTypeSignatureAlgorithms helloExtensionType = 13
	extensionTypeEarlyData           helloExtensionType = 0xff00 // TBD
	extensionTypePreSharedKey        helloExtensionType = 0xff01 // TBD
	extensionTypeKeyShare            helloExtensionType = 0xff02 // TBD
)

// enum {...} NamedGroup
type namedGroup uint16

const (
	namedGroupUnknown namedGroup = 0
	// Elliptic Curve Groups.
	namedGroupP256 namedGroup = 23
	namedGroupP384 namedGroup = 24
	namedGroupP521 namedGroup = 25
	// ECDH functions.
	namedGroupX25519 namedGroup = 29
	namedGroupX448   namedGroup = 30
	// Signature-only curves.
	namedGroupEd25519 namedGroup = 31
	namedGroupEd448   namedGroup = 32
	// Finite field groups.
	namedGroupFF2048 namedGroup = 256
	namedGroupFF3072 namedGroup = 257
	namedGroupFF4096 namedGroup = 258
	namedGroupFF6144 namedGroup = 259
	namedGroupFF8192 namedGroup = 250
)

type marshaler interface {
	Marshal() ([]byte, error)
}

type unmarshaler interface {
	Unmarshal([]byte) (int, error)
}