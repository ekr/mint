package mint

import (
	"bytes"
	"crypto"
	"hash"
	"time"
	"log"
	"encoding/hex"
)

// Client State Machine
//
//                            START <----+
//             Send ClientHello |        | Recv HelloRetryRequest
//          /                   v        |
//         |                  WAIT_SH ---+
//     Can |                    | Recv ServerHello
//    send |                    V
//   early |                 WAIT_EE
//    data |                    | Recv EncryptedExtensions
//         |           +--------+--------+
//         |     Using |                 | Using certificate
//         |       PSK |                 v
//         |           |            WAIT_CERT_CR
//         |           |        Recv |       | Recv CertificateRequest
//         |           | Certificate |       v
//         |           |             |    WAIT_CERT
//         |           |             |       | Recv Certificate
//         |           |             v       v
//         |           |              WAIT_CV
//         |           |                 | Recv CertificateVerify
//         |           +> WAIT_FINISHED <+
//         |                  | Recv Finished
//         \                  |
//                            | [Send EndOfEarlyData]
//                            | [Send Certificate [+ CertificateVerify]]
//                            | Send Finished
//  Can send                  v
//  app data -->          CONNECTED
//  after
//  here
//
//  State							Instructions
//  START							Send(CH); [RekeyOut; SendEarlyData]
//  WAIT_SH						Send(CH) || RekeyIn
//  WAIT_EE						{}
//  WAIT_CERT_CR			{}
//  WAIT_CERT					{}
//  WAIT_CV						{}
//  WAIT_FINISHED			RekeyIn; [Send(EOED);] RekeyOut; [SendCert; SendCV;] SendFin; RekeyOut;
//  CONNECTED					StoreTicket || (RekeyIn; [RekeyOut])

var isClient bool = true

type ClientStateStart struct {
	Caps   Capabilities
	Opts   ConnectionOptions
	Params ConnectionParameters

	cookie            []byte
	firstClientHello  *HandshakeMessage
	helloRetryRequest *HandshakeMessage
}

func (state ClientStateStart) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeAction, Alert) {
	if hm != nil {
		logf(logTypeHandshake, "[ClientStateStart] Unexpected non-nil message")
		return nil, nil, AlertUnexpectedMessage
	}

	// key_shares
	offeredDH := map[NamedGroup][]byte{}
	ks := KeyShareExtension{
		HandshakeType: HandshakeTypeClientHello,
		Shares:        make([]KeyShareEntry, len(state.Caps.Groups)),
	}
	for i, group := range state.Caps.Groups {
		pub, priv, err := newKeyShare(group, isClient)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error generating key share [%v]", err)
			return nil, nil, AlertInternalError
		}

		ks.Shares[i].Group = group
		ks.Shares[i].KeyExchange = pub
		offeredDH[group] = priv
	}

	logf(logTypeHandshake, "opts: %+v", state.Opts)

	// supported_versions, supported_groups, signature_algorithms, server_name
	sv := SupportedVersionsExtension{Versions: []uint16{supportedVersion}}
	sni := ServerNameExtension(state.Opts.ServerName)
	sg := SupportedGroupsExtension{Groups: state.Caps.Groups}
	sa := SignatureAlgorithmsExtension{Algorithms: state.Caps.SignatureSchemes}

	state.Params.ServerName = state.Opts.ServerName

	// Application Layer Protocol Negotiation
	var alpn *ALPNExtension
	if (state.Opts.NextProtos != nil) && (len(state.Opts.NextProtos) > 0) {
		alpn = &ALPNExtension{Protocols: state.Opts.NextProtos}
	}

	// Construct base ClientHello
	ch := &ClientHelloBody{
		CipherSuites: state.Caps.CipherSuites,
	}
	// In Mint, Clinet Random needs to be a random value.
	_, err := prng.Read(ch.Random[:])
	if err != nil {
		logf(logTypeHandshake, "[ClientStateStart] Error creating ClientHello random [%v]", err)
		return nil, nil, AlertInternalError
	}
  // In Spearmint, Client Random needs to be set to 0.
  for i, _ := range ch.Random { ch.Random[i] = 0 }
	log.Printf("client random is:\n%v", hex.Dump(ch.Random[:]))

	for _, ext := range []ExtensionBody{&sv, &sni, &ks, &sg, &sa} {
		err := ch.Extensions.Add(ext)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error adding extension type=[%v] [%v]", ext.Type(), err)
			return nil, nil, AlertInternalError
		}
	}
	// XXX: These optional extensions can't be folded into the above because Go
	// interface-typed values are never reported as nil
	if alpn != nil {
		err := ch.Extensions.Add(alpn)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error adding ALPN extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	if state.cookie != nil {
		err := ch.Extensions.Add(&CookieExtension{Cookie: state.cookie})
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error adding ALPN extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	// Handle PSK and EarlyData just before transmitting, so that we can
	// calculate the PSK binder value
	var psk *PreSharedKeyExtension
	var ed *EarlyDataExtension
	var offeredPSK PreSharedKey
	var earlyHash crypto.Hash
	var earlySecret []byte
	var clientEarlyTrafficKeys keySet
	var clientHello *HandshakeMessage
	if key, ok := state.Caps.PSKs.Get(state.Opts.ServerName); ok {
		offeredPSK = key

		// Narrow ciphersuites to ones that match PSK hash
		params, ok := cipherSuiteMap[key.CipherSuite]
		if !ok {
			logf(logTypeHandshake, "[ClientStateStart] PSK for unknown ciphersuite")
			return nil, nil, AlertInternalError
		}

		compatibleSuites := []CipherSuite{}
		for _, suite := range ch.CipherSuites {
			if cipherSuiteMap[suite].hash == params.hash {
				compatibleSuites = append(compatibleSuites, suite)
			}
		}
		ch.CipherSuites = compatibleSuites

		// Signal early data if we're going to do it
		if len(state.Opts.EarlyData) > 0 {
			state.Params.ClientSendingEarlyData = true
			ed = &EarlyDataExtension{}
			err = ch.Extensions.Add(ed)
			if err != nil {
				logf(logTypeHandshake, "Error adding early data extension: %v", err)
				return nil, nil, AlertInternalError
			}
		}

		// Signal supported PSK key exchange modes
		if len(state.Caps.PSKModes) == 0 {
			logf(logTypeHandshake, "PSK selected, but no PSKModes")
			return nil, nil, AlertInternalError
		}
		kem := &PSKKeyExchangeModesExtension{KEModes: state.Caps.PSKModes}
		err = ch.Extensions.Add(kem)
		if err != nil {
			logf(logTypeHandshake, "Error adding PSKKeyExchangeModes extension: %v", err)
			return nil, nil, AlertInternalError
		}

		// Add the shim PSK extension to the ClientHello
		logf(logTypeHandshake, "Adding PSK extension with id = %x", key.Identity)
		psk = &PreSharedKeyExtension{
			HandshakeType: HandshakeTypeClientHello,
			Identities: []PSKIdentity{
				{
					Identity:            key.Identity,
					ObfuscatedTicketAge: uint32(time.Since(key.ReceivedAt)/time.Millisecond) + key.TicketAgeAdd,
				},
			},
			Binders: []PSKBinderEntry{
				// Note: Stub to get the length fields right
				{Binder: bytes.Repeat([]byte{0x00}, params.hash.Size())},
			},
		}
		ch.Extensions.Add(psk)

		// Compute the binder key
		h0 := params.hash.New().Sum(nil)
		zero := bytes.Repeat([]byte{0}, params.hash.Size())

		earlyHash = params.hash
		earlySecret = hkdfExtract(params.hash, zero, key.Key)
		logf(logTypeCrypto, "early secret: [%d] %x", len(earlySecret), earlySecret)

		binderLabel := labelExternalBinder
		if key.IsResumption {
			binderLabel = labelResumptionBinder
		}
		binderKey := deriveSecret(params, earlySecret, binderLabel, h0)
		logf(logTypeCrypto, "binder key: [%d] %x", len(binderKey), binderKey)

		// Compute the binder value
		trunc, err := ch.Truncated()
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error marshaling truncated ClientHello [%v]", err)
			return nil, nil, AlertInternalError
		}

		truncHash := params.hash.New()
		truncHash.Write(trunc)

		binder := computeFinishedData(params, binderKey, truncHash.Sum(nil))

		// Replace the PSK extension
		psk.Binders[0].Binder = binder
		ch.Extensions.Add(psk)

		// If we got here, the earlier marshal succeeded (in ch.Truncated()), so
		// this one should too.
		clientHello, _ = HandshakeMessageFromBody(ch)

		// Compute early traffic keys
		h := params.hash.New()
		h.Write(clientHello.Marshal())
		chHash := h.Sum(nil)

		earlyTrafficSecret := deriveSecret(params, earlySecret, labelEarlyTrafficSecret, chHash)
		logf(logTypeCrypto, "early traffic secret: [%d] %x", len(earlyTrafficSecret), earlyTrafficSecret)
		clientEarlyTrafficKeys = makeTrafficKeys(params, earlyTrafficSecret)
	} else if len(state.Opts.EarlyData) > 0 {
		logf(logTypeHandshake, "[ClientStateWaitSH] Early data without PSK")
		return nil, nil, AlertInternalError
	} else {
		clientHello, err = HandshakeMessageFromBody(ch)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error marshaling ClientHello [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	logf(logTypeHandshake, "[ClientStateStart] -> [ClientStateWaitSH]")
	nextState := ClientStateWaitSH{
		Caps:       state.Caps,
		Opts:       state.Opts,
		Params:     state.Params,
		OfferedDH:  offeredDH,
		OfferedPSK: offeredPSK,

		earlySecret: earlySecret,
		earlyHash:   earlyHash,

		firstClientHello:  state.firstClientHello,
		helloRetryRequest: state.helloRetryRequest,
		clientHello:       clientHello,
	}

	toSend := []HandshakeAction{
		SendHandshakeMessage{clientHello},
	}
	if state.Params.ClientSendingEarlyData {
		toSend = append(toSend, []HandshakeAction{
			RekeyOut{Label: "early", KeySet: clientEarlyTrafficKeys},
			SendEarlyData{},
		}...)
	}

	return nextState, toSend, AlertNoAlert
}

type ClientStateWaitSH struct {
	Caps       Capabilities
	Opts       ConnectionOptions
	Params     ConnectionParameters
	OfferedDH  map[NamedGroup][]byte
	OfferedPSK PreSharedKey
	PSK        []byte

	earlySecret []byte
	earlyHash   crypto.Hash

	firstClientHello  *HandshakeMessage
	helloRetryRequest *HandshakeMessage
	clientHello       *HandshakeMessage
}

func (state ClientStateWaitSH) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeAction, Alert) {
	if hm == nil {
		logf(logTypeHandshake, "[ClientStateWaitSH] Unexpected nil message")
		return nil, nil, AlertUnexpectedMessage
	}

	bodyGeneric, err := hm.ToBody()
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitSH] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	switch body := bodyGeneric.(type) {
	case *HelloRetryRequestBody:
		hrr := body

		if state.helloRetryRequest != nil {
			logf(logTypeHandshake, "[ClientStateWaitSH] Received a second HelloRetryRequest")
			return nil, nil, AlertUnexpectedMessage
		}

		// Check that the version sent by the server is the one we support
		if hrr.Version != supportedVersion {
			logf(logTypeHandshake, "[ClientStateWaitSH] Unsupported version [%v]", hrr.Version)
			return nil, nil, AlertProtocolVersion
		}

		// Check that the server provided a supported ciphersuite
		supportedCipherSuite := false
		for _, suite := range state.Caps.CipherSuites {
			supportedCipherSuite = supportedCipherSuite || (suite == hrr.CipherSuite)
		}
		if !supportedCipherSuite {
			logf(logTypeHandshake, "[ClientStateWaitSH] Unsupported ciphersuite [%04x]", hrr.CipherSuite)
			return nil, nil, AlertHandshakeFailure
		}

		// Narrow the supported ciphersuites to the server-provided one
		state.Caps.CipherSuites = []CipherSuite{hrr.CipherSuite}

		// The only thing we know how to respond to in an HRR is the Cookie
		// extension, so if there is either no Cookie extension or anything other
		// than a Cookie extension, we have to fail.
		serverCookie := new(CookieExtension)
		foundCookie := hrr.Extensions.Find(serverCookie)
		if !foundCookie || len(hrr.Extensions) != 1 {
			logf(logTypeHandshake, "[ClientStateWaitSH] No Cookie or extra extensions [%v] [%d]", foundCookie, len(hrr.Extensions))
			return nil, nil, AlertIllegalParameter
		}

		// Hash the body into a pseudo-message
		// XXX: Ignoring some errors here
		params := cipherSuiteMap[hrr.CipherSuite]
		h := params.hash.New()
		h.Write(state.clientHello.Marshal())
		firstClientHello := &HandshakeMessage{
			msgType: HandshakeTypeMessageHash,
			body:    h.Sum(nil),
		}

		logf(logTypeHandshake, "[ClientStateWaitSH] -> [ClientStateStart]")
		return ClientStateStart{
			Caps:              state.Caps,
			Opts:              state.Opts,
			cookie:            serverCookie.Cookie,
			firstClientHello:  firstClientHello,
			helloRetryRequest: hm,
		}.Next(nil)

	case *ServerHelloBody:
		sh := body

		// Check that the version sent by the server is the one we support
		if sh.Version != supportedVersion {
			logf(logTypeHandshake, "[ClientStateWaitSH] Unsupported version [%v]", sh.Version)
			return nil, nil, AlertProtocolVersion
		}

		// Check that the server provided a supported ciphersuite
		supportedCipherSuite := false
		for _, suite := range state.Caps.CipherSuites {
			supportedCipherSuite = supportedCipherSuite || (suite == sh.CipherSuite)
		}
		if !supportedCipherSuite {
			logf(logTypeHandshake, "[ClientStateWaitSH] Unsupported ciphersuite [%04x]", sh.CipherSuite)
			return nil, nil, AlertHandshakeFailure
		}

		// Do PSK or key agreement depending on extensions
		serverPSK := PreSharedKeyExtension{HandshakeType: HandshakeTypeServerHello}
		serverKeyShare := KeyShareExtension{HandshakeType: HandshakeTypeServerHello}

		foundPSK := sh.Extensions.Find(&serverPSK)
		foundKeyShare := sh.Extensions.Find(&serverKeyShare)

		if foundPSK && (serverPSK.SelectedIdentity == 0) {
			state.Params.UsingPSK = true
		}

		var dhSecret []byte
		if foundKeyShare {
			sks := serverKeyShare.Shares[0]
			priv, ok := state.OfferedDH[sks.Group]
			if !ok {
				logf(logTypeHandshake, "[ClientStateWaitSH] Key share for unknown group")
				return nil, nil, AlertIllegalParameter
			}

			state.Params.UsingDH = true
			dhSecret, _ = keyAgreement(sks.Group, sks.KeyExchange, priv)
		}

		suite := sh.CipherSuite
		state.Params.CipherSuite = suite

		params, ok := cipherSuiteMap[suite]
		if !ok {
			logf(logTypeCrypto, "Unsupported ciphersuite [%04x]", suite)
			return nil, nil, AlertHandshakeFailure
		}

		// Start up the handshake hash
		handshakeHash := params.hash.New()
		handshakeHash.Write(state.firstClientHello.Marshal())
		handshakeHash.Write(state.helloRetryRequest.Marshal())
		handshakeHash.Write(state.clientHello.Marshal())
		handshakeHash.Write(hm.Marshal())

		// Compute handshake secrets
		zero := bytes.Repeat([]byte{0}, params.hash.Size())

		var earlySecret []byte
		if state.Params.UsingPSK {
			if params.hash != state.earlyHash {
				logf(logTypeCrypto, "Change of hash between early and normal init early=[%02x] suite=[%04x] hash=[%02x]",
					state.earlyHash, suite, params.hash)
			}

			earlySecret = state.earlySecret
		} else {
			earlySecret = hkdfExtract(params.hash, zero, zero)
		}

		if dhSecret == nil {
			dhSecret = zero
		}

		h0 := params.hash.New().Sum(nil)
		h2 := handshakeHash.Sum(nil)
		preHandshakeSecret := deriveSecret(params, earlySecret, labelDerived, h0)
		handshakeSecret := hkdfExtract(params.hash, preHandshakeSecret, dhSecret)
		clientHandshakeTrafficSecret := deriveSecret(params, handshakeSecret, labelClientHandshakeTrafficSecret, h2)
		serverHandshakeTrafficSecret := deriveSecret(params, handshakeSecret, labelServerHandshakeTrafficSecret, h2)
		preMasterSecret := deriveSecret(params, handshakeSecret, labelDerived, h0)
		masterSecret := hkdfExtract(params.hash, preMasterSecret, zero)

		logf(logTypeCrypto, "early secret: [%d] %x", len(earlySecret), earlySecret)
		logf(logTypeCrypto, "handshake secret: [%d] %x", len(handshakeSecret), handshakeSecret)
		logf(logTypeCrypto, "client handshake traffic secret: [%d] %x", len(clientHandshakeTrafficSecret), clientHandshakeTrafficSecret)
		logf(logTypeCrypto, "server handshake traffic secret: [%d] %x", len(serverHandshakeTrafficSecret), serverHandshakeTrafficSecret)
		logf(logTypeCrypto, "master secret: [%d] %x", len(masterSecret), masterSecret)

		serverHandshakeKeys := makeTrafficKeys(params, serverHandshakeTrafficSecret)

		logf(logTypeHandshake, "[ClientStateWaitSH] -> [ClientStateWaitEE]")
		nextState := ClientStateWaitEE{
			Params:                       state.Params,
			cryptoParams:                 params,
			handshakeHash:                handshakeHash,
			certificates:                 state.Caps.Certificates,
			masterSecret:                 masterSecret,
			clientHandshakeTrafficSecret: clientHandshakeTrafficSecret,
			serverHandshakeTrafficSecret: serverHandshakeTrafficSecret,
		}
		toSend := []HandshakeAction{
			RekeyIn{Label: "handshake", KeySet: serverHandshakeKeys},
		}
		return nextState, toSend, AlertNoAlert
	}

	logf(logTypeHandshake, "[ClientStateWaitSH] Unexpected message [%s]", hm.msgType)
	return nil, nil, AlertUnexpectedMessage
}

type ClientStateWaitEE struct {
	AuthCertificate              func(chain []CertificateEntry) error
	Params                       ConnectionParameters
	cryptoParams                 cipherSuiteParams
	handshakeHash                hash.Hash
	certificates                 []*Certificate
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
}

func (state ClientStateWaitEE) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeAction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeEncryptedExtensions {
		logf(logTypeHandshake, "[ClientStateWaitEE] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	ee := EncryptedExtensionsBody{}
	_, err := ee.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitEE] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	serverALPN := ALPNExtension{}
	serverEarlyData := EarlyDataExtension{}

	gotALPN := ee.Extensions.Find(&serverALPN)
	state.Params.UsingEarlyData = ee.Extensions.Find(&serverEarlyData)

	if gotALPN && len(serverALPN.Protocols) > 0 {
		state.Params.NextProto = serverALPN.Protocols[0]
	}

	state.handshakeHash.Write(hm.Marshal())

	if state.Params.UsingPSK {
		logf(logTypeHandshake, "[ClientStateWaitEE] -> [ClientStateWaitFinished]")
		nextState := ClientStateWaitFinished{
			Params:                       state.Params,
			cryptoParams:                 state.cryptoParams,
			handshakeHash:                state.handshakeHash,
			certificates:                 state.certificates,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
		}
		return nextState, nil, AlertNoAlert
	}

	logf(logTypeHandshake, "[ClientStateWaitEE] -> [ClientStateWaitCertCR]")
	nextState := ClientStateWaitCertCR{
		AuthCertificate:              state.AuthCertificate,
		Params:                       state.Params,
		cryptoParams:                 state.cryptoParams,
		handshakeHash:                state.handshakeHash,
		certificates:                 state.certificates,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
	}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitCertCR struct {
	AuthCertificate              func(chain []CertificateEntry) error
	Params                       ConnectionParameters
	cryptoParams                 cipherSuiteParams
	handshakeHash                hash.Hash
	certificates                 []*Certificate
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
}

func (state ClientStateWaitCertCR) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeAction, Alert) {
	if hm == nil {
		logf(logTypeHandshake, "[ClientStateWaitCertCR] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	bodyGeneric, err := hm.ToBody()
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCertCR] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	state.handshakeHash.Write(hm.Marshal())

	switch body := bodyGeneric.(type) {
	case *CertificateBody:
		logf(logTypeHandshake, "[ClientStateWaitCertCR] -> [ClientStateWaitCV]")
		nextState := ClientStateWaitCV{
			AuthCertificate:              state.AuthCertificate,
			Params:                       state.Params,
			cryptoParams:                 state.cryptoParams,
			handshakeHash:                state.handshakeHash,
			certificates:                 state.certificates,
			serverCertificate:            body,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
		}
		return nextState, nil, AlertNoAlert

	case *CertificateRequestBody:
		// A certificate request in the handshake should have a zero-length context
		if len(body.CertificateRequestContext) > 0 {
			logf(logTypeHandshake, "[ClientStateWaitCertCR] Certificate request with non-empty context: %v", err)
			return nil, nil, AlertIllegalParameter
		}

		state.Params.UsingClientAuth = true

		logf(logTypeHandshake, "[ClientStateWaitCertCR] -> [ClientStateWaitCert]")
		nextState := ClientStateWaitCert{
			AuthCertificate:              state.AuthCertificate,
			Params:                       state.Params,
			cryptoParams:                 state.cryptoParams,
			handshakeHash:                state.handshakeHash,
			certificates:                 state.certificates,
			serverCertificateRequest:     body,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
		}
		return nextState, nil, AlertNoAlert
	}

	return nil, nil, AlertUnexpectedMessage
}

type ClientStateWaitCert struct {
	AuthCertificate func(chain []CertificateEntry) error
	Params          ConnectionParameters
	cryptoParams    cipherSuiteParams
	handshakeHash   hash.Hash

	certificates             []*Certificate
	serverCertificateRequest *CertificateRequestBody

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
}

func (state ClientStateWaitCert) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeAction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeCertificate {
		logf(logTypeHandshake, "[ClientStateWaitCert] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	cert := &CertificateBody{}
	_, err := cert.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCert] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	state.handshakeHash.Write(hm.Marshal())

	logf(logTypeHandshake, "[ClientStateWaitCert] -> [ClientStateWaitCV]")
	nextState := ClientStateWaitCV{
		AuthCertificate:              state.AuthCertificate,
		Params:                       state.Params,
		cryptoParams:                 state.cryptoParams,
		handshakeHash:                state.handshakeHash,
		certificates:                 state.certificates,
		serverCertificate:            cert,
		serverCertificateRequest:     state.serverCertificateRequest,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
	}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitCV struct {
	AuthCertificate func(chain []CertificateEntry) error
	Params          ConnectionParameters
	cryptoParams    cipherSuiteParams
	handshakeHash   hash.Hash

	certificates             []*Certificate
	serverCertificate        *CertificateBody
	serverCertificateRequest *CertificateRequestBody

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
}

func (state ClientStateWaitCV) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeAction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeCertificateVerify {
		logf(logTypeHandshake, "[ClientStateWaitCV] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	certVerify := CertificateVerifyBody{}
	_, err := certVerify.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCV] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	hcv := state.handshakeHash.Sum(nil)
	logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hcv), hcv)

	serverPublicKey := state.serverCertificate.CertificateList[0].CertData.PublicKey
	if err := certVerify.Verify(serverPublicKey, hcv); err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCV] Server signature failed to verify")
		return nil, nil, AlertHandshakeFailure
	}

	if state.AuthCertificate != nil {
		err := state.AuthCertificate(state.serverCertificate.CertificateList)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateWaitCV] Application rejected server certificate")
			return nil, nil, AlertBadCertificate
		}
	} else {
		logf(logTypeHandshake, "[ClientStateWaitCV] WARNING: No verification of server certificate")
	}

	state.handshakeHash.Write(hm.Marshal())

	logf(logTypeHandshake, "[ClientStateWaitCV] -> [ClientStateWaitFinished]")
	nextState := ClientStateWaitFinished{
		Params:                       state.Params,
		cryptoParams:                 state.cryptoParams,
		handshakeHash:                state.handshakeHash,
		certificates:                 state.certificates,
		serverCertificateRequest:     state.serverCertificateRequest,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
	}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitFinished struct {
	Params        ConnectionParameters
	cryptoParams  cipherSuiteParams
	handshakeHash hash.Hash

	certificates             []*Certificate
	serverCertificateRequest *CertificateRequestBody

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
}

func (state ClientStateWaitFinished) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeAction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeFinished {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	// Verify server's Finished
	h3 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 3 [%d] %x", len(h3), h3)
	logf(logTypeCrypto, "handshake hash for server Finished: [%d] %x", len(h3), h3)

	serverFinishedData := computeFinishedData(state.cryptoParams, state.serverHandshakeTrafficSecret, h3)
	logf(logTypeCrypto, "server finished data: [%d] %x", len(serverFinishedData), serverFinishedData)

	fin := &FinishedBody{VerifyDataLen: len(serverFinishedData)}
	_, err := fin.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	if !bytes.Equal(fin.VerifyData, serverFinishedData) {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Server's Finished failed to verify [%x] != [%x]",
			fin.VerifyData, serverFinishedData)
		return nil, nil, AlertHandshakeFailure
	}

	// Update the handshake hash with the Finished
	state.handshakeHash.Write(hm.Marshal())
	logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(hm.Marshal()), hm.Marshal())
	h4 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 4 [%d]: %x", len(h4), h4)

	// Compute traffic secrets and keys
	clientTrafficSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelClientApplicationTrafficSecret, h4)
	serverTrafficSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelServerApplicationTrafficSecret, h4)
	logf(logTypeCrypto, "client traffic secret: [%d] %x", len(clientTrafficSecret), clientTrafficSecret)
	logf(logTypeCrypto, "server traffic secret: [%d] %x", len(serverTrafficSecret), serverTrafficSecret)

	clientTrafficKeys := makeTrafficKeys(state.cryptoParams, clientTrafficSecret)
	serverTrafficKeys := makeTrafficKeys(state.cryptoParams, serverTrafficSecret)

	// Assemble client's second flight
	toSend := []HandshakeAction{}

	if state.Params.UsingEarlyData {
		// Note: We only send EOED if the server is actually going to use the early
		// data.  Otherwise, it will never see it, and the transcripts will
		// mismatch.
		// EOED marshal is infallible
		eoedm, _ := HandshakeMessageFromBody(&EndOfEarlyDataBody{})
		toSend = append(toSend, SendHandshakeMessage{eoedm})
		state.handshakeHash.Write(eoedm.Marshal())
		logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(eoedm.Marshal()), eoedm.Marshal())
	}

	clientHandshakeKeys := makeTrafficKeys(state.cryptoParams, state.clientHandshakeTrafficSecret)
	toSend = append(toSend, RekeyOut{Label: "handshake", KeySet: clientHandshakeKeys})

	if state.Params.UsingClientAuth {
		// Extract constraints from certicateRequest
		schemes := SignatureAlgorithmsExtension{}
		gotSchemes := state.serverCertificateRequest.Extensions.Find(&schemes)
		if !gotSchemes {
			logf(logTypeHandshake, "[ClientStateWaitFinished] WARNING no appropriate certificate found [%v]", err)
			return nil, nil, AlertIllegalParameter
		}

		// Select a certificate
		cert, certScheme, err := CertificateSelection(nil, schemes.Algorithms, state.certificates)
		if err != nil {
			// XXX: Signal this to the application layer?
			logf(logTypeHandshake, "[ClientStateWaitFinished] WARNING no appropriate certificate found [%v]", err)

			certificate := &CertificateBody{}
			certm, err := HandshakeMessageFromBody(certificate)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling Certificate [%v]", err)
				return nil, nil, AlertInternalError
			}

			toSend = append(toSend, SendHandshakeMessage{certm})
			state.handshakeHash.Write(certm.Marshal())
		} else {
			// Create and send Certificate, CertificateVerify
			certificate := &CertificateBody{
				CertificateList: make([]CertificateEntry, len(cert.Chain)),
			}
			for i, entry := range cert.Chain {
				certificate.CertificateList[i] = CertificateEntry{CertData: entry}
			}
			certm, err := HandshakeMessageFromBody(certificate)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling Certificate [%v]", err)
				return nil, nil, AlertInternalError
			}

			toSend = append(toSend, SendHandshakeMessage{certm})
			state.handshakeHash.Write(certm.Marshal())

			hcv := state.handshakeHash.Sum(nil)
			logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hcv), hcv)

			certificateVerify := &CertificateVerifyBody{Algorithm: certScheme}
			logf(logTypeHandshake, "Creating CertVerify: %04x %v", certScheme, state.cryptoParams.hash)

			err = certificateVerify.Sign(cert.PrivateKey, hcv)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error signing CertificateVerify [%v]", err)
				return nil, nil, AlertInternalError
			}
			certvm, err := HandshakeMessageFromBody(certificateVerify)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling CertificateVerify [%v]", err)
				return nil, nil, AlertInternalError
			}

			toSend = append(toSend, SendHandshakeMessage{certvm})
			state.handshakeHash.Write(certvm.Marshal())
		}
	}

	// Compute the client's Finished message
	h5 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash for client Finished: [%d] %x", len(h5), h5)

	clientFinishedData := computeFinishedData(state.cryptoParams, state.clientHandshakeTrafficSecret, h5)
	logf(logTypeCrypto, "client Finished data: [%d] %x", len(clientFinishedData), clientFinishedData)

	fin = &FinishedBody{
		VerifyDataLen: len(clientFinishedData),
		VerifyData:    clientFinishedData,
	}
	finm, err := HandshakeMessageFromBody(fin)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling client Finished [%v]", err)
		return nil, nil, AlertInternalError
	}

	// Compute the resumption secret
	state.handshakeHash.Write(finm.Marshal())
	h6 := state.handshakeHash.Sum(nil)

	resumptionSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelResumptionSecret, h6)
	logf(logTypeCrypto, "resumption secret: [%d] %x", len(resumptionSecret), resumptionSecret)

	toSend = append(toSend, []HandshakeAction{
		SendHandshakeMessage{finm},
		RekeyIn{Label: "application", KeySet: serverTrafficKeys},
		RekeyOut{Label: "application", KeySet: clientTrafficKeys},
	}...)

	logf(logTypeHandshake, "[ClientStateWaitFinished] -> [StateConnected]")
	nextState := StateConnected{
		Params:              state.Params,
		isClient:            true,
		cryptoParams:        state.cryptoParams,
		resumptionSecret:    resumptionSecret,
		clientTrafficSecret: clientTrafficSecret,
		serverTrafficSecret: serverTrafficSecret,
	}
	return nextState, toSend, AlertNoAlert
}
