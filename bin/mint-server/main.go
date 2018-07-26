package main

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/bifurcation/mint"
	"log"
	"net"
	"strings"
)

var port string
var upsk string

// UPSKs are of the form: servername:identity:baseKey:hash
// where the identity and the baseKey are in hex
func importUpsk(upskInfo string) (*mint.PSKMapCache, error) {
	s := strings.Split(upskInfo, ":")
	if len(s) != 3 {
		return nil, fmt.Errorf("Invalid USPK string")
	}
	baseIdentity, err := hex.DecodeString(s[0])
	if err != nil {
		return nil, fmt.Errorf("Invalid USPK identity")
	}
	baseKey, err := hex.DecodeString(s[1])
	if err != nil {
		return nil, fmt.Errorf("Invalid USPK key")
	}
	var hash crypto.Hash
	switch s[2] {
	case "sha256":
		hash = crypto.SHA256
	case "sha384":
		hash = crypto.SHA384
	case "sha512":
		hash = crypto.SHA512
	default:
		return nil, fmt.Errorf("Invalid UPSK hash")
	}

	dpskIdentity, dpskKey, err := mint.DeriveFromUniversalPsk(baseIdentity, baseKey, hash, crypto.SHA256)
	dpsk := mint.PreSharedKey{
		CipherSuite:  mint.TLS_AES_128_GCM_SHA256,
		IsResumption: false,
		Identity:     dpskIdentity,
		Key:          dpskKey,
	}
	return &mint.PSKMapCache{
		hex.EncodeToString(dpskIdentity): dpsk,
	}, nil
}

func main() {
	var config mint.Config
	config.SendSessionTickets = true
	config.ServerName = "localhost"
	priv, cert, err := mint.MakeNewSelfSignedCert("localhost", mint.RSA_PKCS1_SHA256)
	config.Certificates = []*mint.Certificate{
		{
			Chain:      []*x509.Certificate{cert},
			PrivateKey: priv,
		},
	}
	config.Init(false)

	flag.StringVar(&port, "port", "4430", "port")
	flag.StringVar(&upsk, "upsk", "", "universal psk")
	flag.Parse()

	if upsk != "" {
		var err error
		config.PSKs, err = importUpsk(upsk)
		if err != nil {
			fmt.Println("err: ", err)
			return
		}
	}

	service := "0.0.0.0:" + port
	listener, err := mint.Listen("tcp", service, &config)

	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Print("server: listening")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 10)
	for {
		log.Print("server: conn: waiting")
		n, err := conn.Read(buf)
		if err != nil {
			if err != nil {
				log.Printf("server: conn: read: %s", err)
			}
			break
		}

		n, err = conn.Write([]byte("hello world"))
		log.Printf("server: conn: wrote %d bytes", n)

		if err != nil {
			log.Printf("server: write: %s", err)
			break
		}
		break
	}
	log.Println("server: conn: closed")
}
