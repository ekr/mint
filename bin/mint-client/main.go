package main

import (
	"crypto"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/bifurcation/mint"
	"strings"
)

var addr string
var dtls bool
var dontValidate bool
var upsk string

// UPSKs are of the form: servername:identity:baseKey:hash
// where the identity and the baseKey are in hex
func importUpsk(upskInfo string) (*mint.PSKMapCache, error) {
	s := strings.Split(upskInfo, ":")
	if len(s) != 4 {
		return nil, fmt.Errorf("Invalid USPK string")
	}
	serverName := s[0]
	baseIdentity, err := hex.DecodeString(s[1])
	if err != nil {
		return nil, fmt.Errorf("Invalid USPK identity")
	}
	baseKey, err := hex.DecodeString(s[2])
	if err != nil {
		return nil, fmt.Errorf("Invalid USPK key")
	}
	var hash crypto.Hash
	switch s[3] {
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
		serverName:                       dpsk,
		hex.EncodeToString(dpskIdentity): dpsk,
	}, nil
}

func main() {
	c := mint.Config{}

	flag.StringVar(&addr, "addr", "localhost:4430", "port")
	flag.BoolVar(&dtls, "dtls", false, "use DTLS")
	flag.BoolVar(&dontValidate, "dontvalidate", false, "don't validate certs")
	flag.StringVar(&upsk, "upsk", "", "Install UPSK")
	flag.Parse()
	if dontValidate {
		c.InsecureSkipVerify = true
	}
	if upsk != "" {
		var err error
		c.PSKs, err = importUpsk(upsk)
		if err != nil {
			fmt.Println("err: ", err)
			return
		}
	}
	network := "tcp"
	if dtls {
		network = "udp"
	}
	conn, err := mint.Dial(network, addr, &c)

	if err != nil {
		fmt.Println("TLS handshake failed:", err)
		return
	}

	request := "GET / HTTP/1.0\r\n\r\n"
	conn.Write([]byte(request))

	response := ""
	buffer := make([]byte, 1024)
	var read int
	for err == nil {
		read, err = conn.Read(buffer)
		fmt.Println(" ~~ read: ", read)
		response += string(buffer)
	}
	fmt.Println("err:", err)
	fmt.Println("Received from server:")
	fmt.Println(response)
}
