package main

import (
	"flag"
	"fmt"

	"github.com/bifurcation/mint"
)

var addr string

func main() {
	flag.StringVar(&addr, "addr", "localhost:4431", "port")
	flag.Parse()

	conn, err := mint.Dial("tcp", addr, nil)

	if err != nil {
		fmt.Println("TLS handshake failed:", err)
		return
	}

	fmt.Println("TLS handshake succeeded")
	request := "GET / HTTP/1.0\r\n\r\n"
	//request := ""
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
	fmt.Println("Received from firewall:")
	fmt.Println(response)
}
