package main

// Adapted from: https://gist.github.com/vmihailenco/1380352

import (
	"flag"
	"fmt"
	//"github.com/bifurcation/mint"
	"spearmint"
	"io"
	"net"
)

var localAddress *string = flag.String("l", "localhost:4431", "Local address")
var remoteAddress *string = flag.String("r", "localhost:4430", "Remote address")

func main() {
	flag.Parse()

	fmt.Printf("Listening: %v\nProxying %v\n", *localAddress, *remoteAddress)

	addr, err := net.ResolveTCPAddr("tcp", *localAddress)
	if err != nil {
		panic(err)
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			panic(err)
		}

		go proxyConnection(conn)
	}

}

func proxyConnection(conn *net.TCPConn) {
	proxy := mint.NewReverseFirewallProxy()

	rAddr, err := net.ResolveTCPAddr("tcp", *remoteAddress)
	if err != nil {
		panic(err)
	}

	rConn, err := net.DialTCP("tcp", nil, rAddr)
	if err != nil {
		panic(err)
	}

	defer rConn.Close()

	// Request loop
	go func() {
		for {
			data := make([]byte, 1024*1024)
			n, err := conn.Read(data)
			if err == io.EOF {
				return
			}
			if err != nil {
				panic(err)
			}

			// Here we need to read frame, if CHello, modify the key share before sending.
			out, err := proxy.ProcessMessage(mint.C2S, data[:n])
			if err != nil {
				panic(err)
			}
			rConn.Write(out)
		}
	}()

	// Response loop
	for {
		data := make([]byte, 1024*1024)
		n, err := rConn.Read(data)
		if err == io.EOF {
			return
		}
		if err != nil {
			panic(err)
		}

		out, err := proxy.ProcessMessage(mint.S2C, data[:n]) //The direction here used to be C2S.
		if err != nil {
			panic(err)
		}

		conn.Write(out)
	}

}
