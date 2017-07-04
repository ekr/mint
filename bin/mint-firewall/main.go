package main

// Adapted from: https://gist.github.com/vmihailenco/1380352

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
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
			if err != nil {
				panic(err)
			}

      // Here we need to read frame, if CHello, modify the key share before sending.
      
			rConn.Write(data[:n])
			log.Printf("received from client and sent to server:\n%v", hex.Dump(data[:n]))
		}
	}()

	// Response loop
	for {
		data := make([]byte, 1024*1024)
		n, err := rConn.Read(data)
		if err != nil {
			panic(err)
		}
		conn.Write(data[:n])
		log.Printf("received from server and sent to client:\n%v", hex.Dump(data[:n]))
	}

}
