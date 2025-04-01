package main

import (
	"fmt"
	"github.com/codecrafters-io/dns-server-starter-go/internal/header"
	"net"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")
	//
	//Uncomment this block to pass the first stage

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
		hed := header.Header{
			ID: [2]byte{4, 210},
		}
		hed.SetQRFlag(true)
		marshalledHeader, err := hed.Marshal()
		if err != nil {
			fmt.Println("Error marshalling header:", err)
		}

		_, err = udpConn.WriteToUDP(marshalledHeader, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
