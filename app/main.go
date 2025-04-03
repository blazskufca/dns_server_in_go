package main

import (
	"fmt"
	"github.com/codecrafters-io/dns-server-starter-go/internal/DNS_Class"
	"github.com/codecrafters-io/dns-server-starter-go/internal/DNS_Type"
	"github.com/codecrafters-io/dns-server-starter-go/internal/answer"
	"github.com/codecrafters-io/dns-server-starter-go/internal/header"
	"github.com/codecrafters-io/dns-server-starter-go/internal/question"
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

		h, err := header.Unmarshal([]byte(receivedData[:12]))
		if err != nil {
			fmt.Println("Failed to unmarshal header:", err)
		}
		fmt.Printf("Header: %+v\n", h)

		qq, readB, err := question.Unmarshal([]byte(receivedData[12:]))
		if err != nil {
			fmt.Println("Failed to unmarshal question:", err)
		}
		fmt.Printf("Question: %+v\n", qq)

		aa, _, err := answer.Unmarshal([]byte(receivedData[readB:]))
		if err != nil {
			fmt.Println("Failed to unmarshal answer:", err)
		}
		fmt.Printf("Answer: %+v\n", aa)

		// Create an empty response
		hed := header.Header{
			ID: h.ID,
		}
		hed.SetQRFlag(true)
		hed.SetOpcode(h.GetOpcode())
		hed.SetAA(false)
		hed.SetTC(false)
		hed.SetRD(h.IsRD())
		hed.SetRA(false)
		hed.SetZ(0)
		if h.GetOpcode() == header.Query {
			hed.SetRCODE(header.NoError)
		} else {
			hed.SetRCODE(header.NotImplemented)
		}
		hed.SetQDCOUNT(h.GetQDCOUNT())
		hed.SetANCOUNT(1)
		hed.SetNSCOUNT(h.GetNSCOUNT())
		hed.SetARCOUNT(h.GetARCOUNT())

		marshalledHeader, err := hed.Marshal()
		if err != nil {
			fmt.Println("Error marshalling header:", err)
		}

		q := question.Question{
			Name:  "codecrafters.io",
			Type:  DNS_Type.A,   // A record (1)
			Class: DNS_Class.IN, // IN class (1)
		}

		marshalledQuestion, err := q.Marshal()
		if err != nil {
			fmt.Println("Error marshalling question:", err)
			continue
		}
		response := append(marshalledHeader, marshalledQuestion...)
		a := answer.Answer{}
		a.SetName("codecrafters.io")
		a.SetType(DNS_Type.A)
		a.SetClass(DNS_Class.IN)
		a.SetTTL(60)
		a.SetRDATAToARecord(net.IP{8, 8, 8, 8})

		marshalledAnswer, err := a.Marshal()
		if err != nil {
			fmt.Println("Error marshalling answer:", err)
		}
		response = append(response, marshalledAnswer...)

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
