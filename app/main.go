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
	fmt.Println("Logs from your program will appear here!")

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

		fmt.Printf("Received %d bytes from %s\n", size, source)

		h, err := header.Unmarshal(buf[:12])
		if err != nil {
			fmt.Println("Failed to unmarshal header:", err)
			continue
		}
		fmt.Printf("Header: %+v\n", h)

		questions := make([]question.Question, 0, h.GetQDCOUNT())
		offset := 12

		for i := 0; i < int(h.GetQDCOUNT()); i++ {
			q, bytesRead, err := question.Unmarshal(buf[offset:])
			if err != nil {
				fmt.Println("Failed to unmarshal question:", err)
				continue
			}
			questions = append(questions, q)
			offset += bytesRead
			fmt.Printf("Question %d: %+v\n", i+1, q)
		}

		responseHeader := header.Header{
			ID: h.ID,
		}
		responseHeader.SetQRFlag(true)
		responseHeader.SetOpcode(h.GetOpcode())
		responseHeader.SetAA(false)
		responseHeader.SetTC(false)
		responseHeader.SetRD(h.IsRD())
		responseHeader.SetRA(false)
		responseHeader.SetZ(0)

		if h.GetOpcode() == header.Query {
			responseHeader.SetRCODE(header.NoError)
		} else {
			responseHeader.SetRCODE(header.NotImplemented)
		}

		responseHeader.SetQDCOUNT(uint16(len(questions)))
		responseHeader.SetANCOUNT(uint16(len(questions)))
		responseHeader.SetNSCOUNT(0)
		responseHeader.SetARCOUNT(0)

		marshalledHeader, err := responseHeader.Marshal()
		if err != nil {
			fmt.Println("Error marshalling header:", err)
			continue
		}

		response := marshalledHeader

		for _, q := range questions {
			marshalledQuestion, err := q.Marshal()
			if err != nil {
				fmt.Println("Error marshalling question:", err)
				continue
			}
			response = append(response, marshalledQuestion...)
		}

		for _, q := range questions {
			a := answer.Answer{}
			a.SetName(q.Name)
			a.SetType(DNS_Type.A)
			a.SetClass(DNS_Class.IN)
			a.SetTTL(60)

			a.SetRDATAToARecord(net.IP{8, 8, 8, 8})

			marshalledAnswer, err := a.Marshal()
			if err != nil {
				fmt.Println("Error marshalling answer:", err)
				continue
			}
			response = append(response, marshalledAnswer...)
		}

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
