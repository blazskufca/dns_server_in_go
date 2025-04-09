package Message

import (
	"bytes"
	"fmt"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Class"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Type"
	"github.com/blazskufca/dns_server_in_go/internal/RR"
	"github.com/blazskufca/dns_server_in_go/internal/header"
	"github.com/blazskufca/dns_server_in_go/internal/question"
	"net"
	"testing"
)

func TestCreateDNSQuery(t *testing.T) {
	tests := []struct {
		name            string
		domainName      string
		qtype           DNS_Type.Type
		qclass          DNS_Class.Class
		desireRecursion bool
	}{
		{
			name:            "Standard A query",
			domainName:      "example.com",
			qtype:           DNS_Type.A,
			qclass:          DNS_Class.IN,
			desireRecursion: true,
		},
		{
			name:            "AAAA query without recursion",
			domainName:      "ipv6.example.org",
			qtype:           DNS_Type.AAAA,
			qclass:          DNS_Class.IN,
			desireRecursion: false,
		},
		{
			name:            "TXT query",
			domainName:      "txt.example.net",
			qtype:           DNS_Type.TXT,
			qclass:          DNS_Class.IN,
			desireRecursion: true,
		},
		{
			name:            "Empty domain",
			domainName:      "",
			qtype:           DNS_Type.A,
			qclass:          DNS_Class.IN,
			desireRecursion: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := CreateDNSQuery(tc.domainName, tc.qtype, tc.qclass, tc.desireRecursion)
			if err != nil {
				t.Fatalf("CreateDNSQuery returned error: %v", err)
			}

			if msg.Header.IsResponse() != false {
				t.Errorf("Expected QR flag to be false, got true")
			}
			if msg.Header.IsRD() != tc.desireRecursion {
				t.Errorf("Expected RD flag to be %v, got %v", tc.desireRecursion, msg.Header.IsRD())
			}

			if msg.Header.GetQDCOUNT() != 1 {
				t.Errorf("Expected QDCOUNT to be 1, got %d", msg.Header.GetQDCOUNT())
			}

			if len(msg.Questions) != 1 {
				t.Fatalf("Expected 1 question, got %d", len(msg.Questions))
			}
			q := msg.Questions[0]
			if q.Name != tc.domainName {
				t.Errorf("Expected question name %s, got %s", tc.domainName, q.Name)
			}
			if q.Type != tc.qtype {
				t.Errorf("Expected question type %d, got %d", tc.qtype, q.Type)
			}
			if q.Class != tc.qclass {
				t.Errorf("Expected question class %d, got %d", tc.qclass, q.Class)
			}
		})
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	msg := Message{}

	err := msg.Header.SetRandomID()
	if err != nil {
		t.Fatalf("Failed to set random ID: %v", err)
	}
	msg.Header.SetQRFlag(false)
	msg.Header.SetRD(true)

	q := question.Question{}
	q.SetName("example.com")
	q.SetType(DNS_Type.A)
	q.SetClass(DNS_Class.IN)
	err = msg.AddQuestion(q)
	if err != nil {
		t.Fatalf("Failed to add question: %v", err)
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal message: %v", err)
	}

	unmarshaledMsg, err := New(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal message: %v", err)
	}

	if unmarshaledMsg.Header.IsQuery() != msg.Header.IsQuery() {
		t.Errorf("QR flag mismatch")
	}
	if unmarshaledMsg.Header.IsRD() != msg.Header.IsRD() {
		t.Errorf("RD flag mismatch")
	}
	if unmarshaledMsg.Header.GetQDCOUNT() != msg.Header.GetQDCOUNT() {
		t.Errorf("QDCOUNT mismatch")
	}
	if len(unmarshaledMsg.Questions) != len(msg.Questions) {
		t.Errorf("Question count mismatch")
	}
	if msg.Header.GetMessageID() != unmarshaledMsg.Header.GetMessageID() {
		t.Errorf("Message ID mismatch")
	}
	for i := 0; i < len(msg.Questions); i++ {
		if unmarshaledMsg.Questions[i].Name != msg.Questions[i].Name {
			t.Errorf("Question name mismatch")
		}
		if unmarshaledMsg.Questions[i].Type != msg.Questions[i].Type {
			t.Errorf("Question type mismatch")
		}
		if unmarshaledMsg.Questions[i].Class != msg.Questions[i].Class {
			t.Errorf("Question class mismatch")
		}
	}
}

func TestCopy(t *testing.T) {
	original, err := CreateDNSQuery("example.com", DNS_Type.A, DNS_Class.IN, true)
	if err != nil {
		t.Fatalf("Failed to create original message: %v", err)
	}

	mockA := RR.RR{
		Name:  "example.com",
		TTL:   300,
		Type:  DNS_Type.A,
		Class: DNS_Class.IN,
	}
	mockA.SetRDATAToARecord(net.IP{127, 0, 0, 1})
	original.Answers = append(original.Answers, mockA)

	mockNS := RR.RR{
		Name:  "example.com",
		TTL:   3600,
		Type:  DNS_Type.NS,
		Class: DNS_Class.IN,
	}
	err = mockNS.SetRDATAToNSRecord("ns1.example.com")
	if err != nil {
		t.Fatalf("Failed to set NS record: %v", err)
	}

	original.Authority = append(original.Authority, mockNS)

	mockMX := RR.RR{
		Name:  "example.com",
		TTL:   3600,
		Type:  DNS_Type.MX,
		Class: DNS_Class.IN,
	}
	err = mockMX.SetRDATAToMXRecord(10, "mail.example.com")
	if err != nil {
		t.Fatalf("Failed to set MX record: %v", err)
	}
	original.Additional = append(original.Additional, mockMX)

	err = original.Header.SetANCOUNT(len(original.Answers))
	if err != nil {
		t.Fatalf("Failed to set ANCOUNT: %v", err)
	}
	err = original.Header.SetNSCOUNT(len(original.Authority))
	if err != nil {
		t.Fatalf("Failed to set ANCOUNT: %v", err)
	}
	err = original.Header.SetARCOUNT(len(original.Additional))
	if err != nil {
		t.Fatalf("Failed to set ANCOUNT: %v", err)
	}

	copyMsg, err := Copy(&original)
	if err != nil {
		t.Fatalf("Failed to copy message: %v", err)
	}

	if copyMsg.Header.GetMessageID() != original.Header.GetMessageID() {
		t.Errorf("Header ID mismatch")
	}

	if copyMsg.Header.GetQDCOUNT() != original.Header.GetQDCOUNT() {
		t.Errorf("QDCOUNT mismatch")
	}
	if copyMsg.Header.GetANCOUNT() != original.Header.GetANCOUNT() {
		t.Errorf("ANCOUNT mismatch")
	}
	if copyMsg.Header.GetNSCOUNT() != original.Header.GetNSCOUNT() {
		t.Errorf("NSCOUNT mismatch")
	}
	if copyMsg.Header.GetARCOUNT() != original.Header.GetARCOUNT() {
		t.Errorf("ARCOUNT mismatch")
	}

	_, err = Copy(nil)
	if err == nil {
		t.Errorf("Expected error when copying nil message, got nil")
	}
}

func TestUnmarshalMalformedMessages(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		expectErr bool
	}{
		{
			name:      "Empty buffer",
			data:      []byte{},
			expectErr: true,
		},
		{
			name:      "Too short header",
			data:      []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A},
			expectErr: true,
		},
		{
			name: "Header with invalid QDCOUNT",
			data: []byte{
				0x00, 0x01, // ID
				0x00, 0x00, // Flags
				0xFF, 0xFF, // QDCOUNT (65535 questions - unreasonably high)
				0x00, 0x00, // ANCOUNT
				0x00, 0x00, // NSCOUNT
				0x00, 0x00, // ARCOUNT
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.data)
			if (err != nil) != tc.expectErr {
				t.Errorf("Expected error: %v, got: %v", tc.expectErr, err)
			}
		})
	}
}

func TestMessageWithManyRecords(t *testing.T) {
	msg := Message{}
	err := msg.Header.SetRandomID()
	if err != nil {
		t.Fatalf("Failed to set random ID: %v", err)
	}

	for i := 0; i < 10; i++ {
		q := question.Question{}
		q.SetName(fmt.Sprintf("test-%d.example.com", i))
		q.SetType(DNS_Type.A)
		q.SetClass(DNS_Class.IN)
		err = msg.AddQuestion(q)
		if err != nil {
			t.Fatalf("Failed to add question: %v", err)
		}
	}

	for i := 0; i < 15; i++ {
		rr := RR.RR{
			Name:  fmt.Sprintf("test-%d.example.com", i),
			Type:  DNS_Type.A,
			Class: DNS_Class.IN,
		}
		err = rr.SetTTL(3600)
		if err != nil {
			t.Fatalf("Failed to set TTL: %v", err)
		}
		rr.SetRDATAToARecord(net.IP{192, 168, 0, byte(i)})
		msg.Answers = append(msg.Answers, rr)
	}

	err = msg.Header.SetANCOUNT(len(msg.Answers))
	if err != nil {
		t.Fatalf("Failed to set ANCOUNT: %v", err)
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal message: %v", err)
	}

	unmarshaledMsg, err := New(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal message: %v", err)
	}

	if len(unmarshaledMsg.Questions) != 10 {
		t.Errorf("Expected 10 questions, got %d", len(unmarshaledMsg.Questions))
	}
	if len(unmarshaledMsg.Answers) != 15 {
		t.Errorf("Expected 15 answers, got %d", len(unmarshaledMsg.Answers))
	}
}

func TestRoundtripMessageWithCompression(t *testing.T) {
	msg := Message{}
	err := msg.Header.SetRandomID()
	if err != nil {
		t.Fatalf("Failed to set random ID: %v", err)
	}

	q := question.Question{}
	q.SetName("example.com")
	q.SetType(DNS_Type.A)
	q.SetClass(DNS_Class.IN)
	err = msg.AddQuestion(q)
	if err != nil {
		t.Fatalf("Failed to add question: %v", err)
	}

	aRecord := RR.RR{}
	aRecord.SetName("example.com")
	aRecord.SetType(DNS_Type.A)
	aRecord.SetClass(DNS_Class.IN)
	err = aRecord.SetTTL(3600)
	if err != nil {
		t.Fatalf("Failed to set TTL: %v", err)
	}
	aRecord.SetRDATAToARecord(net.IP{192, 168, 0, 1})
	msg.Answers = append(msg.Answers, aRecord)

	nsRecord := RR.RR{}
	nsRecord.SetName("example.com")
	err = nsRecord.SetTTL(3600)
	if err != nil {
		t.Fatalf("Failed to set TTL: %v", err)
	}
	err = nsRecord.SetRDATAToNSRecord("ns.example.com")
	if err != nil {
		t.Fatalf("Failed to set RDATA To NS Record: %v", err)
	}
	msg.Authority = append(msg.Authority, nsRecord)

	err = msg.Header.SetANCOUNT(len(msg.Answers))
	if err != nil {
		t.Fatalf("Failed to set ANCOUNT: %v", err)
	}
	err = msg.Header.SetNSCOUNT(len(msg.Authority))
	if err != nil {
		t.Fatalf("Failed to set NSCOUNT: %v", err)
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal message: %v", err)
	}

	unmarshaledMsg, err := New(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal message: %v", err)
	}

	if unmarshaledMsg.Header.GetQDCOUNT() != 1 {
		t.Fatalf("Expected QDCOUNT: 1, got %d", unmarshaledMsg.Header.GetQDCOUNT())
	}

	if unmarshaledMsg.Header.GetANCOUNT() != 1 {
		t.Fatalf("Expected ANCOUNT: 1, got %d", unmarshaledMsg.Header.GetANCOUNT())
	}
	for i := 0; i < int(unmarshaledMsg.Header.GetANCOUNT()); i++ {
		if msg.Answers[i].Name != unmarshaledMsg.Answers[i].Name {
			t.Fatalf("expected %s got %s", msg.Answers[i].Name, unmarshaledMsg.Answers[i].Name)
		}
	}
	if unmarshaledMsg.Header.GetNSCOUNT() != 1 {
		t.Fatalf("Expected ANCOUNT: 1, got %d", unmarshaledMsg.Header.GetANCOUNT())
	}
	for i := 0; i < int(unmarshaledMsg.Header.GetNSCOUNT()); i++ {
		if msg.Authority[i].Name != unmarshaledMsg.Authority[i].Name {
			t.Fatalf("expected %s got %s", msg.Authority[i].Name, unmarshaledMsg.Authority[i].Name)
		}
	}
}

func TestAddQuestion(t *testing.T) {
	msg := Message{}
	err := msg.Header.SetRandomID()
	if err != nil {
		t.Fatalf("Failed to set random ID: %v", err)
	}

	if msg.Header.GetQDCOUNT() != 0 {
		t.Errorf("Initial QDCOUNT should be 0, got %d", msg.Header.GetQDCOUNT())
	}

	q1 := question.Question{}
	q1.SetName("example.com")
	q1.SetType(DNS_Type.A)
	q1.SetClass(DNS_Class.IN)
	err = msg.AddQuestion(q1)
	if err != nil {
		t.Fatalf("Failed to add first question: %v", err)
	}

	if msg.Header.GetQDCOUNT() != 1 {
		t.Errorf("After adding 1 question, QDCOUNT should be 1, got %d", msg.Header.GetQDCOUNT())
	}

	q2 := question.Question{}
	q2.SetName("example.org")
	q2.SetType(DNS_Type.AAAA)
	q2.SetClass(DNS_Class.IN)
	err = msg.AddQuestion(q2)
	if err != nil {
		t.Fatalf("Failed to add second question: %v", err)
	}

	if msg.Header.GetQDCOUNT() != 2 {
		t.Errorf("After adding 2 questions, QDCOUNT should be 2, got %d", msg.Header.GetQDCOUNT())
	}

	if len(msg.Questions) != 2 {
		t.Fatalf("Expected 2 questions, got %d", len(msg.Questions))
	}
	if msg.Questions[0].Name != "example.com" {
		t.Errorf("First question name doesn't match")
	}
	if msg.Questions[1].Name != "example.org" {
		t.Errorf("Second question name doesn't match")
	}
}

func TestUnmarshalWithCorruptPointers(t *testing.T) {
	header := []byte{
		0x00, 0x01, // ID
		0x00, 0x00, // Flags
		0x00, 0x01, // QDCOUNT (1 question)
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}

	corruptQuestion := []byte{
		0xC0, 0xFF, // This is a compression pointer to offset 255, which might be invalid
		0x00, 0x01, // TYPE = A
		0x00, 0x01, // CLASS = IN
	}

	corruptMessage := append(header, corruptQuestion...)

	_, err := New(corruptMessage)

	if err == nil {
		t.Fatal("Corrupt message should have failed")
	}
}

func TestMarshalUnmarshalHeaderValues(t *testing.T) {
	msg := Message{}
	h := header.Header{}
	err := h.SetRandomID()
	if err != nil {
		t.Fatalf("Failed to set random ID: %v", err)
	}
	h.SetQRFlag(true)
	h.SetOpcode(header.IQuery)
	h.SetAA(true)
	h.SetTC(true)
	h.SetRD(true)
	h.SetRA(true)
	err = h.SetZ(3)
	if err != nil {
		t.Fatalf("Failed to set z: %v", err)
	}
	h.SetRCODE(header.ServerFailure)
	msg.Header = h

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal message: %v", err)
	}

	unmarshaledMsg, err := New(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal message: %v", err)
	}
	if unmarshaledMsg.Header.GetMessageID() != msg.Header.GetMessageID() {
		t.Errorf("ID mismatch: expected 12345, got %d", unmarshaledMsg.Header.GetMessageID())
	}
	if unmarshaledMsg.Header.IsResponse() != msg.Header.IsResponse() {
		t.Errorf("QR flag mismatch")
	}
	if unmarshaledMsg.Header.GetOpcode() != header.IQuery {
		t.Errorf("Opcode mismatch: expected 2, got %d", unmarshaledMsg.Header.GetOpcode())
	}
	if !unmarshaledMsg.Header.IsAA() {
		t.Errorf("AA flag mismatch")
	}
	if !unmarshaledMsg.Header.IsTC() {
		t.Errorf("TC flag mismatch")
	}
	if !unmarshaledMsg.Header.IsRD() {
		t.Errorf("RD flag mismatch")
	}
	if !unmarshaledMsg.Header.IsRA() {
		t.Errorf("RA flag mismatch")
	}
	if unmarshaledMsg.Header.GetZ() != 3 {
		t.Errorf("Z bits mismatch: expected 3, got %d", unmarshaledMsg.Header.GetZ())
	}
	if unmarshaledMsg.Header.GetRCODE() != header.ServerFailure {
		t.Errorf("RCode mismatch: expected 3, got %d", unmarshaledMsg.Header.GetRCODE())
	}
}

func TestMessageEquality(t *testing.T) {
	msg1, err := CreateDNSQuery("example.com", DNS_Type.A, DNS_Class.IN, true)
	if err != nil {
		t.Fatalf("Failed to create first message: %v", err)
	}

	msg2, err := CreateDNSQuery("example.com", DNS_Type.A, DNS_Class.IN, true)
	if err != nil {
		t.Fatalf("Failed to create second message: %v", err)
	}

	msg1.Header.ID = msg2.Header.ID

	data1, err := msg1.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal first message: %v", err)
	}

	data2, err := msg2.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal second message: %v", err)
	}

	if !bytes.Equal(data1, data2) {
		t.Errorf("Binary representations of identical messages don't match")
	}
}
