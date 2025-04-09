package header

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func TestHeaderInitialization(t *testing.T) {
	h := &Header{}

	if h.GetMessageID() != 0 {
		t.Fatalf("Expected default ID to be 0, got %d", h.GetMessageID())
	}

	if h.GetQDCOUNT() != 0 {
		t.Fatalf("Expected default QDCOUNT to be 0, got %d", h.GetQDCOUNT())
	}

	if h.GetANCOUNT() != 0 {
		t.Fatalf("Expected default ANCOUNT to be 0, got %d", h.GetANCOUNT())
	}

	if h.GetNSCOUNT() != 0 {
		t.Fatalf("Expected default NSCOUNT to be 0, got %d", h.GetNSCOUNT())
	}

	if h.GetARCOUNT() != 0 {
		t.Fatalf("Expected default ARCOUNT to be 0, got %d", h.GetARCOUNT())
	}
}

func TestRandomID(t *testing.T) {
	h := &Header{}

	err := h.SetRandomID()
	if err != nil {
		t.Fatalf("SetRandomID failed: %v", err)
	}

	if h.GetMessageID() == 0 {
		t.Fatal("Random ID is zero, which is highly improbable")
	}

	oldID := h.GetMessageID()
	err = h.SetRandomID()
	if err != nil {
		t.Fatalf("Second SetRandomID call failed: %v", err)
	}

	// This test has a 1/65536 chance of failing randomly
	// Improbable enough but it could fail with no actual error
	if h.GetMessageID() == oldID {
		t.Fatal("Two consecutive random IDs are identical, which is highly improbable")
	}
}

func TestQRFlag(t *testing.T) {
	h := &Header{}

	if !h.IsQuery() {
		t.Fatal("New header should be a query by default")
	}
	if h.IsResponse() {
		t.Fatal("New header should not be a response by default")
	}

	h.SetQRFlag(true)
	if !h.IsResponse() {
		t.Fatal("Header should be a response after setting QR flag to true")
	}
	if h.IsQuery() {
		t.Fatal("Header should not be a query after setting QR flag to true")
	}

	// Set back to query
	h.SetQRFlag(false)
	if !h.IsQuery() {
		t.Fatal("Header should be a query after setting QR flag back to false")
	}
	if h.IsResponse() {
		t.Fatal("Header should not be a response after setting QR flag back to false")
	}
}

func TestOpcode(t *testing.T) {
	h := &Header{}

	if h.GetOpcode() != Query {
		t.Fatalf("Default opcode should be Query(0), got %d", h.GetOpcode())
	}

	h.SetOpcode(IQuery)
	if h.GetOpcode() != IQuery {
		t.Fatalf("Opcode should be IQuery(1), got %d", h.GetOpcode())
	}

	h.SetOpcode(Status)
	if h.GetOpcode() != Status {
		t.Fatalf("Opcode should be Status(2), got %d", h.GetOpcode())
	}

	h.SetOpcode(IQuery)
	if h.GetOpcode() != IQuery {
		t.Fatalf("Opcode should be %d, got %d", IQuery, h.GetOpcode())
	}

	h.SetQRFlag(true)
	if h.GetOpcode() != IQuery {
		t.Fatalf("Opcode should still be %d after setting QR flag, got %d", IQuery, h.GetOpcode())
	}
}

func TestAuthoritativeAnswerFlag(t *testing.T) {
	h := &Header{}

	if h.IsAA() {
		t.Fatal("AA flag should be false by default")
	}

	h.SetAA(true)
	if !h.IsAA() {
		t.Fatal("AA flag should be true after setting")
	}

	h.SetAA(false)
	if h.IsAA() {
		t.Fatal("AA flag should be false after clearing")
	}

	h.SetQRFlag(true)
	h.SetOpcode(Status)
	h.SetAA(true)

	if !h.IsResponse() {
		t.Fatal("QR flag should still be set after AA modification")
	}
	if h.GetOpcode() != Status {
		t.Fatal("Opcode should still be Status after AA modification")
	}
	if !h.IsAA() {
		t.Fatal("AA flag should be true after setting AA modification")
	}
}

func TestTruncationFlag(t *testing.T) {
	h := &Header{}

	if h.IsTC() {
		t.Fatal("TC flag should be false by default")
	}

	h.SetTC(true)
	if !h.IsTC() {
		t.Fatal("TC flag should be true after setting")
	}

	h.SetTC(false)
	if h.IsTC() {
		t.Fatal("TC flag should be false after clearing")
	}
	h.SetQRFlag(true)
	h.SetOpcode(Status)
	h.SetAA(true)
	h.SetTC(true)

	if !h.IsResponse() {
		t.Fatal("QR flag should still be set after TC modification")
	}
	if h.GetOpcode() != Status {
		t.Fatal("Opcode should still be Status after TC modification")
	}
	if !h.IsAA() {
		t.Fatal("AA flag should still be set after TC modification")
	}
}

func TestRecursionDesiredFlag(t *testing.T) {
	h := &Header{}

	if h.IsRD() {
		t.Fatal("RD flag should be false by default")
	}

	h.SetRD(true)
	if !h.IsRD() {
		t.Fatal("RD flag should be true after setting")
	}
	h.SetRD(false)
	if h.IsRD() {
		t.Fatal("RD flag should be false after clearing")
	}

	h.SetQRFlag(true)
	h.SetOpcode(Status)
	h.SetAA(true)
	h.SetTC(true)
	h.SetRD(true)

	if !h.IsResponse() {
		t.Fatal("QR flag should still be set after RD modification")
	}
	if h.GetOpcode() != Status {
		t.Fatal("Opcode should still be Status after RD modification")
	}
	if !h.IsAA() {
		t.Fatal("AA flag should still be set after RD modification")
	}
	if !h.IsTC() {
		t.Fatal("TC flag should still be set after RD modification")
	}
}

func TestRecursionAvailableFlag(t *testing.T) {
	h := &Header{}

	if h.IsRA() {
		t.Fatal("RA flag should be false by default")
	}

	h.SetRA(true)
	if !h.IsRA() {
		t.Fatal("RA flag should be true after setting")
	}

	h.SetRA(false)
	if h.IsRA() {
		t.Fatal("RA flag should be false after clearing")
	}

	h.SetQRFlag(true)
	h.SetRA(true)

	if !h.IsResponse() {
		t.Fatal("QR flag should remain set when modifying RA")
	}
	if !h.IsRA() {
		t.Fatal("RA flag should remain set when modifying other flags")
	}
}

func TestZField(t *testing.T) {
	h := &Header{}

	if h.GetZ() != 0 {
		t.Fatalf("Z field should be 0 by default, got %d", h.GetZ())
	}

	testValues := []int{1, 3, 7}
	for _, val := range testValues {
		err := h.SetZ(val)
		if err != nil {
			t.Fatalf("SetZ failed for value %d: %v", val, err)
		}
		if h.GetZ() != uint8(val) {
			t.Fatalf("Z field should be %d after setting, got %d", val, h.GetZ())
		}
	}

	// Test overflow handling
	overflowValues := []int{8, 15, 16, 256, math.MaxInt32}
	for _, val := range overflowValues {
		err := h.SetZ(val)
		if err != nil && val <= 7 {
			t.Fatalf("SetZ should not return error for value %d: %v", val, err)
		}

		if h.GetZ() > 7 {
			t.Fatalf("Z field should be limited to 3 bits, got %d", h.GetZ())
		}
	}

	h.SetRA(true)
	err := h.SetZ(3)
	if err != nil {
		t.Fatalf("SetZ failed for value 3: %v", h.GetZ())
	}
	h.SetRCODE(ServerFailure)

	if !h.IsRA() {
		t.Fatal("RA flag should still be set after Z modification")
	}
	if h.GetZ() != 3 {
		t.Fatalf("Z field should still be 3, got %d", h.GetZ())
	}
	if h.GetRCODE() != ServerFailure {
		t.Fatalf("RCODE should still be ServerFailure, got %s", h.GetRCODE())
	}
}

func TestResponseCode(t *testing.T) {
	h := &Header{}

	if h.GetRCODE() != NoError {
		t.Fatalf("Default RCODE should be NoError, got %s", h.GetRCODE())
	}

	testCodes := []ResponseCode{NoError, FormatError, ServerFailure, NameError, NotImplemented, Refused}
	for _, code := range testCodes {
		h.SetRCODE(code)
		if h.GetRCODE() != code {
			t.Fatalf("RCODE should be %s after setting, got %s", code, h.GetRCODE())
		}
	}

	for code := ResponseCode(6); code <= 15; code++ {
		h.SetRCODE(code)
		if h.GetRCODE() != code {
			t.Fatalf("RCODE should be %d after setting, got %d", code, h.GetRCODE())
		}
	}

	h.SetRCODE(NoError)
	if h.GetRCODE().String() != "NoError" {
		t.Fatalf("RCODE.String() should be 'NoError', got '%s'", h.GetRCODE().String())
	}

	h.SetRCODE(Refused)
	if h.GetRCODE().String() != "Refused" {
		t.Fatalf("RCODE.String() should be 'Refused', got '%s'", h.GetRCODE().String())
	}

	h.SetRCODE(6)
	if h.GetRCODE().String() != "ReservedForFutureUse" {
		t.Fatalf("RCODE.String() for reserved value should be 'ReservedForFutureUse', got '%s'", h.GetRCODE().String())
	}
}

func TestCountFields(t *testing.T) {
	h := &Header{}

	testCounts := []int{0, 1, 5, 100, 65535}
	for _, count := range testCounts {
		err := h.SetQDCOUNT(count)
		if err != nil {
			t.Fatalf("SetQDCOUNT failed for value %d: %v", count, err)
		}
		if h.GetQDCOUNT() != uint16(count) {
			t.Fatalf("QDCOUNT should be %d after setting, got %d", count, h.GetQDCOUNT())
		}
	}

	for _, count := range testCounts {
		err := h.SetANCOUNT(count)
		if err != nil {
			t.Fatalf("SetANCOUNT failed for value %d: %v", count, err)
		}
		if h.GetANCOUNT() != uint16(count) {
			t.Fatalf("ANCOUNT should be %d after setting, got %d", count, h.GetANCOUNT())
		}
	}

	for _, count := range testCounts {
		err := h.SetNSCOUNT(count)
		if err != nil {
			t.Fatalf("SetNSCOUNT failed for value %d: %v", count, err)
		}
		if h.GetNSCOUNT() != uint16(count) {
			t.Fatalf("NSCOUNT should be %d after setting, got %d", count, h.GetNSCOUNT())
		}
	}

	for _, count := range testCounts {
		err := h.SetARCOUNT(count)
		if err != nil {
			t.Fatalf("SetARCOUNT failed for value %d: %v", count, err)
		}
		if h.GetARCOUNT() != uint16(count) {
			t.Fatalf("ARCOUNT should be %d after setting, got %d", count, h.GetARCOUNT())
		}
	}

	overflowValues := []int{65536, math.MaxInt32}
	for _, val := range overflowValues {
		if err := h.SetQDCOUNT(val); err == nil {
			t.Fatalf("SetQDCOUNT should return error for overflow value %d", val)
		}
		if err := h.SetANCOUNT(val); err == nil {
			t.Fatalf("SetANCOUNT should return error for overflow value %d", val)
		}
		if err := h.SetNSCOUNT(val); err == nil {
			t.Fatalf("SetNSCOUNT should return error for overflow value %d", val)
		}
		if err := h.SetARCOUNT(val); err == nil {
			t.Fatalf("SetARCOUNT should return error for overflow value %d", val)
		}
	}
}

func TestMarshalBinary(t *testing.T) {
	h := &Header{}

	err := h.SetRandomID()
	if err != nil {
		t.Fatalf("SetRandomID failed for empty header: %v", err)
	}
	h.SetQRFlag(true)
	h.SetOpcode(Query)
	h.SetAA(true)
	h.SetTC(false)
	h.SetRD(true)
	h.SetRA(true)
	err = h.SetZ(2)
	if err != nil {
		t.Fatalf("SetZ failed for empty header: %v", err)
	}
	h.SetRCODE(NoError)
	err = h.SetQDCOUNT(1)
	if err != nil {
		t.Fatalf("SetQDCOUNT failed for empty header: %v", err)
	}
	err = h.SetANCOUNT(2)
	if err != nil {
		t.Fatalf("SetANCOUNT failed for empty header: %v", err)
	}
	err = h.SetNSCOUNT(3)
	if err != nil {
		t.Fatalf("SetNSCOUNT failed for empty header: %v", err)
	}
	err = h.SetARCOUNT(4)
	if err != nil {
		t.Fatalf("SetARCOUNT failed for empty header: %v", err)
	}

	data, err := h.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 12 {
		t.Fatalf("Marshaled data should be 12 bytes, got %d", len(data))
	}

	if binary.BigEndian.Uint16(data[0:2]) != h.GetMessageID() {
		t.Fatal("Marshaled ID doesn't match original")
	}

	if !bytes.Equal(data[2:4], h.Flags[:]) {
		t.Fatal("Marshaled flags don't match original")
	}

	if binary.BigEndian.Uint16(data[4:6]) != h.GetQDCOUNT() {
		t.Fatal("Marshaled QDCOUNT doesn't match original")
	}
	if binary.BigEndian.Uint16(data[6:8]) != h.GetANCOUNT() {
		t.Fatal("Marshaled ANCOUNT doesn't match original")
	}
	if binary.BigEndian.Uint16(data[8:10]) != h.GetNSCOUNT() {
		t.Fatal("Marshaled NSCOUNT doesn't match original")
	}
	if binary.BigEndian.Uint16(data[10:12]) != h.GetARCOUNT() {
		t.Fatal("Marshaled ARCOUNT doesn't match original")
	}
}

func TestUnmarshal(t *testing.T) {
	original := &Header{}
	original.ID[0] = 0x12
	original.ID[1] = 0x34
	original.Flags[0] = 0x85 // QR=1, Opcode=0, AA=1, TC=0, RD=1
	original.Flags[1] = 0x80 // RA=1, Z=0, RCODE=0

	err := original.SetQDCOUNT(1)
	if err != nil {
		t.Fatalf("SetQDCOUNT failed: %v", err)
	}
	err = original.SetANCOUNT(2)
	if err != nil {
		t.Fatalf("SetANCOUNT failed: %v", err)
	}
	err = original.SetNSCOUNT(3)
	if err != nil {
		t.Fatalf("SetNSCOUNT failed: %v", err)
	}
	err = original.SetARCOUNT(4)
	if err != nil {
		t.Fatalf("SetARCOUNT failed: %v", err)
	}

	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	unmarshaled, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if unmarshaled.GetMessageID() != binary.BigEndian.Uint16(original.ID[:]) {
		t.Fatal("Unmarshaled ID doesn't match original")
	}

	if unmarshaled.IsQuery() != original.IsQuery() {
		t.Fatal("Unmarshaled QR flag doesn't match original")
	}

	if unmarshaled.GetOpcode() != original.GetOpcode() {
		t.Fatal("Unmarshaled Opcode doesn't match original")
	}

	if unmarshaled.IsAA() != original.IsAA() {
		t.Fatal("Unmarshaled AA flag doesn't match original")
	}

	if unmarshaled.IsTC() != original.IsTC() {
		t.Fatal("Unmarshaled TC flag doesn't match original")
	}

	if unmarshaled.IsRD() != original.IsRD() {
		t.Fatal("Unmarshaled RD flag doesn't match original")
	}

	if unmarshaled.IsRA() != original.IsRA() {
		t.Fatal("Unmarshaled RA flag doesn't match original")
	}

	if unmarshaled.GetZ() != original.GetZ() {
		t.Fatal("Unmarshaled Z field doesn't match original")
	}

	if unmarshaled.GetRCODE() != original.GetRCODE() {
		t.Fatal("Unmarshaled RCODE doesn't match original")
	}

	if unmarshaled.GetQDCOUNT() != original.GetQDCOUNT() {
		t.Fatal("Unmarshaled QDCOUNT doesn't match original")
	}

	if unmarshaled.GetANCOUNT() != original.GetANCOUNT() {
		t.Fatal("Unmarshaled ANCOUNT doesn't match original")
	}

	if unmarshaled.GetNSCOUNT() != original.GetNSCOUNT() {
		t.Fatal("Unmarshaled NSCOUNT doesn't match original")
	}

	if unmarshaled.GetARCOUNT() != original.GetARCOUNT() {
		t.Fatal("Unmarshaled ARCOUNT doesn't match original")
	}

	_, err = Unmarshal(data[:11])
	if err == nil {
		t.Fatal("Unmarshal should fail with data shorter than 12 bytes")
	}
}

func TestCompleteHeaderWorkflow(t *testing.T) {
	h := &Header{}

	err := h.SetRandomID()
	if err != nil {
		t.Fatalf("SetRandomID failed: %v", err)
	}
	h.SetQRFlag(false) // It's a query
	h.SetOpcode(Query)
	h.SetAA(false) // Not authoritative
	h.SetTC(false) // Not truncated
	h.SetRD(true)  // Recursion desired
	h.SetRA(false) // Server sets recursion available
	err = h.SetZ(0)
	if err != nil {
		t.Fatalf("SetZ failed: %v", err)
	}
	h.SetRCODE(NoError)
	err = h.SetQDCOUNT(1)
	if err != nil {
		t.Fatalf("SetQDCOUNT failed: %v", err)
	}
	err = h.SetANCOUNT(0)
	if err != nil {
		t.Fatalf("SetANCOUNT failed: %v", err)
	}
	err = h.SetNSCOUNT(0)
	if err != nil {
		t.Fatalf("SetNSCOUNT failed: %v", err)
	}
	err = h.SetARCOUNT(0)
	if err != nil {
		t.Fatalf("SetARCOUNT failed: %v", err)
	}

	queryData, err := h.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	responseHeader, err := Unmarshal(queryData)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	responseHeader.SetQRFlag(true)
	responseHeader.SetRA(true)

	err = responseHeader.SetANCOUNT(1)
	if err != nil {
		t.Fatalf("SetANCOUNT failed: %v", err)
	}

	if responseHeader.GetMessageID() != h.GetMessageID() {
		t.Fatal("Response ID doesn't match query ID")
	}

	if !responseHeader.IsResponse() {
		t.Fatal("Header should be marked as a response")
	}
	responseData, err := responseHeader.MarshalBinary()
	if err != nil {
		t.Fatalf("Marshal of response failed: %v", err)
	}

	if !bytes.Equal(queryData[0:2], responseData[0:2]) {
		t.Fatal("Query and response IDs don't match in binary form")
	}

	if responseData[2]&0x80 == 0 {
		t.Fatal("QR bit not set in response data")
	}
}
