package RR

import (
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Class"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Type"
	"math"
	"net"
	"testing"
)

func TestRRBasicFunctions(t *testing.T) {
	record := RR{}

	testName := "example.com."
	record.SetName(testName)
	if record.GetName() != testName {
		t.Fatalf("Name getter/setter failed. Got %s, expected %s", record.GetName(), testName)
	}

	record.SetType(DNS_Type.A)
	if record.Type != DNS_Type.A {
		t.Fatalf("Type setter failed. Got %d, expected %d", record.Type, DNS_Type.A)
	}

	record.SetClass(DNS_Class.IN)
	if record.Class != DNS_Class.IN {
		t.Fatalf("Class setter failed. Got %d, expected %d", record.Class, DNS_Class.IN)
	}

	// Test TTL
	testTTL := 3600
	err := record.SetTTL(testTTL)
	if err != nil {
		t.Fatalf("TTL setter failed with error: %v", err)
	}
	if record.GetTTL() != uint32(testTTL) {
		t.Fatalf("TTL getter/setter failed. Got %d, expected %d", record.GetTTL(), testTTL)
	}

	err = record.SetTTL(math.MaxInt64)
	if err == nil {
		t.Fatal("TTL setter should have failed with overflow error")
	}
}

func TestARRecord(t *testing.T) {
	record := RR{}
	testName := "example.com."
	record.SetName(testName)

	testIP := net.ParseIP("192.168.1.1")
	record.SetRDATAToARecord(testIP)

	if record.Type != DNS_Type.A {
		t.Fatalf("A record type was not set correctly. Got %d, expected %d", record.Type, DNS_Type.A)
	}

	if record.RDLENGTH != 4 {
		t.Fatalf("A record RDLENGTH is incorrect. Got %d, expected 4", record.RDLENGTH)
	}

	ip, err := record.GetRDATAAsARecord()
	if err != nil {
		t.Fatalf("Failed to get A record: %v", err)
	}

	if !ip.Equal(testIP) {
		t.Fatalf("A record IP mismatch. Got %s, expected %s", ip.String(), testIP.String())
	}

	record.SetType(DNS_Type.MX)
	_, err = record.GetRDATAAsARecord()
	if err == nil {
		t.Fatalf("GetRDATAAsARecord should fail with incorrect type")
	}
}

func TestMXRecord(t *testing.T) {
	record := RR{}
	testName := "example.com."
	record.SetName(testName)

	var testPreference uint16 = 10
	testExchange := "mail.example.com"

	err := record.SetRDATAToMXRecord(testPreference, testExchange)
	if err != nil {
		t.Fatalf("Failed to set MX record: %v", err)
	}

	if record.Type != DNS_Type.MX {
		t.Fatalf("MX record type was not set correctly. Got %d, expected %d", record.Type, DNS_Type.MX)
	}

	preference, exchange, err := record.GetRDATAAsMXRecord()
	if err != nil {
		t.Fatalf("Failed to get MX record: %v", err)
	}

	if preference != testPreference {
		t.Fatalf("MX preference mismatch. Got %d, expected %d", preference, testPreference)
	}

	if exchange != testExchange {
		t.Fatalf("MX exchange mismatch. Got %s, expected %s", exchange, testExchange)
	}

	record.SetType(DNS_Type.A)
	_, _, err = record.GetRDATAAsMXRecord()
	if err == nil {
		t.Fatalf("GetRDATAAsMXRecord should fail with incorrect type")
	}

	longDomain := "verylongsubdomain.verylongsubdomain.verylongsubdomain.example.com"
	err = record.SetRDATAToMXRecord(testPreference, longDomain)
	if err != nil {
		t.Fatalf("Failed to set MX record with long domain: %v", err)
	}
	_, gotDomain, err := record.GetRDATAAsMXRecord()
	if err != nil {
		t.Fatalf("Failed to get MX record: %v", err)
	}
	if gotDomain != longDomain {
		t.Fatalf("MX record domain mismatch. Got %s, expected %s", gotDomain, longDomain)
	}
}

func TestCNAMERecord(t *testing.T) {
	record := RR{}
	testName := "alias.example.com"

	record.SetName(testName)

	testCanonicaName := "target.example.com"

	err := record.SetRDATAToCNAMERecord(testCanonicaName)
	if err != nil {
		t.Fatalf("Failed to set CNAME record: %v", err)
	}

	if record.Type != DNS_Type.CNAME {
		t.Fatalf("CNAME record type was not set correctly. Got %d, expected %d", record.Type, DNS_Type.CNAME)
	}

	cname, err := record.GetRDATAAsCNAMERecord()
	if err != nil {
		t.Fatalf("Failed to get CNAME record: %v", err)
	}

	if cname != testCanonicaName {
		t.Fatalf("CNAME mismatch. Got %s, expected %s", cname, testCanonicaName)
	}

	record.SetType(DNS_Type.A)
	_, err = record.GetRDATAAsCNAMERecord()
	if err == nil {
		t.Fatalf("GetRDATAAsCNAMERecord should fail with incorrect type")
	}
}

func TestNSRecord(t *testing.T) {
	record := RR{}
	testName := "example.com."
	record.SetName(testName)

	testNameServer := "ns1.example.com"

	err := record.SetRDATAToNSRecord(testNameServer)
	if err != nil {
		t.Fatalf("Failed to set NS record: %v", err)
	}

	if record.Type != DNS_Type.NS {
		t.Fatalf("NS record type was not set correctly. Got %d, expected %d", record.Type, DNS_Type.NS)
	}

	// Get and verify the NS record
	ns, err := record.GetRDATAAsNSRecord()
	if err != nil {
		t.Fatalf("Failed to get NS record: %v", err)
	}

	if ns != testNameServer {
		t.Fatalf("NS mismatch. Got %s, expected %s", ns, testNameServer)
	}

	record.SetType(DNS_Type.A)
	_, err = record.GetRDATAAsNSRecord()
	if err == nil {
		t.Fatalf("GetRDATAAsNSRecord should fail with incorrect type")
	}
}

func TestTXTRecord(t *testing.T) {
	record := RR{}
	testName := "example.com."
	record.SetName(testName)

	shortText := "This is a test TXT record"
	record.SetRDATAToTXTRecord(shortText)

	if record.Type != DNS_Type.TXT {
		t.Fatalf("TXT record type was not set correctly. Got %d, expected %d", record.Type, DNS_Type.TXT)
	}

	txt, err := record.GetRDATAAsTXTRecord()
	if err != nil {
		t.Fatalf("Failed to get TXT record: %v", err)
	}

	if txt != shortText {
		t.Fatalf("TXT mismatch. Got %s, expected %s", txt, shortText)
	}

	// Test with long text (>255 bytes) to test chunking
	longText := string(make([]byte, 300))
	for i := range longText {
		longText = longText[:i] + "a" + longText[i+1:]
	}

	record.SetRDATAToTXTRecord(longText)

	txt, err = record.GetRDATAAsTXTRecord()
	if err != nil {
		t.Fatalf("Failed to get long TXT record: %v", err)
	}

	if txt != longText {
		t.Fatalf("Long TXT mismatch. Got text of length %d, expected %d", len(txt), len(longText))
	}

	record.SetType(DNS_Type.A)
	_, err = record.GetRDATAAsTXTRecord()
	if err == nil {
		t.Fatal("GetRDATAAsTXTRecord should fail with incorrect type")
	}
}

func TestPTRRecord(t *testing.T) {
	record := RR{}
	testName := "1.1.168.192.in-addr.arpa."
	record.SetName(testName)

	testPtrDomain := "host.example.com"

	err := record.SetRDATAToPTRRecord(testPtrDomain)
	if err != nil {
		t.Fatalf("Failed to set PTR record: %v", err)
	}

	if record.Type != DNS_Type.PTR {
		t.Fatalf("PTR record type was not set correctly. Got %d, expected %d", record.Type, DNS_Type.PTR)
	}

	ptr, err := record.GetRDATAAsPTRRecord()
	if err != nil {
		t.Fatalf("Failed to get PTR record: %v", err)
	}

	if ptr != testPtrDomain {
		t.Fatalf("PTR mismatch. Got %s, expected %s", ptr, testPtrDomain)
	}

	record.SetType(DNS_Type.A)
	_, err = record.GetRDATAAsPTRRecord()
	if err == nil {
		t.Fatalf("GetRDATAAsPTRRecord should fail with incorrect type")
	}
}

func TestSOARecord(t *testing.T) {
	record := RR{}
	testName := "example.com."
	record.SetName(testName)

	testMName := "ns1.example.com"
	testRName := "admin.example.com"
	var testSerial uint32 = 2023121501
	var testRefresh uint32 = 7200
	var testRetry uint32 = 3600
	var testExpire uint32 = 1209600
	var testMinimum uint32 = 86400

	err := record.SetRDATAToSOARecord(
		testMName,
		testRName,
		testSerial,
		testRefresh,
		testRetry,
		testExpire,
		testMinimum,
	)
	if err != nil {
		t.Fatalf("Failed to set SOA record: %v", err)
	}

	if record.Type != DNS_Type.SOA {
		t.Fatalf("SOA record type was not set correctly. Got %d, expected %d", record.Type, DNS_Type.SOA)
	}

	mname, rname, serial, refresh, retry, expire, minimum, err := record.GetRDATAAsSOARecord()
	if err != nil {
		t.Fatalf("Failed to get SOA record: %v", err)
	}

	if mname != testMName {
		t.Fatalf("SOA MNAME mismatch. Got %s, expected %s", mname, testMName)
	}

	if rname != testRName {
		t.Fatalf("SOA RNAME mismatch. Got %s, expected %s", rname, testRName)
	}

	if serial != testSerial {
		t.Fatalf("SOA SERIAL mismatch. Got %d, expected %d", serial, testSerial)
	}

	if refresh != testRefresh {
		t.Fatalf("SOA REFRESH mismatch. Got %d, expected %d", refresh, testRefresh)
	}

	if retry != testRetry {
		t.Fatalf("SOA RETRY mismatch. Got %d, expected %d", retry, testRetry)
	}

	if expire != testExpire {
		t.Fatalf("SOA EXPIRE mismatch. Got %d, expected %d", expire, testExpire)
	}

	if minimum != testMinimum {
		t.Fatalf("SOA MINIMUM mismatch. Got %d, expected %d", minimum, testMinimum)
	}

	record.SetType(DNS_Type.A)
	_, _, _, _, _, _, _, err = record.GetRDATAAsSOARecord()
	if err == nil {
		t.Fatal("GetRDATAAsSOARecord should fail with incorrect type")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	original := RR{}
	original.SetName("example.com")
	original.SetClass(DNS_Class.IN)
	err := original.SetTTL(3600)
	if err != nil {
		t.Fatalf("Failed to set TTL: %v", err)
	}

	ip := net.ParseIP("192.168.1.1")
	original.SetRDATAToARecord(ip)

	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal record: %v", err)
	}

	parsed, bytesRead, err := Unmarshal(data, data)
	if err != nil {
		t.Fatalf("Failed to unmarshal record: %v", err)
	}

	if bytesRead != len(data) {
		t.Fatalf("Not all bytes were read during unmarshal. Read %d, expected %d", bytesRead, len(data))
	}

	if parsed.GetName() != original.GetName() {
		t.Fatalf("Name mismatch after marshal/unmarshal. Got %s, expected %s", parsed.GetName(), original.GetName())
	}

	if parsed.Type != original.Type {
		t.Fatalf("Type mismatch after marshal/unmarshal. Got %d, expected %d", parsed.Type, original.Type)
	}

	if parsed.Class != original.Class {
		t.Fatalf("Class mismatch after marshal/unmarshal. Got %d, expected %d", parsed.Class, original.Class)
	}

	if parsed.GetTTL() != original.GetTTL() {
		t.Fatalf("TTL mismatch after marshal/unmarshal. Got %d, expected %d", parsed.GetTTL(), original.GetTTL())
	}

	if parsed.RDLENGTH != original.RDLENGTH {
		t.Fatalf("RDLENGTH mismatch after marshal/unmarshal. Got %d, expected %d", parsed.RDLENGTH, original.RDLENGTH)
	}

	parsedIP, err := parsed.GetRDATAAsARecord()
	if err != nil {
		t.Fatalf("Failed to get A record from parsed record: %v", err)
	}

	if !parsedIP.Equal(ip) {
		t.Fatalf("IP mismatch after marshal/unmarshal. Got %s, expected %s", parsedIP.String(), ip.String())
	}
}

func TestCopyRR(t *testing.T) {
	original := RR{}
	original.SetName("example.com")
	original.SetClass(DNS_Class.IN)
	err := original.SetTTL(3600)
	if err != nil {
		t.Fatalf("Failed to set TTL: %v", err)
	}

	ip := net.ParseIP("192.168.1.1")
	original.SetRDATAToARecord(ip)

	copyRR, err := CopyRR(original)
	if err != nil {
		t.Fatalf("Failed to copy A record: %v", err)
	}

	if copyRR.GetName() != original.GetName() {
		t.Fatalf("Name mismatch after copy. Got %s, expected %s", copyRR.GetName(), original.GetName())
	}

	if copyRR.Type != original.Type {
		t.Fatalf("Type mismatch after copy. Got %d, expected %d", copyRR.Type, original.Type)
	}

	if copyRR.Class != original.Class {
		t.Fatalf("Class mismatch after copy. Got %d, expected %d", copyRR.Class, original.Class)
	}

	if copyRR.GetTTL() != original.GetTTL() {
		t.Fatalf("TTL mismatch after copy. Got %d, expected %d", copyRR.GetTTL(), original.GetTTL())
	}

	err = copyRR.SetTTL(7200)
	if err != nil {
		t.Fatalf("Failed to set TTL on copy: %v", err)
	}

	if copyRR.GetTTL() == original.GetTTL() {
		t.Fatal("Modifying TTL of copy affected the original")
	}

	soaOriginal := RR{}
	soaOriginal.SetName("example.com")
	soaOriginal.SetClass(DNS_Class.IN)
	err = soaOriginal.SetTTL(3600)
	if err != nil {
		t.Fatalf("Failed to set TTL: %v", err)
	}

	err = soaOriginal.SetRDATAToSOARecord(
		"ns1.example.com",
		"admin.example.com",
		2023121501,
		7200,
		3600,
		1209600,
		86400,
	)
	if err != nil {
		t.Fatalf("Failed to set SOA record: %v", err)
	}

	soaCopy, err := CopyRR(soaOriginal)
	if err != nil {
		t.Fatalf("Failed to copy SOA record: %v", err)
	}

	if soaCopy.Type != DNS_Type.SOA {
		t.Fatalf("SOA Type mismatch after copy. Got %d, expected %d", soaCopy.Type, DNS_Type.SOA)
	}

	mname1, rname1, serial1, refresh1, retry1, expire1, minimum1, err := soaOriginal.GetRDATAAsSOARecord()
	if err != nil {
		t.Fatalf("Failed to get original SOA data: %v", err)
	}

	mname2, rname2, serial2, refresh2, retry2, expire2, minimum2, err := soaCopy.GetRDATAAsSOARecord()
	if err != nil {
		t.Fatalf("Failed to get copy SOA data: %v", err)
	}

	if mname1 != mname2 || rname1 != rname2 || serial1 != serial2 ||
		refresh1 != refresh2 || retry1 != retry2 || expire1 != expire2 || minimum1 != minimum2 {
		t.Fatal("SOA data mismatch after copy")
	}
}

func TestErrorHandlingUnmarshal(t *testing.T) {
	_, _, err := Unmarshal([]byte{}, []byte{})
	if err == nil {
		t.Fatal("Unmarshal should fail with empty data")
	}

	record := RR{}
	record.SetName("example.com")
	record.SetClass(DNS_Class.IN)
	err = record.SetTTL(3600)
	if err != nil {
		t.Fatalf("Failed to set TTL: %v", err)
	}

	ip := net.ParseIP("192.168.1.1")
	record.SetRDATAToARecord(ip)

	data, err := record.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal record: %v", err)
	}

	// Test truncated data at various points
	testPoints := []int{5, 10, 15, len(data) - 2}
	for _, point := range testPoints {
		if point >= len(data) {
			continue
		}

		truncated := data[:point]
		_, _, err := Unmarshal(truncated, truncated)
		if err == nil {
			t.Fatalf("Unmarshal should fail with truncated data of length %d", point)
		}
	}
}

func TestErrorHandlingRDATA(t *testing.T) {
	record := RR{}
	record.SetName("example.com")
	record.SetType(DNS_Type.A)
	record.SetClass(DNS_Class.IN)
	err := record.SetTTL(3600)
	if err != nil {
		t.Fatalf("Failed to set TTL: %v", err)
	}

	// Intentionally create invalid RDATA/RDLENGTH combination
	record.RDATA = []byte{192, 168, 1, 1}
	record.RDLENGTH = 5 // Incorrect length

	_, err = record.GetRDATAAsARecord()
	if err == nil {
		t.Fatal("GetRDATAAsARecord should fail with mismatched RDLENGTH")
	}
}

func TestSpecialCases(t *testing.T) {
	record := RR{}
	record.SetName("example.com")
	record.SetClass(DNS_Class.IN)
	err := record.SetTTL(3600)
	if err != nil {
		t.Fatalf("Failed to set TTL: %v", err)
	}

	err = record.SetRDATAToSOARecord(
		"ns1.example.com",
		"admin.example.com",
		2023121501,
		7200,
		3600,
		1209600,
		86400,
	)
	if err != nil {
		t.Fatalf("Failed to set SOA record: %v", err)
	}

	data, err := record.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal record: %v", err)
	}

	parsed, _, err := Unmarshal(data, data)
	if err != nil {
		t.Fatalf("Failed to unmarshal record: %v", err)
	}

	mname, rname, _, _, _, _, _, err := parsed.GetRDATAAsSOARecord()
	if err != nil {
		t.Fatalf("Failed to get SOA record from parsed record: %v", err)
	}

	if mname != "ns1.example.com" {
		t.Fatalf("SOA MNAME mismatch after marshal/unmarshal. Got %s, expected %s",
			mname, "ns1.example.com.")
	}

	if rname != "admin.example.com" {
		t.Fatalf("SOA RNAME mismatch after marshal/unmarshal. Got %s, expected %s",
			rname, "admin.example.com.")
	}
}
