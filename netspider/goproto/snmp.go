package main

import (
	"fmt"
	"net"
	"time"
)

// SNMP v2c community string verification.
// Sends a GetRequest for sysDescr (1.3.6.1.2.1.1.1.0) and checks response.

func runSNMP(args []string) Result {
	host := ""
	community := "public"
	timeout := 3

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--host":
			if i+1 < len(args) {
				host = args[i+1]
				i++
			}
		case "--community":
			if i+1 < len(args) {
				community = args[i+1]
				i++
			}
		case "--timeout":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &timeout)
				i++
			}
		}
	}

	if host == "" {
		return Result{Success: false, Protocol: "snmp", Error: "missing --host"}
	}

	addr := net.JoinHostPort(host, "161")
	conn, err := net.DialTimeout("udp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return Result{Success: false, Protocol: "snmp",
			Error: fmt.Sprintf("connect: %v", err)}
	}
	defer conn.Close()

	// Build SNMP v2c GetRequest for sysDescr (1.3.6.1.2.1.1.1.0)
	oid := []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	pkt := buildSNMPGetRequest(community, oid)

	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	_, err = conn.Write(pkt)
	if err != nil {
		return Result{Success: false, Protocol: "snmp",
			Error: fmt.Sprintf("send: %v", err)}
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return Result{Success: false, Protocol: "snmp",
			Error: fmt.Sprintf("timeout or no response (community may be wrong): %v", err)}
	}

	resp := buf[:n]
	valid, detail := parseSNMPResponse(resp)
	return Result{Success: valid, Protocol: "snmp", Detail: detail}
}

// ---- BER encoding helpers ----

func berEncodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	// Long form
	var buf []byte
	for length > 0 {
		buf = append([]byte{byte(length & 0xFF)}, buf...)
		length >>= 8
	}
	return append([]byte{byte(0x80 | len(buf))}, buf...)
}

func berInteger(val int) []byte {
	// Encode integer in minimal bytes (big-endian, two's complement)
	if val == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	var buf []byte
	v := val
	for v != 0 && v != -1 {
		buf = append([]byte{byte(v & 0xFF)}, buf...)
		v >>= 8
	}
	// Ensure positive numbers have 0 high bit
	if buf[0]&0x80 != 0 {
		buf = append([]byte{0x00}, buf...)
	}
	return append(append([]byte{0x02}, berEncodeLength(len(buf))...), buf...)
}

func berOctetString(s string) []byte {
	data := []byte(s)
	result := []byte{0x04}
	result = append(result, berEncodeLength(len(data))...)
	result = append(result, data...)
	return result
}

func berNull() []byte {
	return []byte{0x05, 0x00}
}

func berOID(oid []int) []byte {
	if len(oid) < 2 {
		return nil
	}
	// First two components encoded as 40*a + b
	data := []byte{byte(40*oid[0] + oid[1])}
	for _, comp := range oid[2:] {
		// Base-128 encoding
		var enc []byte
		c := comp
		if c == 0 {
			enc = []byte{0}
		} else {
			for c > 0 {
				enc = append([]byte{byte(c & 0x7F)}, enc...)
				c >>= 7
			}
		}
		// Set high bit on all but last byte
		for i := 0; i < len(enc)-1; i++ {
			enc[i] |= 0x80
		}
		data = append(data, enc...)
	}
	result := []byte{0x06}
	result = append(result, berEncodeLength(len(data))...)
	result = append(result, data...)
	return result
}

func berSequence(contents []byte) []byte {
	result := []byte{0x30}
	result = append(result, berEncodeLength(len(contents))...)
	result = append(result, contents...)
	return result
}

func berGetRequest(contents []byte) []byte {
	result := []byte{0xA0}
	result = append(result, berEncodeLength(len(contents))...)
	result = append(result, contents...)
	return result
}

// ---- SNMP packet builder ----

func buildSNMPGetRequest(community string, oid []int) []byte {
	// Variable binding: SEQUENCE { OID, NULL }
	varbind := berSequence(append(berOID(oid), berNull()...))
	// Variable bindings: SEQUENCE OF varbind
	varbinds := berSequence(varbind)

	// GetRequest-PDU: request-id, error-status(0), error-index(0), varbinds
	pdu := append(berInteger(1), berInteger(0)...)  // request-id=1, error=0
	pdu = append(pdu, berInteger(0)...)               // error-index=0
	pdu = append(pdu, varbinds...)
	getReq := berGetRequest(pdu)

	// SNMP message: SEQUENCE { version, community, pdu }
	msg := append(berInteger(1), berOctetString(community)...) // version=1 (v2c)
	msg = append(msg, getReq...)
	return berSequence(msg)
}

// ---- SNMP response parser ----

func parseSNMPResponse(data []byte) (bool, string) {
	// Minimal SNMP response parser.
	// Expected: SEQUENCE { version, community, GetResponse-PDU }
	if len(data) < 2 || data[0] != 0x30 {
		return false, "not a valid SNMP response (no SEQUENCE)"
	}

	// Check for error-status in the PDU (non-zero = error)
	// Walk the BER structure looking for error-status (2nd INTEGER in PDU)
	// The GetResponse-PDU is at context-specific [2] (0xA2)

	_, _, contents := berDecode(data)
	if contents == nil {
		return false, "failed to decode SNMP response"
	}

	// contents = version + community + pdu
	// Skip version (INTEGER)
	rest := skipBERTLV(contents)
	if rest == nil {
		return false, "malformed version"
	}
	// Skip community (OCTET STRING)
	rest = skipBERTLV(rest)
	if rest == nil {
		return false, "malformed community"
	}

	// Now at PDU (0xA2 = GetResponse)
	if len(rest) < 2 || rest[0] != 0xA2 {
		return false, fmt.Sprintf("unexpected PDU type: 0x%02x", rest[0])
	}
	_, _, pduContents := berDecode(rest)
	if pduContents == nil {
		return false, "failed to decode PDU"
	}

	// Skip request-id (INTEGER)
	pduRest := skipBERTLV(pduContents)
	if pduRest == nil {
		return false, "malformed request-id"
	}

	// Parse error-status
	tag, _, val := berDecode(pduRest)
	if tag != 0x02 {
		return false, "expected error-status INTEGER"
	}
	errStatus := berIntValue(val)
	if errStatus != 0 {
		errMsgs := map[int]string{
			1: "tooBig", 2: "noSuchName", 3: "badValue",
			4: "readOnly", 5: "genErr", 6: "noAccess",
			7: "wrongType", 8: "wrongLength", 9: "wrongEncoding",
			10: "wrongValue", 11: "noCreation", 12: "inconsistentValue",
			13: "resourceUnavailable", 14: "commitFailed", 15: "undoFailed",
			16: "authorizationError", 17: "notWritable", 18: "inconsistentName",
		}
		msg := errMsgs[errStatus]
		if msg == "" {
			msg = fmt.Sprintf("error-%d", errStatus)
		}
		return false, fmt.Sprintf("SNMP error: %s", msg)
	}

	return true, "community string valid, sysDescr accessible"
}

// ---- Minimal BER decoder (for response parsing) ----

func berDecode(data []byte) (tag byte, length int, value []byte) {
	if len(data) < 2 {
		return 0, 0, nil
	}
	tag = data[0]
	pos := 1
	if pos >= len(data) {
		return 0, 0, nil
	}
	if data[pos]&0x80 == 0 {
		length = int(data[pos])
		pos++
	} else {
		numLen := int(data[pos] & 0x7F)
		pos++
		if pos+numLen > len(data) {
			return 0, 0, nil
		}
		length = 0
		for i := 0; i < numLen; i++ {
			length = (length << 8) | int(data[pos+i])
		}
		pos += numLen
	}
	if pos+length > len(data) {
		return 0, 0, nil
	}
	value = data[pos : pos+length]
	return tag, length, data[pos : pos+length]
}

func berIntValue(data []byte) int {
	val := 0
	for _, b := range data {
		val = (val << 8) | int(b)
	}
	return val
}

func skipBERTLV(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}
	_, length, _ := berDecode(data)
	if length < 0 {
		return nil
	}
	pos := 1
	if data[pos]&0x80 == 0 {
		pos++
	} else {
		numLen := int(data[pos] & 0x7F)
		pos += 1 + numLen
	}
	if pos+length > len(data) {
		return nil
	}
	return data[pos+length:]
}
