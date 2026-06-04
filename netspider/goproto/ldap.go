package main

import (
	"fmt"
	"net"
	"time"
)

// LDAP simple bind authentication.
// Connects to LDAP server, attempts simple bind with given DN and password.

func runLDAP(args []string) Result {
	host := ""
	user := ""
	pass := ""
	timeout := 5

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--host":
			if i+1 < len(args) {
				host = args[i+1]
				i++
			}
		case "--user":
			if i+1 < len(args) {
				user = args[i+1]
				i++
			}
		case "--pass":
			if i+1 < len(args) {
				pass = args[i+1]
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
		return Result{Success: false, Protocol: "ldap", Error: "missing --host"}
	}
	if user == "" {
		return Result{Success: false, Protocol: "ldap", Error: "missing --user"}
	}

	addr := net.JoinHostPort(host, "389")
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return Result{Success: false, Protocol: "ldap",
			Error: fmt.Sprintf("connect: %v", err)}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	// Build LDAP simple bind request
	bindReq := buildLDAPSimpleBind(user, pass)

	_, err = conn.Write(bindReq)
	if err != nil {
		return Result{Success: false, Protocol: "ldap",
			Error: fmt.Sprintf("send: %v", err)}
	}

	// Read LDAP response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return Result{Success: false, Protocol: "ldap",
			Error: fmt.Sprintf("recv: %v", err)}
	}

	return parseLDAPBindResponse(buf[:n])
}

// LDAP message structure (simplified BER):
// LDAPMessage ::= SEQUENCE {
//     messageID   INTEGER,
//     protocolOp  CHOICE { bindRequest [0] ... }
// }
//
// BindRequest ::= [APPLICATION 0] SEQUENCE {
//     version     INTEGER (3),
//     name        OCTET STRING (DN),
//     authentication CHOICE { simple [0] OCTET STRING }
// }

func buildLDAPSimpleBind(dn, password string) []byte {
	// Simple auth: [0] OCTET STRING (password)
	simpleAuth := []byte{0x80}
	simpleAuth = append(simpleAuth, berEncodeLength(len(password))...)
	simpleAuth = append(simpleAuth, []byte(password)...)

	// DN: OCTET STRING
	dnBytes := berOctetString(dn)

	// Version: INTEGER 3
	version := berInteger(3)

	// BindRequest SEQUENCE
	bindReqSeq := berSequence(append(append(version, dnBytes...), simpleAuth...))

	// [APPLICATION 0] = 0x60
	bindReq := []byte{0x60}
	bindReq = append(bindReq, berEncodeLength(len(bindReqSeq))...)
	bindReq = append(bindReq, bindReqSeq...)

	// MessageID = 1
	msgID := berInteger(1)

	// Full LDAPMessage
	msg := berSequence(append(msgID, bindReq...))

	// LDAP messages are wrapped in a length-prefixed envelope (not BER SEQUENCE)
	// Actually, LDAP uses BER directly over TCP - no extra framing
	return msg
}

func parseLDAPBindResponse(data []byte) Result {
	if len(data) < 2 || data[0] != 0x30 {
		return Result{Success: false, Protocol: "ldap",
			Error: "not a valid LDAP response"}
	}

	// Parse LDAPMessage: SEQUENCE { messageID, protocolOp }
	_, _, contents := berDecode(data)
	if contents == nil {
		return Result{Success: false, Protocol: "ldap",
			Error: "failed to decode LDAP response"}
	}

	// Skip messageID
	rest := skipBERTLV(contents)
	if rest == nil {
		return Result{Success: false, Protocol: "ldap",
			Error: "malformed message ID"}
	}

	// protocolOp: should be [APPLICATION 1] = 0x61 = BindResponse
	if len(rest) < 2 {
		return Result{Success: false, Protocol: "ldap",
			Error: "response too short"}
	}

	tag := rest[0]
	if tag != 0x61 {
		return Result{Success: false, Protocol: "ldap",
			Error: fmt.Sprintf("unexpected op tag: 0x%02x (expected 0x61)", tag)}
	}

	// Parse BindResponse SEQUENCE: { resultCode, matchedDN, errorMessage }
	_, _, bindRespContents := berDecode(rest)
	if bindRespContents == nil {
		return Result{Success: false, Protocol: "ldap",
			Error: "failed to decode BindResponse"}
	}

	// resultCode is first element (INTEGER)
	tag2, _, val := berDecode(bindRespContents)
	if tag2 != 0x02 {
		return Result{Success: false, Protocol: "ldap",
			Error: "expected resultCode INTEGER"}
	}

	resultCode := berIntValue(val)
	switch resultCode {
	case 0:
		return Result{Success: true, Protocol: "ldap",
			Detail: "bind successful (resultCode=0)"}
	case 49:
		return Result{Success: false, Protocol: "ldap",
			Error: "invalid credentials (resultCode=49)"}
	default:
		return Result{Success: false, Protocol: "ldap",
			Error: fmt.Sprintf("bind failed: resultCode=%d", resultCode)}
	}
}
