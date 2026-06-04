package main

import (
	"crypto/des"
	"fmt"
	"net"
	"time"
)

// VNC authentication (RFB protocol DES challenge-response).
// VNC auth is password-only (no username).

func runVNC(args []string) Result {
	host := ""
	pass := ""
	timeout := 5

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--host":
			if i+1 < len(args) { host = args[i+1]; i++ }
		case "--pass":
			if i+1 < len(args) { pass = args[i+1]; i++ }
		case "--timeout":
			if i+1 < len(args) { fmt.Sscanf(args[i+1], "%d", &timeout); i++ }
		}
	}

	if host == "" || pass == "" {
		return Result{Success: false, Protocol: "vnc", Error: "missing --host or --pass"}
	}

	addr := net.JoinHostPort(host, "5900")
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return Result{Success: false, Protocol: "vnc",
			Error: fmt.Sprintf("connect: %v", err)}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	// Read server protocol version
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return Result{Success: false, Protocol: "vnc",
			Error: "not a VNC server (no RFB handshake)"}
	}

	version := string(buf[:n])
	if !(len(version) > 3 && version[:3] == "RFB") {
		return Result{Success: false, Protocol: "vnc",
			Error: fmt.Sprintf("not RFB: %s", version)}
	}

	// Send our version (3.8)
	conn.Write([]byte("RFB 003.008\n"))

	// Read security types offered
	n, err = conn.Read(buf)
	if err != nil || n < 2 {
		return Result{Success: false, Protocol: "vnc",
			Error: "failed to read security types"}
	}

	numTypes := int(buf[0])
	if numTypes == 0 {
		return Result{Success: false, Protocol: "vnc",
			Error: fmt.Sprintf("server rejected: %s", string(buf[1:n]))}
	}

	hasVNC := false
	for i := 1; i <= numTypes && i < n; i++ {
		if buf[i] == 2 { // VNC authentication
			hasVNC = true
			break
		}
	}
	if !hasVNC {
		return Result{Success: false, Protocol: "vnc",
			Detail: "VNC auth not offered (may use None or other)"}
	}

	// Select VNC auth (type 2)
	conn.Write([]byte{2})

	// Read challenge (16 bytes)
	challenge := make([]byte, 16)
	n, err = conn.Read(challenge)
	if err != nil || n != 16 {
		return Result{Success: false, Protocol: "vnc",
			Error: "failed to read challenge"}
	}

	// DES encrypt challenge with password as key
	response := vncDESEncrypt(challenge, pass)
	conn.Write(response)

	// Read auth result (4 bytes)
	result := make([]byte, 4)
	n, err = conn.Read(result)
	if err != nil || n < 4 {
		return Result{Success: false, Protocol: "vnc",
			Error: "no auth result"}
	}

	if result[0] == 0 {
		return Result{Success: true, Protocol: "vnc", Detail: "authentication successful"}
	}
	return Result{Success: false, Protocol: "vnc",
		Error: fmt.Sprintf("auth failed (code=%d)", int(result[3]))}
}

// VNC DES encrypt per RFB 3.8 spec.
// Password truncated/padded to 8 bytes, each byte's bits reversed,
// then used as DES key to encrypt the 16-byte challenge.

func vncDESEncrypt(challenge []byte, password string) []byte {
	// Build DES key: password truncated to 8 bytes, each byte bit-reversed
	key := make([]byte, 8)
	pw := []byte(password)
	for i := 0; i < 8; i++ {
		if i < len(pw) {
			key[i] = reverseBits(pw[i])
		} else {
			key[i] = 0 // pad with nulls
		}
	}

	// Create DES cipher
	cipher, err := des.NewCipher(key)
	if err != nil {
		// Fallback: XOR (should not happen with valid 8-byte key)
		response := make([]byte, 16)
		for i := 0; i < 16; i++ {
			response[i] = challenge[i] ^ key[i%8]
		}
		return response
	}

	// Encrypt challenge in two 8-byte blocks (ECB mode)
	response := make([]byte, 16)
	cipher.Encrypt(response[0:8], challenge[0:8])
	cipher.Encrypt(response[8:16], challenge[8:16])
	return response
}

func reverseBits(b byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		result = (result << 1) | (b & 1)
		b >>= 1
	}
	return result
}
