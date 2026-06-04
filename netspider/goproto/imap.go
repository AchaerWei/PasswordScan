package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// IMAP LOGIN authentication.
// RFC 3501: a001 LOGIN username password

func runIMAP(args []string) Result {
	host := ""
	user := ""
	pass := ""
	timeout := 5

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--host":
			if i+1 < len(args) { host = args[i+1]; i++ }
		case "--user":
			if i+1 < len(args) { user = args[i+1]; i++ }
		case "--pass":
			if i+1 < len(args) { pass = args[i+1]; i++ }
		case "--timeout":
			if i+1 < len(args) { fmt.Sscanf(args[i+1], "%d", &timeout); i++ }
		}
	}

	if host == "" || user == "" {
		return Result{Success: false, Protocol: "imap", Error: "missing --host or --user"}
	}

	// Sanitize inputs — CRLF injection prevention
	if strings.ContainsAny(user, "\r\n") || strings.ContainsAny(pass, "\r\n") {
		return Result{Success: false, Protocol: "imap", Error: "invalid characters in credentials"}
	}

	addr := net.JoinHostPort(host, "143")
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return Result{Success: false, Protocol: "imap",
			Error: fmt.Sprintf("connect: %v", err)}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	// Read server greeting
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return Result{Success: false, Protocol: "imap",
			Error: fmt.Sprintf("read greeting: %v", err)}
	}
	greeting := string(buf[:n])
	if !strings.HasPrefix(greeting, "* OK") {
		return Result{Success: false, Protocol: "imap",
			Error: fmt.Sprintf("not an IMAP server: %s", strings.TrimSpace(greeting))}
	}

	// Send LOGIN command
	cmd := fmt.Sprintf("a001 LOGIN %s %s\r\n", user, pass)
	_, err = conn.Write([]byte(cmd))
	if err != nil {
		return Result{Success: false, Protocol: "imap",
			Error: fmt.Sprintf("send: %v", err)}
	}

	n, err = conn.Read(buf)
	if err != nil {
		return Result{Success: false, Protocol: "imap",
			Error: fmt.Sprintf("recv: %v", err)}
	}

	response := string(buf[:n])
	if strings.HasPrefix(response, "a001 OK") {
		return Result{Success: true, Protocol: "imap", Detail: "LOGIN successful"}
	}
	if strings.Contains(response, "a001 NO") || strings.Contains(response, "a001 BAD") {
		return Result{Success: false, Protocol: "imap",
			Error: fmt.Sprintf("LOGIN failed: %s", strings.TrimSpace(response))}
	}
	return Result{Success: false, Protocol: "imap",
		Error: fmt.Sprintf("unexpected response: %s", strings.TrimSpace(response))}
}
