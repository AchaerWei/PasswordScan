package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// POP3 USER/PASS authentication (RFC 1939).

func runPOP3(args []string) Result {
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
		return Result{Success: false, Protocol: "pop3", Error: "missing --host or --user"}
	}

	if strings.ContainsAny(user, "\r\n") || strings.ContainsAny(pass, "\r\n") {
		return Result{Success: false, Protocol: "pop3", Error: "invalid characters in credentials"}
	}

	addr := net.JoinHostPort(host, "110")
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return Result{Success: false, Protocol: "pop3",
			Error: fmt.Sprintf("connect: %v", err)}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	buf := make([]byte, 4096)

	// Read server greeting
	n, err := conn.Read(buf)
	if err != nil {
		return Result{Success: false, Protocol: "pop3",
			Error: fmt.Sprintf("read greeting: %v", err)}
	}
	if !strings.HasPrefix(string(buf[:n]), "+OK") {
		return Result{Success: false, Protocol: "pop3", Error: "not a POP3 server"}
	}

	// Send USER
	fmt.Fprintf(conn, "USER %s\r\n", user)
	n, err = conn.Read(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "+OK") {
		return Result{Success: false, Protocol: "pop3",
			Error: fmt.Sprintf("USER failed: %s", strings.TrimSpace(string(buf[:n])))}
	}

	// Send PASS
	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	n, err = conn.Read(buf)
	if err != nil {
		return Result{Success: false, Protocol: "pop3",
			Error: fmt.Sprintf("PASS recv: %v", err)}
	}
	response := string(buf[:n])
	if strings.HasPrefix(response, "+OK") {
		return Result{Success: true, Protocol: "pop3", Detail: "authentication successful"}
	}
	return Result{Success: false, Protocol: "pop3",
		Error: fmt.Sprintf("authentication failed: %s", strings.TrimSpace(response))}
}
