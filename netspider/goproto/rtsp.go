package main

import (
	"crypto/md5"
	"fmt"
	"net"
	"strings"
	"time"
)

// RTSP DESCRIBE + Digest authentication (RFC 2326).

func runRTSP(args []string) Result {
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

	if host == "" {
		return Result{Success: false, Protocol: "rtsp", Error: "missing --host"}
	}

	addr := net.JoinHostPort(host, "554")
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return Result{Success: false, Protocol: "rtsp",
			Error: fmt.Sprintf("connect: %v", err)}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	// Send OPTIONS to probe
	req := fmt.Sprintf("OPTIONS rtsp://%s:554 RTSP/1.0\r\nCSeq: 1\r\n\r\n", host)
	_, err = conn.Write([]byte(req))
	if err != nil {
		return Result{Success: false, Protocol: "rtsp",
			Error: fmt.Sprintf("send OPTIONS: %v", err)}
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return Result{Success: false, Protocol: "rtsp",
			Error: "no response to OPTIONS"}
	}
	resp := string(buf[:n])

	if !strings.HasPrefix(resp, "RTSP/1.0") {
		return Result{Success: false, Protocol: "rtsp", Error: "not an RTSP server"}
	}

	// If no auth required, OPTIONS returns 200 OK
	if strings.Contains(resp, "200 OK") && user == "" {
		return Result{Success: true, Protocol: "rtsp", Detail: "no authentication required"}
	}

	// Send DESCRIBE without auth to get WWW-Authenticate
	req = fmt.Sprintf("DESCRIBE rtsp://%s:554 RTSP/1.0\r\nCSeq: 2\r\n\r\n", host)
	conn.Write([]byte(req))
	n, err = conn.Read(buf)
	if err != nil || n == 0 {
		return Result{Success: false, Protocol: "rtsp",
			Error: "no response to DESCRIBE"}
	}
	resp = string(buf[:n])

	if strings.Contains(resp, "200 OK") {
		return Result{Success: true, Protocol: "rtsp", Detail: "no authentication required"}
	}

	if !strings.Contains(resp, "401 Unauthorized") {
		return Result{Success: false, Protocol: "rtsp",
			Error: fmt.Sprintf("unexpected DESCRIBE response: %s",
				strings.Split(resp, "\r\n")[0])}
	}

	// Parse WWW-Authenticate header for Digest
	realm, nonce := parseDigest(resp)
	if realm == "" || nonce == "" || user == "" {
		return Result{Success: false, Protocol: "rtsp",
			Error: "no auth challenge or missing credentials"}
	}

	// Build Digest response
	uri := fmt.Sprintf("rtsp://%s:554", host)
	ha1 := md5Hex(fmt.Sprintf("%s:%s:%s", user, realm, pass))
	ha2 := md5Hex(fmt.Sprintf("DESCRIBE:%s", uri))
	response := md5Hex(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))

	authHeader := fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		user, realm, nonce, uri, response)

	req = fmt.Sprintf("DESCRIBE %s RTSP/1.0\r\nCSeq: 3\r\nAuthorization: %s\r\n\r\n", uri, authHeader)
	conn.Write([]byte(req))
	n, err = conn.Read(buf)
	if err != nil || n == 0 {
		return Result{Success: false, Protocol: "rtsp",
			Error: "no response to authenticated DESCRIBE"}
	}
	resp = string(buf[:n])

	if strings.Contains(resp, "200 OK") {
		return Result{Success: true, Protocol: "rtsp", Detail: "Digest authentication successful"}
	}
	if strings.Contains(resp, "401 Unauthorized") || strings.Contains(resp, "403 Forbidden") {
		return Result{Success: false, Protocol: "rtsp",
			Error: "invalid credentials"}
	}
	return Result{Success: false, Protocol: "rtsp",
		Error: fmt.Sprintf("auth result: %s", strings.Split(resp, "\r\n")[0])}
}

func parseDigest(resp string) (realm, nonce string) {
	for _, line := range strings.Split(resp, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "www-authenticate:") {
			line = line[len("www-authenticate:"):]
			for _, part := range strings.Split(line, ",") {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "realm=") {
					realm = strings.Trim(part[6:], `"`)
				}
				if strings.HasPrefix(part, "nonce=") {
					nonce = strings.Trim(part[6:], `"`)
				}
			}
		}
	}
	return
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", h)
}
