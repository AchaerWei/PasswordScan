// NetSpider Go Proto — Go-native protocol testers for NetSpider-Max v3.
// Each protocol is a subcommand. All output is JSON lines to stdout.
// Called from Python via subprocess: goproto <proto> --host <ip> ...
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Result struct {
	Success  bool   `json:"success"`
	Protocol string `json:"protocol"`
	Error    string `json:"error,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: goproto <protocol> [args...]\n")
		os.Exit(1)
	}
	protocol := os.Args[1]
	args := os.Args[2:]

	var result Result
	result.Protocol = protocol

	switch protocol {
	case "snmp":
		result = runSNMP(args)
	case "ldap":
		result = runLDAP(args)
	case "imap":
		result = runIMAP(args)
	case "pop3":
		result = runPOP3(args)
	case "rtsp":
		result = runRTSP(args)
	case "vnc":
		result = runVNC(args)
	case "version":
		result = Result{Success: true, Protocol: "version", Detail: "goproto v0.2.0"}
	default:
		result = Result{Success: false, Protocol: protocol, Error: fmt.Sprintf("unknown protocol: %s", protocol)}
	}

	b, _ := json.Marshal(result)
	fmt.Println(string(b))
	if !result.Success {
		os.Exit(1)
	}
}
