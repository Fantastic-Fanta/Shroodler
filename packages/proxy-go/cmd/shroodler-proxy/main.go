package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/shroodler/proxy-go/internal/autoresponder"
	"github.com/shroodler/proxy-go/internal/ca"
	"github.com/shroodler/proxy-go/internal/proxy"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "ca":
		return cmdCA(args[1:])
	case "start":
		return cmdStart(args[1:])
	case "replay":
		return cmdReplay(args[1:])
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "shroodler-proxy start [--port 8888] [--control-port 8890] [--record out.sessions.jsonl] [--rules rules.yaml]")
	fmt.Fprintln(os.Stderr, "shroodler-proxy ca generate|export [--output path]|uninstall [--yes]")
	fmt.Fprintln(os.Stderr, "shroodler-proxy replay <session.json> [--output out.json]")
}

func store() *ca.Store { return ca.NewStore("") }

func cmdCA(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	s := store()
	switch args[0] {
	case "generate":
		if err := s.Generate(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("generated CA at", s.Dir)
		return 0
	case "export":
		out := "ca.pem"
		for i := 1; i < len(args); i++ {
			if args[i] == "--output" {
				i++
				out = args[i]
			}
		}
		if err := s.Export(out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("exported", out)
		return 0
	case "uninstall":
		yes := false
		for _, a := range args[1:] {
			if a == "--yes" {
				yes = true
			}
		}
		fmt.Printf("This will delete the local proxy CA files in %s (ca.pem and ca.key). It will not silently modify the OS trust store.\n", s.Dir)
		if !yes {
			fmt.Fprintln(os.Stderr, "pass --yes to confirm")
			return 2
		}
		if err := s.Uninstall(true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("uninstalled local CA files")
		return 0
	}
	usage()
	return 2
}

func cmdStart(args []string) int {
	s := proxy.New(store())
	s.Timeout = 5 * time.Minute
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--port":
			i++
			s.Addr = "127.0.0.1:" + args[i]
		case "--control-port":
			i++
			s.ControlAddr = "127.0.0.1:" + args[i]
		case "--record":
			i++
			s.RecordPath = args[i]
		case "--rules":
			i++
			rules, err := autoresponder.Load(args[i])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			s.SetRules(rules)
		}
	}
	fmt.Println("proxy listening", s.Addr, "control", s.ControlAddr)
	if err := s.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func cmdReplay(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var sess proxy.Session
	if err := json.Unmarshal(b, &sess); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	edits := map[string]any{}
	var out string
	for i := 1; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--edit-header") {
			i++
			kv := strings.SplitN(args[i], "=", 2)
			if len(kv) == 2 {
				edits["header_"+kv[0]] = kv[1]
			}
		}
		if args[i] == "--output" {
			i++
			out = args[i]
		}
	}
	srv := proxy.New(store())
	if err := srv.ReplaySession(&sess, edits); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if out != "" {
		_ = os.WriteFile(out, b, 0o644)
	}
	return 0
}
