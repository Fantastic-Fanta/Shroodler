package sessions

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/shroodler/crawler-go/internal/urls"
)

type Body struct {
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

type Msg struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       Body              `json:"body"`
}

type Session struct {
	ID       string `json:"id"`
	Request  Msg    `json:"request"`
	Response *Msg   `json:"response"`
}

func HeaderGet(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func SplitSetCookie(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(raw)-1; i++ {
		if raw[i] == ',' && raw[i+1] == ' ' {
			rest := raw[i+2:]
			if j := strings.IndexByte(rest, '='); j > 0 && !strings.ContainsAny(rest[:j], " ;") {
				out = append(out, strings.TrimSpace(raw[start:i]))
				start = i + 2
			}
		}
	}
	out = append(out, strings.TrimSpace(raw[start:]))
	return out
}

func cookieNV(first string) (string, string, bool) {
	if !strings.Contains(first, "=") {
		return "", "", false
	}
	name, val, _ := strings.Cut(first, "=")
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", false
	}
	return name, strings.TrimSpace(val), true
}

func pairsFromCookieHeader(raw string) [][2]string {
	var out [][2]string
	skip := map[string]bool{"secure": true, "httponly": true, "samesite": true, "path": true, "domain": true, "expires": true, "max-age": true}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		name, val, ok := cookieNV(part)
		if !ok || skip[strings.ToLower(name)] {
			continue
		}
		out = append(out, [2]string{name, val})
	}
	return out
}

func pairsFromSetCookie(raw string) [][2]string {
	var out [][2]string
	for _, c := range SplitSetCookie(raw) {
		first, _, _ := strings.Cut(c, ";")
		name, val, ok := cookieNV(first)
		if ok {
			out = append(out, [2]string{name, val})
		}
	}
	return out
}

func usable(s Session) bool {
	m := strings.ToUpper(s.Request.Method)
	if m == "CONNECT" || m == "OPTIONS" {
		return false
	}
	return s.Request.URL != "" && strings.Contains(s.Request.URL, "://")
}

func LoadJSONL(path string) ([]Session, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 8*1024*1024)
	var out []Session
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var s Session
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			return nil, fmt.Errorf("invalid session JSONL at line %d: %w", lineNo, err)
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

func SeedURLs(sessions []Session, originURL string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range sessions {
		if !usable(s) {
			continue
		}
		if originURL != "" && !urls.SameOrigin(s.Request.URL, originURL) {
			continue
		}
		key := urls.CanonicalKey(s.Request.URL)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s.Request.URL)
	}
	return out
}

func CookieHeader(sessions []Session, originURL string) string {
	jar := map[string]string{}
	var order []string
	for _, s := range sessions {
		if !usable(s) {
			continue
		}
		if originURL != "" && !urls.SameOrigin(s.Request.URL, originURL) {
			continue
		}
		put := func(name, val string) {
			if _, ok := jar[name]; !ok {
				order = append(order, name)
			}
			jar[name] = val
		}
		for _, nv := range pairsFromCookieHeader(HeaderGet(s.Request.Headers, "Cookie")) {
			put(nv[0], nv[1])
		}
		if s.Response != nil {
			for _, nv := range pairsFromSetCookie(HeaderGet(s.Response.Headers, "Set-Cookie")) {
				put(nv[0], nv[1])
			}
		}
	}
	var parts []string
	for _, name := range order {
		parts = append(parts, name+"="+jar[name])
	}
	return strings.Join(parts, "; ")
}

func (b Body) Text() string {
	if b.Encoding == "base64" {
		raw, err := base64.StdEncoding.DecodeString(b.Content)
		if err != nil {
			return b.Content
		}
		return string(raw)
	}
	return b.Content
}
